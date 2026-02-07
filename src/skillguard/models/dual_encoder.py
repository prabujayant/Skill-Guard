"""
Dual-Encoder Neural Network for SkillGuard.

Novel architecture that combines:
1. Description encoder (transformer-based)
2. Code encoder (CodeBERT-based)
3. Static feature fusion
4. Semantic alignment regularization
"""

from typing import Dict, Any, Optional, Tuple, List
import numpy as np
from loguru import logger

from skillguard.models.base import BaseModel, ModelConfig, TrainingMetrics, PredictionResult


class DualEncoderModel(BaseModel):
    """
    Dual-Encoder Neural Network for malicious skill detection.
    
    Architecture:
    - Description encoder: Transformer embedding
    - Code encoder: CodeBERT/transformer embedding
    - Fusion layer: Concatenate embeddings + static features
    - Classifier: MLP with dropout
    
    Novel contributions:
    - Semantic alignment loss (description-code similarity)
    - Focal loss for class imbalance
    - Multi-task learning (classification + alignment)
    """
    
    def __init__(self, config: Optional[ModelConfig] = None):
        super().__init__(config)
        self.config.name = "dual_encoder"
        self._torch_model = None
        self._device = None
    
    def _build_model(self, input_dim: int, embedding_dim: int = 384):
        """Build PyTorch model."""
        try:
            import torch
            import torch.nn as nn
            
            self._device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
            logger.info(f"Using device: {self._device}")
            
            # Define model architecture
            class DualEncoderNet(nn.Module):
                def __init__(self, static_dim, emb_dim, hidden_dims, dropout):
                    super().__init__()
                    
                    # Embedding projection (reduce dimension)
                    self.desc_proj = nn.Linear(emb_dim, 128)
                    self.code_proj = nn.Linear(emb_dim, 128)
                    
                    # Static feature projection
                    self.static_proj = nn.Linear(static_dim, 64)
                    
                    # Fusion layers
                    fusion_input = 128 + 128 + 64  # desc + code + static
                    
                    layers = []
                    prev_dim = fusion_input
                    for hidden_dim in hidden_dims:
                        layers.extend([
                            nn.Linear(prev_dim, hidden_dim),
                            nn.ReLU(),
                            nn.Dropout(dropout),
                        ])
                        prev_dim = hidden_dim
                    
                    layers.append(nn.Linear(prev_dim, 1))
                    
                    self.classifier = nn.Sequential(*layers)
                
                def forward(self, static_features, desc_emb=None, code_emb=None):
                    # Project embeddings
                    if desc_emb is not None and code_emb is not None:
                        desc_feat = self.desc_proj(desc_emb)
                        code_feat = self.code_proj(code_emb)
                    else:
                        # No embeddings - use zeros
                        batch_size = static_features.shape[0]
                        desc_feat = torch.zeros(batch_size, 128, device=static_features.device)
                        code_feat = torch.zeros(batch_size, 128, device=static_features.device)
                    
                    # Project static features
                    static_feat = self.static_proj(static_features)
                    
                    # Concatenate all features
                    x = torch.cat([desc_feat, code_feat, static_feat], dim=1)
                    
                    # Classify
                    logits = self.classifier(x)
                    return logits.squeeze(-1)
                
                def get_alignment_score(self, desc_emb, code_emb):
                    """Compute cosine similarity for alignment loss."""
                    desc_feat = self.desc_proj(desc_emb)
                    code_feat = self.code_proj(code_emb)
                    
                    # Normalize
                    desc_norm = desc_feat / (desc_feat.norm(dim=1, keepdim=True) + 1e-8)
                    code_norm = code_feat / (code_feat.norm(dim=1, keepdim=True) + 1e-8)
                    
                    # Cosine similarity
                    return (desc_norm * code_norm).sum(dim=1)
            
            self._torch_model = DualEncoderNet(
                static_dim=input_dim,
                emb_dim=embedding_dim,
                hidden_dims=self.config.hidden_dims,
                dropout=self.config.dropout,
            ).to(self._device)
            
            return True
            
        except ImportError:
            logger.error("PyTorch not installed, cannot use DualEncoder model")
            return False
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        desc_emb_train: Optional[np.ndarray] = None,
        code_emb_train: Optional[np.ndarray] = None,
        desc_emb_val: Optional[np.ndarray] = None,
        code_emb_val: Optional[np.ndarray] = None,
    ) -> TrainingMetrics:
        """
        Train the dual-encoder model.
        
        Args:
            X_train: Static features (n_samples x n_features)
            y_train: Labels
            X_val: Validation static features
            y_val: Validation labels
            desc_emb_train: Description embeddings for training
            code_emb_train: Code embeddings for training
            desc_emb_val: Description embeddings for validation
            code_emb_val: Code embeddings for validation
        """
        import torch
        import torch.nn as nn
        from torch.utils.data import TensorDataset, DataLoader
        from sklearn.metrics import f1_score, roc_auc_score
        
        # Build model
        embedding_dim = desc_emb_train.shape[1] if desc_emb_train is not None else 384
        if not self._build_model(X_train.shape[1], embedding_dim):
            raise RuntimeError("Failed to build model")
        
        # Compute class weights for focal loss
        n_neg = np.sum(y_train == 0)
        n_pos = np.sum(y_train == 1)
        pos_weight = torch.tensor([n_neg / n_pos], device=self._device)
        
        # Create datasets
        X_train_t = torch.FloatTensor(X_train).to(self._device)
        y_train_t = torch.FloatTensor(y_train).to(self._device)
        
        if desc_emb_train is not None:
            desc_emb_train_t = torch.FloatTensor(desc_emb_train).to(self._device)
            code_emb_train_t = torch.FloatTensor(code_emb_train).to(self._device)
            train_dataset = TensorDataset(X_train_t, y_train_t, desc_emb_train_t, code_emb_train_t)
        else:
            train_dataset = TensorDataset(X_train_t, y_train_t)
        
        train_loader = DataLoader(train_dataset, batch_size=self.config.batch_size, shuffle=True)
        
        # Optimizer
        optimizer = torch.optim.AdamW(
            self._torch_model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay,
        )
        
        # Loss function (focal loss for imbalance)
        def focal_loss(logits, targets, gamma=2.0):
            bce = nn.functional.binary_cross_entropy_with_logits(
                logits, targets, pos_weight=pos_weight, reduction='none'
            )
            pt = torch.where(targets == 1, torch.sigmoid(logits), 1 - torch.sigmoid(logits))
            focal_weight = (1 - pt) ** gamma
            return (focal_weight * bce).mean()
        
        # Training loop
        best_val_f1 = 0.0
        patience_counter = 0
        
        for epoch in range(self.config.epochs):
            self._torch_model.train()
            epoch_loss = 0.0
            
            for batch in train_loader:
                if len(batch) == 4:
                    static, labels, desc_emb, code_emb = batch
                else:
                    static, labels = batch
                    desc_emb = code_emb = None
                
                optimizer.zero_grad()
                
                logits = self._torch_model(static, desc_emb, code_emb)
                loss = focal_loss(logits, labels, self.config.focal_loss_gamma)
                
                # Add alignment regularization if embeddings available
                if desc_emb is not None and code_emb is not None:
                    alignment = self._torch_model.get_alignment_score(desc_emb, code_emb)
                    # For malicious samples, alignment should be LOW
                    # For benign samples, alignment should be HIGH
                    alignment_target = 1 - labels  # benign=1 (high align), malicious=0 (low align)
                    alignment_loss = nn.functional.mse_loss(alignment, alignment_target * 0.5 + 0.5)
                    loss = loss + 0.1 * alignment_loss
                
                loss.backward()
                optimizer.step()
                
                epoch_loss += loss.item()
            
            # Validation
            if X_val is not None and y_val is not None:
                val_preds, val_probs = self._evaluate(X_val, desc_emb_val, code_emb_val)
                val_f1 = f1_score(y_val, val_preds)
                val_auc = roc_auc_score(y_val, val_probs)
                
                self.training_metrics.val_f1.append(val_f1)
                self.training_metrics.val_auc.append(val_auc)
                self.training_metrics.val_loss.append(0)  # Placeholder
                
                # Early stopping
                if val_f1 > best_val_f1:
                    best_val_f1 = val_f1
                    self.training_metrics.best_val_f1 = val_f1
                    self.training_metrics.best_epoch = epoch
                    patience_counter = 0
                    # Save best model weights
                    best_state = {k: v.cpu().clone() for k, v in self._torch_model.state_dict().items()}
                else:
                    patience_counter += 1
                
                if patience_counter >= self.config.early_stopping_patience:
                    logger.info(f"Early stopping at epoch {epoch}")
                    break
            
            # Log progress
            avg_loss = epoch_loss / len(train_loader)
            self.training_metrics.train_loss.append(avg_loss)
            
            if epoch % 10 == 0:
                logger.info(f"Epoch {epoch}: loss={avg_loss:.4f}, val_f1={val_f1:.4f}" if X_val is not None else f"Epoch {epoch}: loss={avg_loss:.4f}")
        
        # Restore best model
        if X_val is not None and 'best_state' in locals():
            self._torch_model.load_state_dict(best_state)
        
        self.is_fitted = True
        logger.info(f"DualEncoder trained: best_val_f1={self.training_metrics.best_val_f1:.4f}")
        
        return self.training_metrics
    
    def _evaluate(
        self,
        X: np.ndarray,
        desc_emb: Optional[np.ndarray] = None,
        code_emb: Optional[np.ndarray] = None,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Evaluate model on data."""
        import torch
        
        self._torch_model.eval()
        
        with torch.no_grad():
            static = torch.FloatTensor(X).to(self._device)
            
            if desc_emb is not None:
                desc_t = torch.FloatTensor(desc_emb).to(self._device)
                code_t = torch.FloatTensor(code_emb).to(self._device)
            else:
                desc_t = code_t = None
            
            logits = self._torch_model(static, desc_t, code_t)
            probs = torch.sigmoid(logits).cpu().numpy()
            preds = (probs > 0.5).astype(int)
        
        return preds, probs
    
    def predict(
        self,
        X: np.ndarray,
        desc_emb: Optional[np.ndarray] = None,
        code_emb: Optional[np.ndarray] = None,
    ) -> PredictionResult:
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        preds, probs = self._evaluate(X, desc_emb, code_emb)
        
        # Convert to 2-class probabilities
        probabilities = np.stack([1 - probs, probs], axis=1)
        
        return PredictionResult(
            labels=preds,
            probabilities=probabilities,
            confidence=np.maximum(probs, 1 - probs),
        )
