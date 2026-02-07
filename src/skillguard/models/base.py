"""
Base model interface and configuration for SkillGuard ML models.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import json
import pickle

import numpy as np
from loguru import logger


@dataclass
class ModelConfig:
    """Configuration for ML models."""
    
    name: str = "base_model"
    
    # Training parameters
    learning_rate: float = 0.001
    batch_size: int = 32
    epochs: int = 100
    early_stopping_patience: int = 10
    
    # Regularization
    dropout: float = 0.3
    weight_decay: float = 0.01
    
    # Class imbalance handling
    class_weight: Optional[Dict[int, float]] = None
    focal_loss_gamma: float = 2.0
    
    # Architecture
    hidden_dims: List[int] = field(default_factory=lambda: [256, 64])
    use_embeddings: bool = True
    embedding_dim: int = 384  # bge-small-en-v1.5
    
    # Random seed
    random_state: int = 42
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "learning_rate": self.learning_rate,
            "batch_size": self.batch_size,
            "epochs": self.epochs,
            "dropout": self.dropout,
            "hidden_dims": self.hidden_dims,
            "use_embeddings": self.use_embeddings,
            "random_state": self.random_state,
        }


@dataclass
class TrainingMetrics:
    """Metrics tracked during training."""
    
    train_loss: List[float] = field(default_factory=list)
    val_loss: List[float] = field(default_factory=list)
    train_f1: List[float] = field(default_factory=list)
    val_f1: List[float] = field(default_factory=list)
    train_auc: List[float] = field(default_factory=list)
    val_auc: List[float] = field(default_factory=list)
    best_epoch: int = 0
    best_val_f1: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "train_loss": self.train_loss,
            "val_loss": self.val_loss,
            "train_f1": self.train_f1,
            "val_f1": self.val_f1,
            "train_auc": self.train_auc,
            "val_auc": self.val_auc,
            "best_epoch": self.best_epoch,
            "best_val_f1": self.best_val_f1,
        }


@dataclass
class PredictionResult:
    """Result of model prediction."""
    
    labels: np.ndarray  # Predicted class labels
    probabilities: np.ndarray  # Class probabilities
    confidence: np.ndarray  # Confidence scores (max probability)
    
    def get_positives(self, threshold: float = 0.5) -> np.ndarray:
        """Get indices of positive predictions."""
        return np.where(self.probabilities[:, 1] >= threshold)[0]


class BaseModel(ABC):
    """
    Abstract base class for SkillGuard ML models.
    
    All models must implement train, predict, and save/load methods.
    """
    
    def __init__(self, config: Optional[ModelConfig] = None):
        self.config = config or ModelConfig()
        self.is_fitted = False
        self.training_metrics = TrainingMetrics()
        self._model = None
    
    @abstractmethod
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> TrainingMetrics:
        """
        Train the model.
        
        Args:
            X_train: Training features (n_samples x n_features)
            y_train: Training labels (n_samples,)
            X_val: Optional validation features
            y_val: Optional validation labels
            
        Returns:
            TrainingMetrics with loss and metric history
        """
        pass
    
    @abstractmethod
    def predict(self, X: np.ndarray) -> PredictionResult:
        """
        Make predictions on new data.
        
        Args:
            X: Features (n_samples x n_features)
            
        Returns:
            PredictionResult with labels and probabilities
        """
        pass
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get probability predictions."""
        result = self.predict(X)
        return result.probabilities
    
    def save(self, filepath: Path) -> None:
        """Save model to file."""
        filepath.parent.mkdir(parents=True, exist_ok=True)
        
        data = {
            "config": self.config.to_dict(),
            "is_fitted": self.is_fitted,
            "training_metrics": self.training_metrics.to_dict(),
            "model": self._model,
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(data, f)
        
        logger.info(f"Model saved to {filepath}")
    
    def load(self, filepath: Path) -> None:
        """Load model from file."""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        
        self.config = ModelConfig(**data["config"])
        self.is_fitted = data["is_fitted"]
        self.training_metrics = TrainingMetrics(**data["training_metrics"])
        self._model = data["model"]
        
        logger.info(f"Model loaded from {filepath}")
    
    @staticmethod
    def compute_class_weights(y: np.ndarray) -> Dict[int, float]:
        """Compute class weights for imbalanced data."""
        from collections import Counter
        counter = Counter(y)
        total = len(y)
        n_classes = len(counter)
        
        weights = {}
        for cls, count in counter.items():
            weights[cls] = total / (n_classes * count)
        
        return weights
    
    def get_feature_importance(self) -> Optional[np.ndarray]:
        """Get feature importance if available."""
        return None  # Override in subclasses
