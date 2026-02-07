"""
Baseline ML Models for SkillGuard.

Implements traditional ML classifiers as baselines:
- Logistic Regression (interpretable)
- Random Forest (non-linear)
- Gradient Boosting (SOTA for tabular)
"""

from typing import Dict, Any, Optional
import numpy as np
from loguru import logger

from skillguard.models.base import BaseModel, ModelConfig, TrainingMetrics, PredictionResult


class LogisticRegressionModel(BaseModel):
    """
    Logistic Regression baseline.
    
    Pros:
    - Interpretable (feature weights)
    - Fast training and inference
    - Low sample complexity
    
    Cons:
    - Linear decision boundary
    - May miss complex patterns
    """
    
    def __init__(self, config: Optional[ModelConfig] = None):
        super().__init__(config)
        self.config.name = "logistic_regression"
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> TrainingMetrics:
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import f1_score, roc_auc_score
        
        # Compute class weights
        class_weight = self.compute_class_weights(y_train)
        
        self._model = LogisticRegression(
            C=1.0,
            class_weight=class_weight,
            max_iter=1000,
            random_state=self.config.random_state,
        )
        
        self._model.fit(X_train, y_train)
        self.is_fitted = True
        
        # Compute metrics
        train_pred = self._model.predict(X_train)
        train_proba = self._model.predict_proba(X_train)[:, 1]
        
        self.training_metrics.train_f1.append(f1_score(y_train, train_pred))
        self.training_metrics.train_auc.append(roc_auc_score(y_train, train_proba))
        
        if X_val is not None and y_val is not None:
            val_pred = self._model.predict(X_val)
            val_proba = self._model.predict_proba(X_val)[:, 1]
            
            self.training_metrics.val_f1.append(f1_score(y_val, val_pred))
            self.training_metrics.val_auc.append(roc_auc_score(y_val, val_proba))
            self.training_metrics.best_val_f1 = self.training_metrics.val_f1[-1]
        
        logger.info(f"LogisticRegression trained: F1={self.training_metrics.train_f1[-1]:.4f}")
        
        return self.training_metrics
    
    def predict(self, X: np.ndarray) -> PredictionResult:
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        labels = self._model.predict(X)
        probabilities = self._model.predict_proba(X)
        confidence = np.max(probabilities, axis=1)
        
        return PredictionResult(
            labels=labels,
            probabilities=probabilities,
            confidence=confidence,
        )
    
    def get_feature_importance(self) -> Optional[np.ndarray]:
        if self.is_fitted:
            return np.abs(self._model.coef_[0])
        return None


class RandomForestModel(BaseModel):
    """
    Random Forest baseline.
    
    Pros:
    - Handles feature interactions
    - Built-in feature importance
    - Robust to outliers
    
    Cons:
    - Less interpretable than linear models
    - Can overfit on small datasets
    """
    
    def __init__(self, config: Optional[ModelConfig] = None):
        super().__init__(config)
        self.config.name = "random_forest"
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> TrainingMetrics:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import f1_score, roc_auc_score
        
        class_weight = self.compute_class_weights(y_train)
        
        self._model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight=class_weight,
            random_state=self.config.random_state,
            n_jobs=-1,
        )
        
        self._model.fit(X_train, y_train)
        self.is_fitted = True
        
        # Metrics
        train_pred = self._model.predict(X_train)
        train_proba = self._model.predict_proba(X_train)[:, 1]
        
        self.training_metrics.train_f1.append(f1_score(y_train, train_pred))
        self.training_metrics.train_auc.append(roc_auc_score(y_train, train_proba))
        
        if X_val is not None and y_val is not None:
            val_pred = self._model.predict(X_val)
            val_proba = self._model.predict_proba(X_val)[:, 1]
            
            self.training_metrics.val_f1.append(f1_score(y_val, val_pred))
            self.training_metrics.val_auc.append(roc_auc_score(y_val, val_proba))
            self.training_metrics.best_val_f1 = self.training_metrics.val_f1[-1]
        
        logger.info(f"RandomForest trained: F1={self.training_metrics.train_f1[-1]:.4f}")
        
        return self.training_metrics
    
    def predict(self, X: np.ndarray) -> PredictionResult:
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        labels = self._model.predict(X)
        probabilities = self._model.predict_proba(X)
        confidence = np.max(probabilities, axis=1)
        
        return PredictionResult(labels=labels, probabilities=probabilities, confidence=confidence)
    
    def get_feature_importance(self) -> Optional[np.ndarray]:
        if self.is_fitted:
            return self._model.feature_importances_
        return None


class GradientBoostingModel(BaseModel):
    """
    Gradient Boosting (XGBoost/LightGBM) baseline.
    
    Pros:
    - SOTA for tabular data
    - Handles missing values
    - Built-in regularization
    
    Cons:
    - Slower training than RF
    - Less interpretable
    """
    
    def __init__(self, config: Optional[ModelConfig] = None, use_xgboost: bool = True):
        super().__init__(config)
        self.config.name = "gradient_boosting"
        self.use_xgboost = use_xgboost
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
    ) -> TrainingMetrics:
        from sklearn.metrics import f1_score, roc_auc_score
        
        # Compute scale_pos_weight for imbalance
        n_neg = np.sum(y_train == 0)
        n_pos = np.sum(y_train == 1)
        scale_pos_weight = n_neg / n_pos if n_pos > 0 else 1.0
        
        try:
            import xgboost as xgb
            
            self._model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                scale_pos_weight=scale_pos_weight,
                random_state=self.config.random_state,
                use_label_encoder=False,
                eval_metric='logloss',
            )
            
            eval_set = [(X_train, y_train)]
            if X_val is not None:
                eval_set.append((X_val, y_val))
            
            self._model.fit(
                X_train, y_train,
                eval_set=eval_set,
                verbose=False,
            )
            
        except ImportError:
            # Fall back to sklearn GradientBoosting
            from sklearn.ensemble import GradientBoostingClassifier
            logger.warning("XGBoost not available, using sklearn GradientBoosting")
            
            self._model = GradientBoostingClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=self.config.random_state,
            )
            self._model.fit(X_train, y_train)
        
        self.is_fitted = True
        
        # Metrics
        train_pred = self._model.predict(X_train)
        train_proba = self._model.predict_proba(X_train)[:, 1]
        
        self.training_metrics.train_f1.append(f1_score(y_train, train_pred))
        self.training_metrics.train_auc.append(roc_auc_score(y_train, train_proba))
        
        if X_val is not None and y_val is not None:
            val_pred = self._model.predict(X_val)
            val_proba = self._model.predict_proba(X_val)[:, 1]
            
            self.training_metrics.val_f1.append(f1_score(y_val, val_pred))
            self.training_metrics.val_auc.append(roc_auc_score(y_val, val_proba))
            self.training_metrics.best_val_f1 = self.training_metrics.val_f1[-1]
        
        logger.info(f"GradientBoosting trained: F1={self.training_metrics.train_f1[-1]:.4f}")
        
        return self.training_metrics
    
    def predict(self, X: np.ndarray) -> PredictionResult:
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        
        labels = self._model.predict(X)
        probabilities = self._model.predict_proba(X)
        confidence = np.max(probabilities, axis=1)
        
        return PredictionResult(labels=labels, probabilities=probabilities, confidence=confidence)
    
    def get_feature_importance(self) -> Optional[np.ndarray]:
        if self.is_fitted:
            return self._model.feature_importances_
        return None
