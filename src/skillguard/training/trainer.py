"""
Model Trainer for SkillGuard ML Pipeline.

Handles model training, evaluation, and experiment tracking.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Type
from pathlib import Path
import json
import time

import numpy as np
from loguru import logger

from skillguard.models.base import BaseModel, ModelConfig, TrainingMetrics, PredictionResult
from skillguard.training.data_splits import SkillDataset, DataSplits


@dataclass
class TrainingConfig:
    """Configuration for training runs."""
    
    experiment_name: str = "skillguard_experiment"
    output_dir: Path = Path("./output/experiments")
    
    # Model selection
    models_to_train: List[str] = field(default_factory=lambda: [
        "logistic_regression",
        "random_forest",
        "gradient_boosting",
    ])
    
    # Training settings
    use_cross_validation: bool = True
    n_folds: int = 5
    
    # Hyperparameter tuning
    tune_hyperparameters: bool = False
    
    # Evaluation
    save_predictions: bool = True
    compute_feature_importance: bool = True


@dataclass  
class ExperimentResults:
    """Results from a training experiment."""
    
    experiment_name: str
    model_results: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    best_model: str = ""
    best_f1: float = 0.0
    best_auc: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_name": self.experiment_name,
            "model_results": self.model_results,
            "best_model": self.best_model,
            "best_f1": self.best_f1,
            "best_auc": self.best_auc,
        }
    
    def save(self, filepath: Path) -> None:
        filepath.write_text(json.dumps(self.to_dict(), indent=2))


class Trainer:
    """
    Training controller for SkillGuard models.
    
    Handles:
    - Multiple model training
    - Cross-validation
    - Evaluation metrics
    - Experiment tracking
    """
    
    def __init__(self, config: Optional[TrainingConfig] = None):
        self.config = config or TrainingConfig()
        self.results = ExperimentResults(experiment_name=self.config.experiment_name)
    
    def train_all_models(self, splits: DataSplits) -> ExperimentResults:
        """
        Train all configured models and compare results.
        
        Args:
            splits: Train/val/test data splits
            
        Returns:
            ExperimentResults with all model performances
        """
        from skillguard.models.baselines import (
            LogisticRegressionModel,
            RandomForestModel,
            GradientBoostingModel,
        )
        from skillguard.models.dual_encoder import DualEncoderModel
        
        model_classes = {
            "logistic_regression": LogisticRegressionModel,
            "random_forest": RandomForestModel,
            "gradient_boosting": GradientBoostingModel,
            "dual_encoder": DualEncoderModel,
        }
        
        for model_name in self.config.models_to_train:
            if model_name not in model_classes:
                logger.warning(f"Unknown model: {model_name}")
                continue
            
            logger.info(f"\n{'='*50}")
            logger.info(f"Training {model_name}")
            logger.info(f"{'='*50}")
            
            try:
                model_class = model_classes[model_name]
                result = self._train_single_model(model_class, splits, model_name)
                self.results.model_results[model_name] = result
                
                # Update best model
                if result["test_f1"] > self.results.best_f1:
                    self.results.best_f1 = result["test_f1"]
                    self.results.best_auc = result["test_auc"]
                    self.results.best_model = model_name
                    
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {e}")
                self.results.model_results[model_name] = {"error": str(e)}
        
        # Save results
        output_dir = self.config.output_dir / self.config.experiment_name
        output_dir.mkdir(parents=True, exist_ok=True)
        self.results.save(output_dir / "results.json")
        
        # Print summary
        self._print_summary()
        
        return self.results
    
    def _train_single_model(
        self,
        model_class: Type[BaseModel],
        splits: DataSplits,
        model_name: str,
    ) -> Dict[str, Any]:
        """Train a single model and evaluate."""
        from sklearn.metrics import (
            f1_score, precision_score, recall_score,
            roc_auc_score, accuracy_score, confusion_matrix
        )
        
        start_time = time.time()
        
        # Initialize model
        model = model_class()
        
        # Train
        if model_name == "dual_encoder":
            metrics = model.train(
                splits.train.X, splits.train.y,
                splits.val.X, splits.val.y,
                splits.train.desc_embeddings,
                splits.train.code_embeddings,
                splits.val.desc_embeddings,
                splits.val.code_embeddings,
            )
        else:
            metrics = model.train(
                splits.train.X, splits.train.y,
                splits.val.X, splits.val.y,
            )
        
        training_time = time.time() - start_time
        
        # Evaluate on test set
        if model_name == "dual_encoder":
            predictions = model.predict(
                splits.test.X,
                splits.test.desc_embeddings,
                splits.test.code_embeddings,
            )
        else:
            predictions = model.predict(splits.test.X)
        
        y_true = splits.test.y
        y_pred = predictions.labels
        y_proba = predictions.probabilities[:, 1]
        
        # Compute metrics
        result = {
            "test_f1": f1_score(y_true, y_pred),
            "test_precision": precision_score(y_true, y_pred),
            "test_recall": recall_score(y_true, y_pred),
            "test_auc": roc_auc_score(y_true, y_proba),
            "test_accuracy": accuracy_score(y_true, y_pred),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
            "training_time_seconds": training_time,
            "best_val_f1": metrics.best_val_f1,
            "best_epoch": metrics.best_epoch,
        }
        
        # Feature importance
        if self.config.compute_feature_importance:
            importance = model.get_feature_importance()
            if importance is not None:
                from skillguard.features.feature_pipeline import FeatureVector
                feature_names = FeatureVector.tabular_feature_names()
                result["feature_importance"] = dict(zip(feature_names, importance.tolist()))
        
        # Save model
        output_dir = self.config.output_dir / self.config.experiment_name
        output_dir.mkdir(parents=True, exist_ok=True)
        model.save(output_dir / f"{model_name}.pkl")
        
        logger.info(f"{model_name} results:")
        logger.info(f"  Test F1: {result['test_f1']:.4f}")
        logger.info(f"  Test AUC: {result['test_auc']:.4f}")
        logger.info(f"  Test Precision: {result['test_precision']:.4f}")
        logger.info(f"  Test Recall: {result['test_recall']:.4f}")
        
        return result
    
    def run_ablation_study(self, splits: DataSplits) -> Dict[str, Dict[str, Any]]:
        """
        Run ablation study to measure component contributions.
        
        Tests:
        1. Static features only
        2. Semantic features only
        3. Code embeddings only
        4. Description embeddings only
        5. Full model (all features)
        """
        from sklearn.metrics import f1_score, roc_auc_score
        from skillguard.models.baselines import GradientBoostingModel
        
        logger.info("\n" + "="*50)
        logger.info("Running Ablation Study")
        logger.info("="*50)
        
        from skillguard.features.feature_pipeline import FeatureVector
        n_static = 29  # Number of static features
        n_semantic = 8  # Number of semantic scalar features
        
        ablation_configs = {
            "static_only": list(range(n_static)),
            "semantic_only": list(range(n_static, n_static + n_semantic)),
            "all_tabular": list(range(n_static + n_semantic)),
        }
        
        results = {}
        
        for config_name, feature_indices in ablation_configs.items():
            logger.info(f"\nTesting {config_name} ({len(feature_indices)} features)")
            
            # Subset features
            X_train = splits.train.X[:, feature_indices]
            X_val = splits.val.X[:, feature_indices]
            X_test = splits.test.X[:, feature_indices]
            
            # Train model
            model = GradientBoostingModel()
            model.train(X_train, splits.train.y, X_val, splits.val.y)
            
            # Evaluate
            predictions = model.predict(X_test)
            
            test_f1 = f1_score(splits.test.y, predictions.labels)
            test_auc = roc_auc_score(splits.test.y, predictions.probabilities[:, 1])
            
            results[config_name] = {
                "num_features": len(feature_indices),
                "test_f1": test_f1,
                "test_auc": test_auc,
            }
            
            logger.info(f"  F1: {test_f1:.4f}, AUC: {test_auc:.4f}")
        
        # Save results
        output_dir = self.config.output_dir / self.config.experiment_name
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / "ablation_results.json").write_text(json.dumps(results, indent=2))
        
        return results
    
    def _print_summary(self) -> None:
        """Print summary table of all results."""
        logger.info("\n" + "="*70)
        logger.info("EXPERIMENT SUMMARY")
        logger.info("="*70)
        logger.info(f"{'Model':<25} {'F1':>10} {'AUC':>10} {'Precision':>10} {'Recall':>10}")
        logger.info("-"*70)
        
        for model_name, result in self.results.model_results.items():
            if "error" in result:
                logger.info(f"{model_name:<25} {'ERROR':>10}")
            else:
                logger.info(
                    f"{model_name:<25} "
                    f"{result['test_f1']:>10.4f} "
                    f"{result['test_auc']:>10.4f} "
                    f"{result['test_precision']:>10.4f} "
                    f"{result['test_recall']:>10.4f}"
                )
        
        logger.info("-"*70)
        logger.info(f"Best Model: {self.results.best_model} (F1: {self.results.best_f1:.4f})")
        logger.info("="*70)
