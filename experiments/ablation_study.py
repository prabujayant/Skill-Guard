"""
Ablation Study Experiment Script.

Systematically tests different feature configurations to measure
contribution of each component.
"""

import json
from pathlib import Path
from typing import Dict, Any, List

import numpy as np
from loguru import logger

from skillguard.training.data_splits import create_splits, SkillDataset
from skillguard.features.feature_pipeline import FeatureVector
from skillguard.models.baselines import GradientBoostingModel


def run_ablation_study(
    features: List[FeatureVector],
    output_dir: Path = Path("./output/ablation"),
) -> Dict[str, Dict[str, float]]:
    """
    Run comprehensive ablation study.
    
    Tests:
    1. Static features only (code-level)
    2. Semantic scalar features only
    3. Static + Semantic combined
    4. Individual feature groups
    """
    from sklearn.metrics import f1_score, roc_auc_score, precision_score, recall_score
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create splits
    splits = create_splits(features, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1)
    
    # Define feature configurations
    n_static = 29
    n_semantic = 8
    
    feature_configs = {
        # Main configurations
        "all_features": list(range(n_static + n_semantic)),
        "static_only": list(range(n_static)),
        "semantic_only": list(range(n_static, n_static + n_semantic)),
        
        # Static feature groups
        "structural": [0, 1, 2, 3, 4, 5],  # num_funcs, classes, imports, LOC, complexity, depth
        "dangerous_primitives": [6, 7, 8, 9, 10, 11, 12, 13, 14],  # eval, subprocess, network, etc.
        "data_flow": [15, 16, 17],  # user_input_to_*
        "obfuscation": [18, 19, 20, 21, 22, 23, 24, 25],  # base64, hex, dynamic imports
        "serialization": [26, 27, 28],  # pickle, yaml, marshal
        
        # Semantic feature groups
        "embedding_alignment": [n_static + 0],  # cosine_sim
        "capability_mismatch": [n_static + 1],  # mismatch_count
        "text_stats": [n_static + 2, n_static + 3, n_static + 4, n_static + 5, n_static + 6, n_static + 7],
    }
    
    results = {}
    
    for config_name, feature_indices in feature_configs.items():
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
        
        results[config_name] = {
            "num_features": len(feature_indices),
            "feature_indices": feature_indices,
            "f1": f1_score(splits.test.y, predictions.labels),
            "auc": roc_auc_score(splits.test.y, predictions.probabilities[:, 1]),
            "precision": precision_score(splits.test.y, predictions.labels),
            "recall": recall_score(splits.test.y, predictions.labels),
        }
        
        logger.info(f"  F1: {results[config_name]['f1']:.4f}")
        logger.info(f"  AUC: {results[config_name]['auc']:.4f}")
    
    # Calculate contribution (delta from baseline)
    baseline_f1 = results["all_features"]["f1"]
    for name, metrics in results.items():
        metrics["f1_delta"] = baseline_f1 - metrics["f1"]
    
    # Save results
    (output_dir / "ablation_results.json").write_text(
        json.dumps(results, indent=2, default=str)
    )
    
    # Print summary table
    print("\n" + "="*80)
    print("ABLATION STUDY RESULTS")
    print("="*80)
    print(f"{'Configuration':<25} {'#Features':>10} {'F1':>10} {'AUC':>10} {'Delta':>10}")
    print("-"*80)
    
    for name, metrics in sorted(results.items(), key=lambda x: x[1]['f1'], reverse=True):
        print(
            f"{name:<25} "
            f"{metrics['num_features']:>10} "
            f"{metrics['f1']:>10.4f} "
            f"{metrics['auc']:>10.4f} "
            f"{metrics['f1_delta']:>+10.4f}"
        )
    
    print("="*80)
    
    return results


def run_feature_importance_analysis(
    features: List[FeatureVector],
    output_dir: Path = Path("./output/importance"),
) -> Dict[str, float]:
    """
    Analyze feature importance using trained model.
    """
    from skillguard.features.feature_pipeline import FeatureVector
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create splits
    splits = create_splits(features, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1)
    
    # Train model
    model = GradientBoostingModel()
    model.train(splits.train.X, splits.train.y, splits.val.X, splits.val.y)
    
    # Get importance
    importance = model.get_feature_importance()
    feature_names = FeatureVector.tabular_feature_names()
    
    importance_dict = dict(zip(feature_names, importance))
    
    # Sort by importance
    sorted_importance = sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)
    
    # Print top features
    print("\n" + "="*60)
    print("TOP 15 MOST IMPORTANT FEATURES")
    print("="*60)
    
    for i, (name, imp) in enumerate(sorted_importance[:15], 1):
        print(f"{i:2}. {name:<35} {imp:.4f}")
    
    # Save
    (output_dir / "feature_importance.json").write_text(
        json.dumps(importance_dict, indent=2)
    )
    
    return importance_dict


def run_robustness_analysis(
    features: List[FeatureVector],
    output_dir: Path = Path("./output/robustness"),
) -> Dict[str, Dict[str, float]]:
    """
    Test model robustness to perturbations.
    """
    from sklearn.metrics import f1_score
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create splits
    splits = create_splits(features, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1)
    
    # Train model
    model = GradientBoostingModel()
    model.train(splits.train.X, splits.train.y, splits.val.X, splits.val.y)
    
    # Baseline
    baseline_pred = model.predict(splits.test.X)
    baseline_f1 = f1_score(splits.test.y, baseline_pred.labels)
    
    results = {"baseline": {"f1": baseline_f1}}
    
    # Test robustness to noise
    for noise_level in [0.01, 0.05, 0.1, 0.2]:
        X_noisy = splits.test.X + np.random.normal(0, noise_level, splits.test.X.shape)
        pred = model.predict(X_noisy)
        f1 = f1_score(splits.test.y, pred.labels)
        results[f"noise_{noise_level}"] = {
            "f1": f1,
            "f1_drop": baseline_f1 - f1,
        }
        logger.info(f"Noise {noise_level:.0%}: F1={f1:.4f} (drop: {baseline_f1-f1:.4f})")
    
    # Test robustness to missing features
    for drop_pct in [0.1, 0.2, 0.3]:
        n_drop = int(splits.test.X.shape[1] * drop_pct)
        drop_indices = np.random.choice(splits.test.X.shape[1], n_drop, replace=False)
        X_dropped = splits.test.X.copy()
        X_dropped[:, drop_indices] = 0
        
        pred = model.predict(X_dropped)
        f1 = f1_score(splits.test.y, pred.labels)
        results[f"drop_{drop_pct}"] = {
            "f1": f1,
            "f1_drop": baseline_f1 - f1,
            "features_dropped": n_drop,
        }
        logger.info(f"Drop {drop_pct:.0%} features: F1={f1:.4f}")
    
    # Save
    (output_dir / "robustness_results.json").write_text(
        json.dumps(results, indent=2)
    )
    
    return results


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Run ablation studies")
    parser.add_argument("--data-dir", type=Path, default=Path("./data"))
    parser.add_argument("--output-dir", type=Path, default=Path("./output"))
    
    args = parser.parse_args()
    
    # Load features
    from skillguard.features.feature_pipeline import load_features
    
    features_file = args.data_dir / "features.json"
    if not features_file.exists():
        logger.error("Features file not found. Run train.py first.")
        exit(1)
    
    features = load_features(features_file)
    
    # Run studies
    run_ablation_study(features, args.output_dir / "ablation")
    run_feature_importance_analysis(features, args.output_dir / "importance")
    run_robustness_analysis(features, args.output_dir / "robustness")
