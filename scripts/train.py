#!/usr/bin/env python
"""
Main training script for SkillGuard ML experiments.

Usage:
    python scripts/train.py --data-dir ./data --output-dir ./output
    python scripts/train.py --experiment full_experiment --use-embeddings
"""

import argparse
from pathlib import Path
import json
import sys

from loguru import logger


def setup_logging(log_file: Path = None):
    """Configure logging."""
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    if log_file:
        logger.add(log_file, level="DEBUG")


def load_or_create_dataset(
    data_dir: Path,
    use_embeddings: bool = True,
    force_recreate: bool = False,
):
    """Load existing features or create from skills."""
    from skillguard.features.feature_pipeline import FeaturePipeline, load_features, save_features
    from skillguard.core.skill import SkillCorpus
    
    features_file = data_dir / "features.json"
    
    if features_file.exists() and not force_recreate:
        logger.info(f"Loading cached features from {features_file}")
        return load_features(features_file)
    
    # Look for corpus or skill directories
    corpus_file = data_dir / "corpus.json"
    skills_dir = data_dir / "skills"
    
    if corpus_file.exists():
        logger.info(f"Loading corpus from {corpus_file}")
        corpus = SkillCorpus.load(corpus_file)
        skills = corpus.skills
    elif skills_dir.exists():
        logger.info(f"Loading skills from {skills_dir}")
        from skillguard.core.skill import Skill
        skills = []
        for skill_dir in skills_dir.iterdir():
            if skill_dir.is_dir():
                try:
                    skill = Skill.from_directory(skill_dir)
                    skills.append(skill)
                except Exception as e:
                    logger.warning(f"Failed to load {skill_dir}: {e}")
    else:
        logger.error("No corpus.json or skills/ directory found")
        sys.exit(1)
    
    logger.info(f"Loaded {len(skills)} skills")
    
    # Extract features
    pipeline = FeaturePipeline(use_embeddings=use_embeddings)
    features = pipeline.extract_batch(skills, show_progress=True)
    
    # Save for caching
    save_features(features, features_file)
    
    return features


def run_experiment(
    data_dir: Path,
    output_dir: Path,
    experiment_name: str,
    models: list,
    use_embeddings: bool = True,
    run_ablation: bool = True,
):
    """Run full training experiment."""
    from skillguard.training.trainer import Trainer, TrainingConfig
    from skillguard.training.data_splits import create_splits
    from skillguard.features.feature_pipeline import FeaturePipeline
    
    # Load or create features
    features = load_or_create_dataset(data_dir, use_embeddings)
    
    # Filter to labeled only
    labeled = [f for f in features if f.label is not None]
    logger.info(f"Found {len(labeled)} labeled samples")
    
    if len(labeled) < 10:
        logger.error("Not enough labeled samples for training")
        sys.exit(1)
    
    # Create splits
    pipeline = FeaturePipeline(use_embeddings=False)  # Already extracted
    splits = create_splits(
        labeled,
        train_ratio=0.8,
        val_ratio=0.1,
        test_ratio=0.1,
        stratify=True,
    )
    
    # Configure training
    config = TrainingConfig(
        experiment_name=experiment_name,
        output_dir=output_dir,
        models_to_train=models,
        compute_feature_importance=True,
    )
    
    # Train all models
    trainer = Trainer(config)
    results = trainer.train_all_models(splits)
    
    # Run ablation study
    if run_ablation:
        ablation_results = trainer.run_ablation_study(splits)
        results.model_results["ablation"] = ablation_results
    
    logger.info(f"\nExperiment complete! Results saved to {output_dir / experiment_name}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Train SkillGuard ML models")
    
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path("./data"),
        help="Directory containing skills or corpus"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output/experiments"),
        help="Output directory for results"
    )
    parser.add_argument(
        "--experiment",
        type=str,
        default="skillguard_v1",
        help="Experiment name"
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=["logistic_regression", "random_forest", "gradient_boosting"],
        help="Models to train"
    )
    parser.add_argument(
        "--use-embeddings",
        action="store_true",
        help="Use transformer embeddings (requires sentence-transformers)"
    )
    parser.add_argument(
        "--no-ablation",
        action="store_true",
        help="Skip ablation study"
    )
    parser.add_argument(
        "--force-recreate",
        action="store_true",
        help="Force recreation of feature cache"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    args.output_dir.mkdir(parents=True, exist_ok=True)
    setup_logging(args.output_dir / f"{args.experiment}.log")
    
    logger.info("="*60)
    logger.info("SkillGuard ML Training")
    logger.info("="*60)
    logger.info(f"Data directory: {args.data_dir}")
    logger.info(f"Output directory: {args.output_dir}")
    logger.info(f"Experiment: {args.experiment}")
    logger.info(f"Models: {args.models}")
    logger.info(f"Use embeddings: {args.use_embeddings}")
    
    # Run experiment
    results = run_experiment(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        experiment_name=args.experiment,
        models=args.models,
        use_embeddings=args.use_embeddings,
        run_ablation=not args.no_ablation,
    )
    
    # Print final summary
    print("\n" + "="*60)
    print("FINAL RESULTS")
    print("="*60)
    print(f"Best Model: {results.best_model}")
    print(f"Best F1: {results.best_f1:.4f}")
    print(f"Best AUC: {results.best_auc:.4f}")
    print("="*60)


if __name__ == "__main__":
    main()
