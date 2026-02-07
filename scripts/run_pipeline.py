#!/usr/bin/env python
"""
End-to-end pipeline script for SkillGuard.

This script runs the complete workflow:
1. Generate synthetic dataset
2. Extract features
3. Train models
4. Run ablation study
5. Generate visualizations
"""

import argparse
from pathlib import Path
import sys
import json

from loguru import logger


def setup_logging(output_dir: Path):
    """Configure logging."""
    logger.remove()
    logger.add(sys.stderr, level="INFO")
    logger.add(output_dir / "pipeline.log", level="DEBUG")


def run_pipeline(
    output_dir: Path = Path("./output"),
    n_benign: int = 600,
    n_malicious: int = 200,
    skip_dataset: bool = False,
    skip_training: bool = False,
    skip_ablation: bool = False,
):
    """Run complete ML pipeline."""
    
    output_dir.mkdir(parents=True, exist_ok=True)
    data_dir = output_dir / "data"
    data_dir.mkdir(exist_ok=True)
    
    setup_logging(output_dir)
    
    logger.info("="*60)
    logger.info("SkillGuard ML Pipeline")
    logger.info("="*60)
    
    # Step 1: Generate dataset
    if not skip_dataset:
        logger.info("\n[Step 1/5] Generating synthetic dataset...")
        from scripts.generate_dataset import generate_dataset
        generate_dataset(n_benign, n_malicious, data_dir / "synthetic_dataset.json")
    
    # Step 2: Load and extract features
    logger.info("\n[Step 2/5] Extracting features...")
    features = load_and_extract_features(data_dir)
    
    # Step 3: Train models
    if not skip_training:
        logger.info("\n[Step 3/5] Training models...")
        results = train_models(features, output_dir / "experiments")
    
    # Step 4: Run ablation study
    if not skip_ablation:
        logger.info("\n[Step 4/5] Running ablation study...")
        run_ablation(features, output_dir / "ablation")
    
    # Step 5: Generate visualizations
    logger.info("\n[Step 5/5] Generating visualizations...")
    generate_figures(output_dir)
    
    logger.info("\n" + "="*60)
    logger.info("Pipeline complete!")
    logger.info(f"Results saved to: {output_dir}")
    logger.info("="*60)


def load_and_extract_features(data_dir: Path):
    """Load dataset and extract features."""
    from skillguard.core.skill import Skill
    from skillguard.features.feature_pipeline import FeaturePipeline, save_features
    from skillguard.taxonomy import LabelCategory
    
    dataset_file = data_dir / "synthetic_dataset.json"
    features_file = data_dir / "features.json"
    
    # Load dataset
    if not dataset_file.exists():
        logger.error(f"Dataset not found: {dataset_file}")
        sys.exit(1)
    
    with open(dataset_file) as f:
        dataset = json.load(f)
    
    logger.info(f"Loaded {len(dataset['samples'])} samples")
    
    # Convert to Skills
    skills = []
    for sample in dataset["samples"]:
        skill = Skill.from_components(
            manifest_content=sample["manifest_content"],
            code_content=sample["code_content"],
            label=LabelCategory.MALICIOUS if sample["label"] == 1 else LabelCategory.BENIGN,
        )
        skills.append(skill)
    
    # Extract features
    pipeline = FeaturePipeline(use_embeddings=False)  # Skip embeddings for speed
    features = pipeline.extract_batch(skills, show_progress=True)
    
    # Save features
    save_features(features, features_file)
    
    return features


def train_models(features, output_dir: Path):
    """Train all models."""
    from skillguard.training.trainer import Trainer, TrainingConfig
    from skillguard.training.data_splits import create_splits
    
    # Filter labeled
    labeled = [f for f in features if f.label is not None]
    
    # Create splits
    splits = create_splits(labeled, train_ratio=0.8, val_ratio=0.1, test_ratio=0.1)
    
    # Configure
    config = TrainingConfig(
        experiment_name="skillguard_v1",
        output_dir=output_dir,
        models_to_train=[
            "logistic_regression",
            "random_forest",
            "gradient_boosting",
        ],
    )
    
    # Train
    trainer = Trainer(config)
    results = trainer.train_all_models(splits)
    
    return results


def run_ablation(features, output_dir: Path):
    """Run ablation study."""
    from experiments.ablation_study import run_ablation_study
    run_ablation_study(features, output_dir)


def generate_figures(output_dir: Path):
    """Generate paper figures."""
    figures_dir = output_dir / "figures"
    figures_dir.mkdir(exist_ok=True)
    
    # Load results if available
    results_file = output_dir / "experiments" / "skillguard_v1" / "results.json"
    ablation_file = output_dir / "ablation" / "ablation_results.json"
    
    if results_file.exists():
        with open(results_file) as f:
            results = json.load(f)
        
        # Generate comparison chart
        try:
            from scripts.visualize import plot_baseline_comparison
            
            baselines = {}
            for model, metrics in results.get("model_results", {}).items():
                if isinstance(metrics, dict) and "test_f1" in metrics:
                    baselines[model] = {
                        "f1_score": metrics["test_f1"],
                        "precision": metrics.get("test_precision", 0),
                        "recall": metrics.get("test_recall", 0),
                    }
            
            if baselines:
                plot_baseline_comparison(baselines, figures_dir)
                logger.info("Generated baseline comparison chart")
        except Exception as e:
            logger.warning(f"Could not generate figures: {e}")
    
    if ablation_file.exists():
        logger.info("Ablation results available for visualization")


def main():
    parser = argparse.ArgumentParser(description="Run SkillGuard ML pipeline")
    
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./output"),
        help="Output directory"
    )
    parser.add_argument(
        "--benign",
        type=int,
        default=600,
        help="Number of benign samples"
    )
    parser.add_argument(
        "--malicious",
        type=int,
        default=200,
        help="Number of malicious samples"
    )
    parser.add_argument(
        "--skip-dataset",
        action="store_true",
        help="Skip dataset generation"
    )
    parser.add_argument(
        "--skip-training",
        action="store_true",
        help="Skip model training"
    )
    parser.add_argument(
        "--skip-ablation",
        action="store_true",
        help="Skip ablation study"
    )
    
    args = parser.parse_args()
    
    run_pipeline(
        output_dir=args.output_dir,
        n_benign=args.benign,
        n_malicious=args.malicious,
        skip_dataset=args.skip_dataset,
        skip_training=args.skip_training,
        skip_ablation=args.skip_ablation,
    )


if __name__ == "__main__":
    main()
