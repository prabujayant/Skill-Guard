"""
Data splitting utilities for ML training.

Provides stratified train/val/test splits with proper handling of class imbalance.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from pathlib import Path
import json

from loguru import logger

from skillguard.core.skill import Skill, SkillCorpus
from skillguard.features.feature_pipeline import FeaturePipeline, FeatureVector


@dataclass
class SkillDataset:
    """Dataset of skills with features and labels."""
    
    name: str
    features: List[FeatureVector]
    X: np.ndarray  # Tabular features
    y: np.ndarray  # Labels
    
    # Optional embeddings
    desc_embeddings: Optional[np.ndarray] = None
    code_embeddings: Optional[np.ndarray] = None
    
    # Skill reference
    skill_ids: List[str] = field(default_factory=list)
    
    @property
    def n_samples(self) -> int:
        return len(self.features)
    
    @property
    def n_features(self) -> int:
        return self.X.shape[1]
    
    @property
    def class_distribution(self) -> Dict[int, int]:
        unique, counts = np.unique(self.y, return_counts=True)
        return dict(zip(unique.astype(int), counts.astype(int)))
    
    def get_labeled_only(self) -> "SkillDataset":
        """Get subset with valid labels only."""
        mask = self.y >= 0
        return SkillDataset(
            name=f"{self.name}_labeled",
            features=[f for f, m in zip(self.features, mask) if m],
            X=self.X[mask],
            y=self.y[mask],
            desc_embeddings=self.desc_embeddings[mask] if self.desc_embeddings is not None else None,
            code_embeddings=self.code_embeddings[mask] if self.code_embeddings is not None else None,
            skill_ids=[s for s, m in zip(self.skill_ids, mask) if m],
        )
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "n_samples": self.n_samples,
            "n_features": self.n_features,
            "class_distribution": self.class_distribution,
            "skill_ids": self.skill_ids,
        }


@dataclass
class DataSplits:
    """Train/Val/Test splits."""
    
    train: SkillDataset
    val: SkillDataset
    test: SkillDataset
    
    # Original corpus reference
    corpus_name: str = ""
    
    def __post_init__(self):
        logger.info(f"DataSplits created:")
        logger.info(f"  Train: {self.train.n_samples} samples, distribution: {self.train.class_distribution}")
        logger.info(f"  Val: {self.val.n_samples} samples, distribution: {self.val.class_distribution}")
        logger.info(f"  Test: {self.test.n_samples} samples, distribution: {self.test.class_distribution}")
    
    def save(self, output_dir: Path) -> None:
        """Save splits to directory."""
        output_dir.mkdir(parents=True, exist_ok=True)
        
        metadata = {
            "corpus_name": self.corpus_name,
            "train": self.train.to_dict(),
            "val": self.val.to_dict(),
            "test": self.test.to_dict(),
        }
        
        (output_dir / "metadata.json").write_text(json.dumps(metadata, indent=2))
        
        # Save numpy arrays
        np.save(output_dir / "train_X.npy", self.train.X)
        np.save(output_dir / "train_y.npy", self.train.y)
        np.save(output_dir / "val_X.npy", self.val.X)
        np.save(output_dir / "val_y.npy", self.val.y)
        np.save(output_dir / "test_X.npy", self.test.X)
        np.save(output_dir / "test_y.npy", self.test.y)
        
        if self.train.desc_embeddings is not None:
            np.save(output_dir / "train_desc_emb.npy", self.train.desc_embeddings)
            np.save(output_dir / "train_code_emb.npy", self.train.code_embeddings)
            np.save(output_dir / "val_desc_emb.npy", self.val.desc_embeddings)
            np.save(output_dir / "val_code_emb.npy", self.val.code_embeddings)
            np.save(output_dir / "test_desc_emb.npy", self.test.desc_embeddings)
            np.save(output_dir / "test_code_emb.npy", self.test.code_embeddings)
        
        logger.info(f"Splits saved to {output_dir}")


def create_splits(
    features: List[FeatureVector],
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    stratify: bool = True,
    random_state: int = 42,
    pipeline: Optional[FeaturePipeline] = None,
) -> DataSplits:
    """
    Create stratified train/val/test splits.
    
    Args:
        features: List of FeatureVectors
        train_ratio: Proportion for training
        val_ratio: Proportion for validation
        test_ratio: Proportion for testing
        stratify: Whether to stratify by label
        random_state: Random seed
        pipeline: Feature pipeline for normalization
        
    Returns:
        DataSplits with train/val/test datasets
    """
    from sklearn.model_selection import train_test_split
    
    # Filter to labeled only
    labeled_features = [f for f in features if f.label is not None]
    
    if not labeled_features:
        raise ValueError("No labeled features provided")
    
    # Get labels for stratification
    labels = np.array([f.label for f in labeled_features])
    indices = np.arange(len(labeled_features))
    
    # First split: train+val vs test
    train_val_idx, test_idx = train_test_split(
        indices,
        test_size=test_ratio,
        stratify=labels if stratify else None,
        random_state=random_state,
    )
    
    # Second split: train vs val
    train_val_labels = labels[train_val_idx]
    relative_val_ratio = val_ratio / (train_ratio + val_ratio)
    
    train_idx, val_idx = train_test_split(
        train_val_idx,
        test_size=relative_val_ratio,
        stratify=train_val_labels if stratify else None,
        random_state=random_state,
    )
    
    # Create datasets
    def make_dataset(indices: np.ndarray, name: str) -> SkillDataset:
        subset_features = [labeled_features[i] for i in indices]
        
        X = np.stack([f.get_tabular_features() for f in subset_features])
        y = np.array([f.label for f in subset_features])
        
        # Get embeddings if available
        desc_embs = None
        code_embs = None
        if all(f.description_embedding is not None for f in subset_features):
            desc_embs = np.stack([f.description_embedding for f in subset_features])
            code_embs = np.stack([f.code_embedding for f in subset_features])
        
        return SkillDataset(
            name=name,
            features=subset_features,
            X=X,
            y=y,
            desc_embeddings=desc_embs,
            code_embeddings=code_embs,
            skill_ids=[f.skill_id for f in subset_features],
        )
    
    train_dataset = make_dataset(train_idx, "train")
    val_dataset = make_dataset(val_idx, "val")
    test_dataset = make_dataset(test_idx, "test")
    
    # Normalize using pipeline if provided
    if pipeline is not None:
        pipeline.fit([train_dataset.features[i] for i in range(len(train_dataset.features))])
        train_dataset.X = pipeline.transform(train_dataset.features)
        val_dataset.X = pipeline.transform(val_dataset.features)
        test_dataset.X = pipeline.transform(test_dataset.features)
    
    return DataSplits(
        train=train_dataset,
        val=val_dataset,
        test=test_dataset,
    )


def create_cross_validation_folds(
    features: List[FeatureVector],
    n_folds: int = 5,
    random_state: int = 42,
) -> List[Tuple[SkillDataset, SkillDataset]]:
    """
    Create k-fold cross-validation splits.
    
    Returns:
        List of (train, val) dataset tuples
    """
    from sklearn.model_selection import StratifiedKFold
    
    labeled_features = [f for f in features if f.label is not None]
    labels = np.array([f.label for f in labeled_features])
    
    skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=random_state)
    
    folds = []
    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(labeled_features, labels)):
        train_features = [labeled_features[i] for i in train_idx]
        val_features = [labeled_features[i] for i in val_idx]
        
        train_X = np.stack([f.get_tabular_features() for f in train_features])
        train_y = np.array([f.label for f in train_features])
        
        val_X = np.stack([f.get_tabular_features() for f in val_features])
        val_y = np.array([f.label for f in val_features])
        
        train_dataset = SkillDataset(
            name=f"fold_{fold_idx}_train",
            features=train_features,
            X=train_X,
            y=train_y,
            skill_ids=[f.skill_id for f in train_features],
        )
        
        val_dataset = SkillDataset(
            name=f"fold_{fold_idx}_val",
            features=val_features,
            X=val_X,
            y=val_y,
            skill_ids=[f.skill_id for f in val_features],
        )
        
        folds.append((train_dataset, val_dataset))
    
    return folds
