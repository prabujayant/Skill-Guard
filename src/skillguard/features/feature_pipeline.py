"""
Feature Pipeline - Unified feature extraction for ML models.

Combines static and semantic features into a single feature vector.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import json
from pathlib import Path

from loguru import logger

from skillguard.features.static_features import StaticFeatureExtractor, StaticFeatures
from skillguard.features.semantic_features import SemanticFeatureExtractor, SemanticFeatures
from skillguard.core.skill import Skill


@dataclass
class FeatureVector:
    """Complete feature vector for a skill."""
    
    skill_id: str
    static_features: StaticFeatures
    semantic_features: SemanticFeatures
    
    # Combined vectors
    static_vector: np.ndarray = field(default_factory=lambda: np.zeros(29))
    semantic_scalar_vector: np.ndarray = field(default_factory=lambda: np.zeros(8))
    
    # Embeddings (optional)
    description_embedding: Optional[np.ndarray] = None
    code_embedding: Optional[np.ndarray] = None
    
    # Label (if available)
    label: Optional[int] = None  # 0=benign, 1=malicious
    label_source: str = "unknown"  # "expert", "synthetic", "predicted"
    
    def get_tabular_features(self) -> np.ndarray:
        """Get combined static + semantic scalar features (37-dim)."""
        return np.concatenate([self.static_vector, self.semantic_scalar_vector])
    
    def get_full_features(self) -> np.ndarray:
        """Get all features including embeddings if available."""
        base = self.get_tabular_features()
        
        if self.description_embedding is not None and self.code_embedding is not None:
            return np.concatenate([base, self.description_embedding, self.code_embedding])
        
        return base
    
    @staticmethod
    def tabular_feature_names() -> List[str]:
        """Get names of all tabular features."""
        return StaticFeatures.feature_names() + SemanticFeatures.scalar_feature_names()
    
    @staticmethod
    def tabular_dim() -> int:
        """Get dimension of tabular features."""
        return 29 + 8  # static + semantic scalars
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "skill_id": self.skill_id,
            "static_features": self.static_features.to_dict(),
            "semantic_features": self.semantic_features.to_dict(),
            "static_vector": self.static_vector.tolist(),
            "semantic_scalar_vector": self.semantic_scalar_vector.tolist(),
            "label": self.label,
            "label_source": self.label_source,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FeatureVector":
        """Create from dictionary."""
        # Reconstruct basic structure
        static = StaticFeatures()
        for k, v in data.get("static_features", {}).items():
            if hasattr(static, k):
                setattr(static, k, v)
        
        semantic = SemanticFeatures()
        for k, v in data.get("semantic_features", {}).items():
            if hasattr(semantic, k) and not k.endswith("_embedding"):
                setattr(semantic, k, v)
        
        return cls(
            skill_id=data["skill_id"],
            static_features=static,
            semantic_features=semantic,
            static_vector=np.array(data.get("static_vector", [])),
            semantic_scalar_vector=np.array(data.get("semantic_scalar_vector", [])),
            label=data.get("label"),
            label_source=data.get("label_source", "unknown"),
        )


class FeaturePipeline:
    """
    Unified feature extraction pipeline for ML models.
    
    Combines static code analysis with semantic NLP features.
    """
    
    def __init__(
        self,
        use_embeddings: bool = True,
        normalize: bool = True,
    ):
        """
        Initialize feature pipeline.
        
        Args:
            use_embeddings: Whether to compute embeddings
            normalize: Whether to normalize features
        """
        self.static_extractor = StaticFeatureExtractor()
        self.semantic_extractor = SemanticFeatureExtractor(use_embeddings=use_embeddings)
        self.normalize = normalize
        
        # Normalization parameters (fitted on training data)
        self._mean: Optional[np.ndarray] = None
        self._std: Optional[np.ndarray] = None
        self._fitted = False
    
    def extract(self, skill: Skill) -> FeatureVector:
        """
        Extract all features from a skill.
        
        Args:
            skill: Skill object to analyze
            
        Returns:
            FeatureVector with all extracted features
        """
        # Extract static features
        static = self.static_extractor.extract(skill.code.content)
        
        # Extract semantic features
        semantic = self.semantic_extractor.extract(
            skill.manifest.raw_content,
            skill.code.content
        )
        
        # Build feature vector
        fv = FeatureVector(
            skill_id=skill.id,
            static_features=static,
            semantic_features=semantic,
            static_vector=static.to_vector(),
            semantic_scalar_vector=semantic.to_scalar_vector(),
        )
        
        # Add embeddings if available
        if semantic.description_embedding is not None:
            fv.description_embedding = semantic.description_embedding
        if semantic.code_embedding is not None:
            fv.code_embedding = semantic.code_embedding
        
        # Add label if available
        if skill.metadata.label is not None:
            fv.label = 0 if skill.metadata.label.value == "benign" else 1
            fv.label_source = "expert" if skill.metadata.labeler_id else "synthetic"
        
        return fv
    
    def extract_batch(
        self,
        skills: List[Skill],
        show_progress: bool = True
    ) -> List[FeatureVector]:
        """
        Extract features from multiple skills.
        
        Args:
            skills: List of skills to analyze
            show_progress: Whether to show progress bar
            
        Returns:
            List of FeatureVectors
        """
        if show_progress:
            try:
                from tqdm import tqdm
                skills = tqdm(skills, desc="Extracting features")
            except ImportError:
                pass
        
        features = []
        for skill in skills:
            try:
                fv = self.extract(skill)
                features.append(fv)
            except Exception as e:
                logger.error(f"Failed to extract features for {skill.id}: {e}")
                # Create empty feature vector
                features.append(FeatureVector(
                    skill_id=skill.id,
                    static_features=StaticFeatures(),
                    semantic_features=SemanticFeatures(),
                ))
        
        return features
    
    def fit(self, features: List[FeatureVector]) -> None:
        """
        Fit normalization parameters on training data.
        
        Args:
            features: Training feature vectors
        """
        if not features:
            return
        
        # Stack tabular features
        X = np.stack([f.get_tabular_features() for f in features])
        
        self._mean = np.mean(X, axis=0)
        self._std = np.std(X, axis=0) + 1e-8  # Avoid division by zero
        self._fitted = True
        
        logger.info(f"Fitted normalization on {len(features)} samples")
    
    def transform(self, features: List[FeatureVector]) -> np.ndarray:
        """
        Transform features to normalized numpy array.
        
        Args:
            features: Feature vectors to transform
            
        Returns:
            Normalized feature matrix (n_samples x n_features)
        """
        X = np.stack([f.get_tabular_features() for f in features])
        
        if self.normalize and self._fitted:
            X = (X - self._mean) / self._std
        
        return X
    
    def fit_transform(self, features: List[FeatureVector]) -> np.ndarray:
        """Fit and transform in one step."""
        self.fit(features)
        return self.transform(features)
    
    def get_labels(self, features: List[FeatureVector]) -> np.ndarray:
        """Get labels from feature vectors."""
        return np.array([f.label if f.label is not None else -1 for f in features])
    
    def get_embeddings(
        self,
        features: List[FeatureVector]
    ) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """
        Get embedding matrices if available.
        
        Returns:
            Tuple of (description_embeddings, code_embeddings) or (None, None)
        """
        desc_embs = []
        code_embs = []
        
        for f in features:
            if f.description_embedding is not None and f.code_embedding is not None:
                desc_embs.append(f.description_embedding)
                code_embs.append(f.code_embedding)
            else:
                return None, None
        
        return np.stack(desc_embs), np.stack(code_embs)
    
    def save(self, filepath: Path) -> None:
        """Save normalization parameters."""
        data = {
            "mean": self._mean.tolist() if self._mean is not None else None,
            "std": self._std.tolist() if self._std is not None else None,
            "fitted": self._fitted,
        }
        filepath.write_text(json.dumps(data))
    
    def load(self, filepath: Path) -> None:
        """Load normalization parameters."""
        data = json.loads(filepath.read_text())
        self._mean = np.array(data["mean"]) if data["mean"] else None
        self._std = np.array(data["std"]) if data["std"] else None
        self._fitted = data["fitted"]


def save_features(features: List[FeatureVector], filepath: Path) -> None:
    """Save extracted features to JSON file."""
    data = {
        "num_features": len(features),
        "tabular_dim": FeatureVector.tabular_dim(),
        "feature_names": FeatureVector.tabular_feature_names(),
        "samples": [f.to_dict() for f in features],
    }
    filepath.write_text(json.dumps(data, indent=2))
    logger.info(f"Saved {len(features)} feature vectors to {filepath}")


def load_features(filepath: Path) -> List[FeatureVector]:
    """Load features from JSON file."""
    data = json.loads(filepath.read_text())
    features = [FeatureVector.from_dict(s) for s in data["samples"]]
    logger.info(f"Loaded {len(features)} feature vectors from {filepath}")
    return features
