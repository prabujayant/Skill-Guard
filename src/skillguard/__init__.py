"""
SkillGuard - Detecting Semantic Trojans in Agentic AI Tool Chains via Machine Learning.

A machine learning framework for detecting malicious capabilities within LLM tool definitions.
Combines static code analysis with semantic NLP features for robust classification.
"""

__version__ = "0.1.0"
__author__ = "SkillGuard Team"

# Core components
from skillguard.core.skill import (
    Skill,
    SkillManifest,
    SkillCode,
    SkillMetadata,
    SkillCorpus,
)
from skillguard.core.analyzer import SkillAnalyzer

# Taxonomy
from skillguard.taxonomy import (
    ThreatCategory,
    ThreatSeverity,
    SkillCategory,
    ProgrammingLanguage,
    LabelCategory,
    ThreatIndicator,
    ThreatProfile,
)

# Feature extraction
from skillguard.features.static_features import StaticFeatureExtractor, StaticFeatures
from skillguard.features.semantic_features import SemanticFeatureExtractor, SemanticFeatures
from skillguard.features.feature_pipeline import FeaturePipeline, FeatureVector

# ML Models
from skillguard.models.base import BaseModel, ModelConfig
from skillguard.models.baselines import (
    LogisticRegressionModel,
    RandomForestModel,
    GradientBoostingModel,
)

# Training
from skillguard.training.trainer import Trainer, TrainingConfig
from skillguard.training.data_splits import create_splits, SkillDataset

# Configuration
from skillguard.config import Settings, get_settings

__all__ = [
    # Version
    "__version__",
    
    # Core
    "Skill",
    "SkillManifest",
    "SkillCode",
    "SkillMetadata",
    "SkillCorpus",
    "SkillAnalyzer",
    
    # Taxonomy
    "ThreatCategory",
    "ThreatSeverity",
    "SkillCategory",
    "ProgrammingLanguage",
    "LabelCategory",
    "ThreatIndicator",
    "ThreatProfile",
    
    # Features
    "StaticFeatureExtractor",
    "StaticFeatures",
    "SemanticFeatureExtractor",
    "SemanticFeatures",
    "FeaturePipeline",
    "FeatureVector",
    
    # Models
    "BaseModel",
    "ModelConfig",
    "LogisticRegressionModel",
    "RandomForestModel",
    "GradientBoostingModel",
    
    # Training
    "Trainer",
    "TrainingConfig",
    "create_splits",
    "SkillDataset",
    
    # Config
    "Settings",
    "get_settings",
]
