# SkillGuard

**Detecting Semantic Trojans in Agentic AI Tool Chains via Machine Learning**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Overview

SkillGuard is a machine learning framework for detecting malicious capabilities within LLM tool definitions. While AI security research focuses on prompt injection, we address an understudied problem: **Malicious Tool Supply Chains**—where models are compliant, but executing code contains "Semantic Trojans" that violate declared purposes.

### Key Contributions

1. **Novel Dataset**: 1,200+ agent skills with expert annotations for supervised learning research
2. **Learning-Based Detection**: First ML framework combining static program features + semantic embeddings
3. **Theoretical Analysis**: Formalization of semantic mismatch as a distributional shift problem
4. **Benchmark Suite**: Standardized evaluation protocol for malicious tool detection

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SkillGuard ML Pipeline                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐    ┌──────────────────┐    ┌────────────────────────────┐ │
│  │   SKILL.md  │───▶│ Semantic Feature │───▶│                            │ │
│  │ Description │    │   Extractor      │    │                            │ │
│  └─────────────┘    └──────────────────┘    │                            │ │
│                            │                │   ML Classifier            │ │
│                            │ Embeddings     │   ────────────────         │ │
│                            │ + Capability   │   • Logistic Regression    │ │
│                            │   Analysis     │   • Random Forest          │ │
│                            ▼                │   • Gradient Boosting      │ │
│  ┌─────────────┐    ┌──────────────────┐    │   • Dual-Encoder NN       │ │
│  │   Code      │───▶│  Static Feature  │───▶│                            │ │
│  │  (Python)   │    │   Extractor      │    │                            │ │
│  └─────────────┘    └──────────────────┘    └─────────────┬──────────────┘ │
│                            │                              │                │
│                            │ 37-dim feature vector        ▼                │
│                            │ + 768-dim embeddings   ┌──────────────┐       │
│                            │                        │   Risk Score │       │
│                            └───────────────────────▶│   0-100      │       │
│                                                     │ + Confidence │       │
│                                                     └──────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Feature Engineering

### Static Features (29 dimensions)
- **Structural**: Function count, class count, imports, LOC, cyclomatic complexity
- **Dangerous Primitives**: eval/exec calls, subprocess usage, network calls, file I/O
- **Data Flow**: Tainted input to dangerous sinks (eval, subprocess, network)
- **Obfuscation**: Base64/hex strings, dynamic imports, getattr usage

### Semantic Features (8+ dimensions)
- **Embedding Alignment**: Cosine similarity between description and code embeddings
- **Capability Mismatch**: Declared vs. actual capabilities detected in code
- **Text Statistics**: Description length, permissions section presence

## Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/skillguard.git
cd skillguard

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install core dependencies
pip install -e .

# Optional: Install ML dependencies for neural models
pip install -e ".[ml]"
```

### Generate Synthetic Dataset

```bash
python scripts/generate_dataset.py --benign 600 --malicious 200
```

### Train Models

```bash
python scripts/train.py \
    --data-dir ./data \
    --output-dir ./output/experiments \
    --experiment skillguard_v1 \
    --models logistic_regression random_forest gradient_boosting
```

### Analyze a Single Skill

```python
from skillguard.core.skill import Skill
from skillguard.features.feature_pipeline import FeaturePipeline
from skillguard.models.baselines import GradientBoostingModel

# Load skill
skill = Skill.from_directory("path/to/skill")

# Extract features
pipeline = FeaturePipeline()
features = pipeline.extract(skill)

# Load trained model
model = GradientBoostingModel()
model.load("output/experiments/skillguard_v1/gradient_boosting.pkl")

# Predict
prediction = model.predict(features.get_tabular_features().reshape(1, -1))
print(f"Malicious: {prediction.labels[0]}, Confidence: {prediction.confidence[0]:.2%}")
```

## ML Models

### Baseline Models

| Model | Description | Pros | Cons |
|-------|------------|------|------|
| Logistic Regression | Linear classifier | Interpretable, fast | Linear boundary |
| Random Forest | Ensemble of trees | Feature importance | Can overfit |
| XGBoost | Gradient boosting | SOTA for tabular | Less interpretable |

### Novel Contribution: Dual-Encoder Network

```python
class DualEncoderNet(nn.Module):
    def __init__(self):
        # Description encoder (transformer-based)
        self.desc_proj = nn.Linear(embedding_dim, 128)
        # Code encoder (CodeBERT-based)
        self.code_proj = nn.Linear(embedding_dim, 128)
        # Static feature projection
        self.static_proj = nn.Linear(static_dim, 64)
        # Fusion classifier
        self.classifier = nn.Sequential(...)
```

**Key innovations:**
- **Semantic Alignment Loss**: Regularizes description-code similarity
- **Focal Loss**: Handles class imbalance
- **Multi-modal Fusion**: Combines embeddings with static features

## Evaluation Results (Expected)

| Method | F1 | AUC | Precision | Recall |
|--------|-----|-----|-----------|--------|
| Bandit (rule-based) | 0.45 | 0.62 | 0.40 | 0.52 |
| Semgrep (pattern) | 0.51 | 0.68 | 0.55 | 0.48 |
| Random Forest | 0.76 | 0.84 | 0.72 | 0.81 |
| XGBoost | 0.82 | 0.89 | 0.78 | 0.87 |
| **SkillGuard (ours)** | **0.88** | **0.92** | **0.85** | **0.91** |

## Project Structure

```
skillguard/
├── src/skillguard/
│   ├── core/                 # Skill model, analyzer
│   ├── features/             # Feature extraction
│   │   ├── static_features.py
│   │   ├── semantic_features.py
│   │   └── feature_pipeline.py
│   ├── models/              # ML models
│   │   ├── base.py
│   │   ├── baselines.py     # LR, RF, XGBoost
│   │   └── dual_encoder.py  # Neural model
│   ├── training/            # Training utilities
│   │   ├── data_splits.py
│   │   └── trainer.py
│   ├── evaluation/          # Metrics, evaluation
│   ├── detection/           # SIFA, LLM audit (legacy)
│   └── acquisition/         # Data collection
├── scripts/
│   ├── train.py             # Main training script
│   ├── generate_dataset.py  # Synthetic data
│   └── visualize.py         # Paper figures
├── experiments/             # Jupyter notebooks
├── data/                    # Dataset
├── tests/                   # Unit tests
└── docs/                    # Documentation
```

## Research Questions

1. **RQ1**: Can ML classifiers distinguish benign from malicious skills?
2. **RQ2**: Which features contribute most to detection? (ablation study)
3. **RQ3**: Does semantic alignment improve generalization?
4. **RQ4**: How robust is detection to adversarial obfuscation?

## Citation

If you use SkillGuard in your research, please cite:

```bibtex
@inproceedings{skillguard2025,
  title={SkillGuard: Detecting Semantic Trojans in Agentic AI Tool Chains},
  author={SkillGuard Team},
  booktitle={Proceedings of ICML 2025},
  year={2025}
}
```

## License

Apache License 2.0 - see [LICENSE](LICENSE).

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

- Google SAIF for threat taxonomy alignment
- Anthropic and OpenAI for MCP standardization
- The MLsec research community
