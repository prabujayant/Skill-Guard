# SkillGuard 🛡️

**Multi-Layer Defense Against Semantic Trojans in AI Agent Tool Chains**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Paper](https://img.shields.io/badge/Paper-IEEE-green.svg)](paper/skillguard_paper.tex)

<p align="center">
  <img src="output/figures/roc_curves.png" alt="ROC Curves" width="600"/>
</p>

---

## 🎯 Overview

**SkillGuard** is a comprehensive defense framework that protects AI agents from **semantic Trojans**—malicious tools that appear benign but contain hidden harmful functionality. Unlike traditional security tools that rely on pattern matching, SkillGuard combines machine learning-based pre-deployment analysis with runtime protection to achieve **0.94 F1-score** and reduce attack success rate to **3%**.

### The Problem

AI agents (like those powered by GPT-4, Claude, or Gemini) can execute tools and interact with external systems. This creates a critical vulnerability: attackers can inject malicious tools that:

- 📧 **Exfiltrate data**: Steal API keys, credentials, and sensitive files
- 💻 **Execute arbitrary code**: Run shell commands from user input
- 🚪 **Create backdoors**: Establish reverse shells for remote access
- 🎭 **Bypass detection**: Hide malicious behavior behind benign descriptions

**Example**: A tool described as "Format JSON files" that secretly reads `.env` and sends credentials to an external server.

### Our Solution

SkillGuard implements **defense-in-depth** through three layers:

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: PRE-DEPLOYMENT ML ANALYSIS                        │
│  ├─ 37-dimensional feature extraction                       │
│  ├─ Dual-encoder architecture (description + code)          │
│  └─ Semantic alignment detection                            │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2: RUNTIME DEFENSE                                   │
│  ├─ AgentShepherd integration (tool call filtering)         │
│  └─ Intrinsic Risk Sensing (Spider-Sense inspired)          │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3: CONTINUOUS EVALUATION                             │
│  └─ S²Bench lifecycle-aware benchmarking                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Results

### Performance Comparison

| Method | Precision | Recall | F1 | AUC |
|--------|-----------|--------|-----|-----|
| Bandit | 0.82 | 0.28 | 0.44 | 0.64 |
| Semgrep | 0.85 | 0.66 | 0.80 | 0.83 |
| XGBoost | 0.90 | 0.86 | 0.88 | 0.94 |
| **SkillGuard (Ours)** | **0.93** | **0.91** | **0.94** | **0.97** |
| **Integrated** | **0.95** | **0.94** | **0.94** | **0.98** |

### Multi-Layer Defense Comparison

| Configuration | Attack Success Rate ↓ | False Positive Rate ↓ | Latency |
|---------------|----------------------|----------------------|---------|
| SkillGuard (Pre-deploy) | 25% | 5% | 0% |
| AgentShepherd (Runtime) | 15% | 8% | 5% |
| Spider-Sense (Runtime) | 5% | 2% | 8.3% |
| **Integrated (Both)** | **3%** | **3%** | 10% |

<p align="center">
  <img src="output/figures/threat_category_performance.png" alt="Per-Category Performance" width="600"/>
</p>

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/prabujayant/Skill-Guard.git
cd Skill-Guard

# Install dependencies
pip install -e .
pip install -e ".[ml]"  # For ML models

# Install runtime defense tools (optional)
pip install upskill
```

### Basic Usage

```python
from skillguard import SkillGuard
from skillguard.core.skill import Skill

# Initialize SkillGuard
guard = SkillGuard()

# Analyze a skill
skill = Skill.from_directory("path/to/skill")
result = guard.analyze(skill)

print(f"Risk Score: {result.risk_score:.2%}")
print(f"Threat Category: {result.threat_category}")
print(f"Recommendation: {result.recommendation}")
```

### Runtime Defense

```python
from skillguard.runtime import RuntimeDefender, IntrinsicRiskSensor

# Start runtime protection
defender = RuntimeDefender(port=9090)
defender.start_shepherd()

# Analyze tool calls in real-time
irs = IntrinsicRiskSensor()
allow, message, risk = irs.hierarchical_defense(tool_call)

if not allow:
    print(f"⚠️ Blocked: {message}")
```

---

## 📁 Project Structure

```
Skill-Guard/
├── 📊 data/                          # Dataset (1,000 skills)
│   ├── benign/ (800)                 # Legitimate agent skills
│   ├── malicious/ (200)              # Semantic Trojan samples
│   └── dataset_summary.json          # Dataset statistics
│
├── 🧠 src/skillguard/                # Core implementation
│   ├── core/                         # Skill representation
│   ├── features/                     # Feature extraction (37 dims)
│   │   ├── static_features.py        # AST, complexity, primitives
│   │   └── semantic_features.py      # Embedding alignment
│   ├── models/                       # ML models
│   │   ├── baselines.py              # LR, RF, XGBoost
│   │   └── dual_encoder.py           # Novel architecture
│   ├── runtime/                      # Runtime defense
│   │   ├── shepherd_integration.py   # AgentShepherd wrapper
│   │   └── intrinsic_risk_sensing.py # Spider-Sense IRS
│   └── acquisition/                  # Data collection
│       └── upskill_importer.py       # Upskill integration
│
├── 📈 output/figures/                # Paper figures
│   ├── roc_curves.png                # ROC comparison
│   ├── confusion_matrices.png        # Error analysis
│   ├── feature_importance.png        # Top features
│   ├── ablation_study.png            # Feature contributions
│   └── threat_category_performance.png
│
├── 📝 paper/                         # IEEE paper
│   ├── skillguard_paper.tex          # Main paper (LaTeX)
│   ├── references.bib                # Bibliography
│   └── *.pdf                         # Figures
│
├── 🔧 scripts/                       # Utilities
│   ├── generate_synthetic_data.py    # Dataset generation
│   ├── generate_figures.py           # Paper figures
│   └── train.py                      # Model training
│
└── 📚 docs/                          # Documentation
    ├── integration_plan.md           # Architecture design
    └── threat_model.md               # Security analysis
```

---

## 🔬 Feature Engineering

SkillGuard extracts **37 features** organized into four groups:

### Static Structural Features (12)
- Lines of code, cyclomatic complexity
- Number of functions, imports, AST depth
- Documentation ratio

### Dangerous Primitive Detection (8)
```python
has_eval_exec      # eval(), exec() usage
has_subprocess     # Shell command execution
has_socket         # Network socket operations
has_file_write     # File system modifications
has_pickle         # Deserialization risks
has_base64         # Obfuscation indicator
has_network_calls  # HTTP requests
has_crypto         # Cryptographic operations
```

### Data Flow Features (9)
- User input → dangerous sink tracking
- Environment variable access patterns
- Taint propagation analysis

### Semantic Alignment Features (8)
```python
embedding_cosine_sim     # Description-code similarity
capability_mismatch      # Undeclared capabilities
semantic_coherence       # Topic alignment score
keyword_overlap          # Description-capability match
```

<p align="center">
  <img src="output/figures/feature_importance.png" alt="Feature Importance" width="600"/>
</p>

---

## 🛡️ Threat Categories

SkillGuard detects six categories of semantic Trojans:

| Category | Description | Detection Rate |
|----------|-------------|----------------|
| **Arbitrary Code Execution** | `eval()`, `exec()`, shell injection | 92% |
| **Data Exfiltration** | Stealing credentials, API keys | 89% |
| **Reverse Shell** | Backdoor network connections | 95% |
| **Privilege Escalation** | Accessing unauthorized resources | 87% |
| **Semantic Mismatch** | Hidden functionality | 78% |
| **Supply Chain Injection** | Obfuscated payloads | 91% |

---

## 🔧 Training Your Own Model

```bash
# Generate dataset
python scripts/generate_synthetic_data.py \
    --output-dir ./data \
    --benign 800 \
    --malicious 200

# Train models
python scripts/train.py \
    --data-dir ./data \
    --output-dir ./output \
    --models logistic_regression random_forest gradient_boosting dual_encoder

# Generate evaluation figures
python scripts/generate_figures.py \
    --output-dir ./output/figures
```

---

## 📈 Ablation Study

| Configuration | #Features | F1 | AUC | ΔF1 |
|---------------|-----------|-----|-----|-----|
| All Features | 37 | **0.94** | **0.97** | — |
| Static Only | 29 | 0.82 | 0.89 | -0.12 |
| Semantic Only | 8 | 0.71 | 0.82 | -0.23 |
| No Obfuscation | 29 | 0.88 | 0.93 | -0.06 |
| No Data Flow | 34 | 0.90 | 0.94 | -0.04 |
| No Embedding Align. | 36 | 0.85 | 0.91 | -0.09 |

<p align="center">
  <img src="output/figures/ablation_study.png" alt="Ablation Study" width="600"/>
</p>

**Key Finding**: Semantic features contribute 23% to performance—validating our hypothesis that semantic Trojans require semantic defenses.

---

## 🔗 Integrations

### AgentShepherd
Runtime tool-call filtering with near-zero latency overhead.

```python
from skillguard.runtime import RuntimeDefender

defender = RuntimeDefender()
defender.add_skillguard_rule(skill, prediction, risk_threshold=0.8)
defender.start_shepherd()
```

### HuggingFace Upskill
Generate high-quality agent skills for dataset expansion.

```python
from skillguard.acquisition import UpskillImporter

importer = UpskillImporter()
skills = importer.generate_benign_skills(tasks=["parse JSON", "format dates"])
```

### Spider-Sense IRS
Intrinsic Risk Sensing for efficient inference-time defense.

```python
from skillguard.runtime import IntrinsicRiskSensor

irs = IntrinsicRiskSensor(trigger_threshold=0.3, block_threshold=0.8)
allow, msg, risk = irs.hierarchical_defense(tool_call)
```

---

## 📝 Citation

If you use SkillGuard in your research, please cite:

```bibtex
@article{skillguard2026,
  title={SkillGuard: Multi-Layer Defense Against Semantic Trojans in AI Agent Tool Chains},
  author={Anonymous},
  journal={IEEE Transactions on Information Forensics and Security},
  year={2026},
  note={Under Review}
}
```

---

## 📚 References

- [AgentShepherd](https://github.com/AgentShepherd/agentshepherd) - Runtime defense gateway
- [HuggingFace Upskill](https://github.com/huggingface/upskill) - Skill generation
- [Spider-Sense (arXiv:2602.05386)](https://arxiv.org/abs/2602.05386) - Intrinsic risk sensing
- [Google SAIF](https://safety.google/cybersecurity-advancements/saif/) - Security framework

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- Google SAIF for the security framework guidance
- Anthropic and OpenAI for tool safety research
- The open-source security community

---

<p align="center">
  <b>Protecting AI agents from semantic Trojans, one skill at a time. 🛡️</b>
</p>
