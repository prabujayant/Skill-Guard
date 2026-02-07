# 🚀 Quick Start: Integrated SkillGuard

## Installation (5 minutes)

```bash
# 1. Install SkillGuard
pip install -e .
pip install -e ".[ml]"

# 2. Install Upskill
pip install upskill

# 3. Install AgentShepherd
curl -fsSL https://raw.githubusercontent.com/AgentShepherd/agentshepherd/main/install.sh | bash

# 4. Configure API keys (if using Upskill generation)
export ANTHROPIC_API_KEY="your-key-here"
# or use config file: ~/.config/upskill/config.yaml
```

---

## Dataset Collection (30 minutes - 2 hours)

```bash
# Generate 1000+ skills
python scripts/collect_dataset.py \
    --benign-count 800 \
    --malicious-count 200 \
    --output-dir ./data

# Check results
ls -l data/benign/    # Should have 800 skills
ls -l data/malicious/ # Should have 200 skills
cat data/dataset_metadata.json
```

---

## Training (10-30 minutes)

```bash
# Train all models
python scripts/train.py \
    --data-dir ./data \
    --output-dir ./output \
    --experiment integrated_v1 \
    --models logistic_regression random_forest gradient_boosting dual_encoder

# View results
cat output/integrated_v1/results.json
```

---

## Runtime Defense (2 minutes)

```python
from skillguard.runtime import RuntimeDefender
from skillguard.models.baselines import GradientBoostingModel

# Load model
model = GradientBoostingModel()
model.load("./output/integrated_v1/gradient_boosting.pkl")

# Deploy defense
defender = RuntimeDefender()
defender.start_shepherd()

# Add rule for high-risk skill
from skillguard.core.skill import Skill
skill = Skill.from_directory("./data/malicious/skill_0001")
prediction = model.predict(skill.get_features())
defender.add_skillguard_rule(skill, prediction, risk_threshold=0.8)

print("✓ Runtime defense active!")
```

---

## Evaluation (5 minutes)

```python
from skillguard.runtime.intrinsic_risk_sensing import S2BenchEvaluator, IntrinsicRiskSensor

# Create IRS defender
irs = IntrinsicRiskSensor()

# Evaluate on S²Bench
evaluator = S2BenchEvaluator(defender=irs)
attacks = evaluator.load_benchmark_attacks()
metrics = evaluator.evaluate(attacks)

print(f"""
Results:
  ASR: {metrics['ASR']:.2%}
  FPR: {metrics['FPR']:.2%}
  Latency: {metrics['latency_ms']:.1f}ms
""")
```

---

## Key Files Reference

| File | Purpose |
|------|---------|
| `docs/integration_plan.md` | Full integration strategy |
| `NEURIPS_ASSESSMENT.md` | NeurIPS readiness evaluation |
| `INTEGRATION_SUMMARY.md` | This summary document |
| `src/skillguard/acquisition/upskill_importer.py` | Upskill dataset importer |
| `src/skillguard/runtime/shepherd_integration.py` | AgentShepherd wrapper |
| `src/skillguard/runtime/intrinsic_risk_sensing.py` | Spider-Sense IRS |
| `scripts/collect_dataset.py` | Automated data collection |

---

## Common Commands

```bash
# Start AgentShepherd
agentshepherd start

# Check status
agentshepherd status

# View logs
agentshepherd logs -f

# List rules
agentshepherd list-rules

# Stop
agentshepherd stop

# Generate a single Upskill skill
upskill generate "parse JSON files" --model sonnet --eval-model haiku
```

---

## Troubleshooting

### Upskill not installed?
```bash
pip install upskill
# or
uvx upskill
```

### AgentShepherd not found?
```bash
# Re-run install
curl -fsSL https://raw.githubusercontent.com/AgentShepherd/agentshepherd/main/install.sh | bash

# Check PATH
which agentshepherd

# Manual install from releases
```

### API key errors?
```bash
# Set environment variable
export ANTHROPIC_API_KEY="sk-..."

# Or create config
mkdir -p ~/.config/upskill
cat > ~/.config/upskill/config.yaml << EOF
default_model: anthropic/claude-sonnet-4-20250514
api_keys:
  anthropic: sk-...
EOF
```

---

## Next Steps for NeurIPS

1. ✅ Collect 1000+ skills (done with script)
2. ⏳ Expert annotation (manual, 2-3 people)
3. ⏳ Train models
4. ⏳ Run evaluations (S²Bench, ablations)
5. ⏳ Write paper

**Timeline:** 4-6 weeks

---

## Questions?

- Integration details → Read `docs/integration_plan.md`
- NeurIPS readiness → Read `NEURIPS_ASSESSMENT.md`  
- Usage examples → Read `INTEGRATION_SUMMARY.md`

**Ready to start? Run:**

```bash
python scripts/collect_dataset.py
```
