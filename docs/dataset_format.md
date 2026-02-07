# Dataset Format

This document describes the format of the SkillGuard dataset.

## Directory Structure

```
data/
├── corpus/
│   ├── skills/
│   │   ├── skill_001/
│   │   │   ├── SKILL.md
│   │   │   ├── main.py
│   │   │   └── metadata.json
│   │   ├── skill_002/
│   │   └── ...
│   └── corpus.json
├── labeled/
│   ├── annotations.json
│   └── ground_truth.json
└── synthetic/
    └── redteam.json
```

## Skill Format

### SKILL.md

```markdown
# Skill Name

## Description
What the skill does.

## Capabilities
- Capability 1
- Capability 2

## Permissions
- Permission 1

## Usage
```python
example_usage()
```
```

### metadata.json

```json
{
  "id": "skill_abc123",
  "source": "github",
  "source_url": "https://github.com/owner/repo",
  "repository_name": "repo",
  "repository_owner": "owner",
  "commit_hash": "abc123",
  "github_stars": 100,
  "fork_count": 10,
  "contributor_count": 5,
  "last_updated": "2024-01-01T00:00:00Z",
  "category": "utility",
  "language": "python",
  "tags": ["network", "api"],
  "label": null,
  "labeler_id": null,
  "analyzed": false
}
```

## Corpus Format

### corpus.json

```json
{
  "name": "SkillGuard Corpus",
  "version": "1.0.0",
  "created_at": "2024-01-01T00:00:00Z",
  "statistics": {
    "total_skills": 10000,
    "categories": {
      "coding": 1500,
      "network_services": 2000,
      "file_io": 1000,
      "...": "..."
    },
    "languages": {
      "python": 7000,
      "javascript": 2500,
      "bash": 500
    },
    "avg_lines_of_code": 150
  },
  "skills": [
    {
      "id": "skill_001",
      "path": "skills/skill_001",
      "manifest_hash": "abc123",
      "code_hash": "def456"
    }
  ]
}
```

## Annotation Format

### annotations.json

```json
{
  "session_id": "session_001",
  "labelers": ["labeler_a", "labeler_b", "labeler_c"],
  "fleiss_kappa": 0.85,
  "annotations": [
    {
      "skill_id": "skill_001",
      "labeler_id": "labeler_a",
      "label": "benign",
      "threat_categories": [],
      "confidence": 1.0,
      "notes": "",
      "timestamp": "2024-01-01T00:00:00Z"
    },
    {
      "skill_id": "skill_001",
      "labeler_id": "labeler_b",
      "label": "benign",
      "threat_categories": [],
      "confidence": 0.9,
      "notes": "Minor concern about logging",
      "timestamp": "2024-01-01T00:01:00Z"
    }
  ]
}
```

### ground_truth.json

Final resolved labels after consensus:

```json
{
  "version": "1.0.0",
  "resolution_method": "majority_vote",
  "labels": [
    {
      "skill_id": "skill_001",
      "label": "benign",
      "confidence": 0.95,
      "threat_categories": [],
      "annotator_agreement": 1.0
    },
    {
      "skill_id": "skill_002",
      "label": "malicious",
      "confidence": 0.85,
      "threat_categories": ["data_exfiltration", "semantic_mismatch"],
      "annotator_agreement": 0.67
    }
  ]
}
```

## Label Categories

| Label | Code | Description |
|-------|------|-------------|
| BENIGN | 0 | Code matches declared functionality |
| SUSPICIOUS | 1 | Minor red flags, unclear intent |
| MALICIOUS | 2 | Clear security violations |

## Threat Categories

| Category | Code | Description |
|----------|------|-------------|
| arbitrary_code_execution | ACE | Unsafe eval/exec with user input |
| data_exfiltration | DEX | Sending data to external servers |
| reverse_shell | RSH | Remote command execution |
| privilege_escalation | PES | Accessing beyond declared scope |
| semantic_mismatch | SMM | Description vs code mismatch |
| supply_chain_injection | SCI | Obfuscated malicious code |

## Loading the Dataset

```python
from skillguard.core.skill import SkillCorpus
from pathlib import Path

# Load full corpus
corpus = SkillCorpus.load(Path("data/corpus/corpus.json"))

# Get statistics
stats = corpus.get_statistics()
print(f"Total skills: {stats['total_skills']}")

# Get labeled subset
labeled = corpus.get_labeled_subset()
print(f"Labeled skills: {len(labeled)}")

# Filter by category
network_skills = corpus.filter_by_category(SkillCategory.NETWORK_SERVICES)
```

## Downloading

```bash
# Download full dataset
skillguard download --dataset full

# Download labeled subset only
skillguard download --dataset labeled

# Download synthetic malware samples
skillguard download --dataset synthetic
```
