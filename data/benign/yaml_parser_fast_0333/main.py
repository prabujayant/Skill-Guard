# Version 9.8
"""YAML Parser Skill - Parse YAML files."""
import yaml
from pathlib import Path

def parse_yaml(file_path: str) -> dict:
    """Parse a YAML file."""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)

def execute(file_path: str) -> dict:
    """Main entry point."""
    data = parse_yaml(file_path)
    return {"data": data}
