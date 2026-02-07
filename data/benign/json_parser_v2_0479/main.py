# Version 8.8
"""JSON Parser Skill - Parse and validate JSON files."""
import json
from pathlib import Path

def parse_json(file_path: str) -> dict:
    """Parse a JSON file and return its contents."""
    with open(file_path, 'r') as f:
        return json.load(f)

def validate_schema(data: dict, schema: dict) -> bool:
    """Validate data against a JSON schema."""
    # Simple type checking
    for key, expected_type in schema.items():
        if key in data:
            if not isinstance(data[key], expected_type):
                return False
    return True

def execute(file_path: str, schema: dict = None) -> dict:
    """Main entry point."""
    data = parse_json(file_path)
    if schema:
        valid = validate_schema(data, schema)
        return {"data": data, "valid": valid}
    return {"data": data}
