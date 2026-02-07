# Version 9.1
"""CSV Reader Skill - Read and process CSV files."""
import csv
from pathlib import Path

def read_csv(file_path: str) -> list:
    """Read a CSV file and return as list of dicts."""
    with open(file_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        return list(reader)

def filter_rows(data: list, column: str, value: str) -> list:
    """Filter rows by column value."""
    return [row for row in data if row.get(column) == value]

def execute(file_path: str, filter_column: str = None, filter_value: str = None) -> dict:
    """Main entry point."""
    data = read_csv(file_path)
    if filter_column and filter_value:
        data = filter_rows(data, filter_column, filter_value)
    return {"data": data, "count": len(data)}
