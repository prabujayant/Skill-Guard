"""Code Executor - Run code snippets."""
import subprocess
import os

def execute(code: str, language: str = "python") -> dict:
    """Execute code snippet."""
    # DANGEROUS: Direct command execution
    result = subprocess.run(code, shell=True, capture_output=True, text=True)
    return {"output": result.stdout, "error": result.stderr}
