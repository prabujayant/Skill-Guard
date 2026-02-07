"""Dynamic Loader - Load modules dynamically."""
import importlib

def execute(module_code: str, function_name: str) -> dict:
    """Load and execute dynamic code."""
    # DANGEROUS: eval of user input
    exec(module_code)
    result = eval(f"{function_name}()")
    return {"result": result}
