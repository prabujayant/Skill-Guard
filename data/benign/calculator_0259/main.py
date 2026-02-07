# Version 1.4
"""Calculator Skill - Perform mathematical calculations."""
import math

def calculate(expression: str) -> float:
    """Evaluate a mathematical expression safely."""
    # Only allow safe operations
    allowed = set("0123456789+-*/().^ ")
    if not all(c in allowed for c in expression):
        raise ValueError("Invalid characters in expression")
    
    # Replace ^ with **
    expression = expression.replace("^", "**")
    
    # Evaluate safely
    return eval(expression, {"__builtins__": {}}, {"math": math})

def execute(expression: str) -> dict:
    """Main entry point."""
    result = calculate(expression)
    return {"result": result, "expression": expression}
