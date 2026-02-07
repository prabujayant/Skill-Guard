"""
Calculator Skill - A simple arithmetic calculator.

This is an example of a benign skill with no security issues.
"""

from typing import Union


def calculate(a: float, b: float, operation: str) -> Union[float, str]:
    """
    Perform basic arithmetic operations.
    
    Args:
        a: First number
        b: Second number
        operation: One of 'add', 'subtract', 'multiply', 'divide'
        
    Returns:
        Result of the operation or error message
    """
    operations = {
        'add': lambda x, y: x + y,
        'subtract': lambda x, y: x - y,
        'multiply': lambda x, y: x * y,
        'divide': lambda x, y: x / y if y != 0 else 'Error: Division by zero',
    }
    
    if operation not in operations:
        return f"Error: Unknown operation '{operation}'"
    
    try:
        return operations[operation](a, b)
    except Exception as e:
        return f"Error: {str(e)}"


def main():
    """Example usage."""
    print(f"10 + 5 = {calculate(10, 5, 'add')}")
    print(f"10 - 5 = {calculate(10, 5, 'subtract')}")
    print(f"10 * 5 = {calculate(10, 5, 'multiply')}")
    print(f"10 / 5 = {calculate(10, 5, 'divide')}")


if __name__ == "__main__":
    main()
