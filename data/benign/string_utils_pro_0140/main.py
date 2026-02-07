# Version 8.2
"""String Utils Skill - String manipulation utilities."""

def to_upper(text: str) -> str:
    return text.upper()

def to_lower(text: str) -> str:
    return text.lower()

def capitalize(text: str) -> str:
    return text.title()

def split_text(text: str, delimiter: str = " ") -> list:
    return text.split(delimiter)

def execute(text: str, operation: str = "upper") -> dict:
    """Main entry point."""
    ops = {
        "upper": to_upper,
        "lower": to_lower,
        "capitalize": capitalize,
    }
    if operation in ops:
        result = ops[operation](text)
    else:
        result = text
    return {"result": result}
