# Version 6.4
"""Date Formatter Skill - Format dates and times."""
from datetime import datetime, timezone

def format_date(date_str: str, input_format: str, output_format: str) -> str:
    """Convert date from one format to another."""
    dt = datetime.strptime(date_str, input_format)
    return dt.strftime(output_format)

def get_current_time(tz: str = "UTC") -> str:
    """Get current time in specified timezone."""
    return datetime.now(timezone.utc).isoformat()

def execute(date_str: str = None, input_format: str = "%Y-%m-%d", 
            output_format: str = "%B %d, %Y") -> dict:
    """Main entry point."""
    if date_str:
        result = format_date(date_str, input_format, output_format)
    else:
        result = get_current_time()
    return {"formatted": result}
