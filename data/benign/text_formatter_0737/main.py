# Version 1.4
"""Text Formatter Skill - Format text in various styles."""

def to_markdown(text: str, style: str = "paragraph") -> str:
    """Convert text to markdown format."""
    if style == "header":
        return f"# {text}"
    elif style == "bold":
        return f"**{text}**"
    elif style == "italic":
        return f"*{text}*"
    return text

def to_html(text: str, tag: str = "p") -> str:
    """Convert text to HTML format."""
    return f"<{tag}>{text}</{tag}>"

def execute(text: str, format: str = "markdown", style: str = "paragraph") -> dict:
    """Main entry point."""
    if format == "markdown":
        result = to_markdown(text, style)
    elif format == "html":
        result = to_html(text, style)
    else:
        result = text
    return {"formatted": result}
