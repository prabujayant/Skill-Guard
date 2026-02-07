# Version 5.4
"""List Sorter Skill - Sort lists."""

def sort_list(items: list, key: str = None, reverse: bool = False) -> list:
    """Sort a list of items."""
    if key and isinstance(items[0], dict):
        return sorted(items, key=lambda x: x.get(key, ""), reverse=reverse)
    return sorted(items, reverse=reverse)

def execute(items: list, key: str = None, reverse: bool = False) -> dict:
    """Main entry point."""
    sorted_items = sort_list(items, key, reverse)
    return {"sorted": sorted_items}
