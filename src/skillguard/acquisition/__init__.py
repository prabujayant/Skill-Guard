"""
Data acquisition module exports.
"""

from skillguard.acquisition.scraper import (
    GitHubScraper,
    GitHubRepo,
    ScrapingStats,
    SkillCategorizer,
)

__all__ = [
    "GitHubScraper",
    "GitHubRepo", 
    "ScrapingStats",
    "SkillCategorizer",
]
