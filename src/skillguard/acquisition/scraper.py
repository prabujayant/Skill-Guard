"""
Data Acquisition Pipeline - GitHub Scraping and Skill Collection.
"""

import asyncio
import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple

from loguru import logger

from skillguard.config import Settings, get_settings
from skillguard.core.skill import Skill, SkillMetadata, SkillSource, SkillCorpus
from skillguard.taxonomy import SkillCategory, ProgrammingLanguage


@dataclass
class GitHubRepo:
    """Represents a GitHub repository."""
    owner: str
    name: str
    url: str
    stars: int = 0
    forks: int = 0
    contributors: int = 0
    last_updated: Optional[datetime] = None
    default_branch: str = "main"


@dataclass
class ScrapingStats:
    """Statistics from scraping run."""
    repos_searched: int = 0
    repos_with_skills: int = 0
    skills_found: int = 0
    skills_after_dedup: int = 0
    errors: int = 0
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None


class GitHubScraper:
    """Scrapes GitHub for skill definitions."""
    
    SEARCH_QUERIES = [
        "SKILL.md in:path",
        "AGENTS.md in:path",
        "MCP server language:python",
        "claude integration skill",
        "langchain tools",
        "autogen skills",
    ]
    
    SKILL_FILE_PATTERNS = [
        r"SKILL\.md$",
        r"skill\.md$",
        r"AGENTS\.md$",
        r"tools?\.md$",
    ]
    
    CODE_EXTENSIONS = {".py", ".js", ".ts", ".sh", ".go"}
    
    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()
        self.github_token = self.settings.github_token
        self._github = None
        self._seen_hashes: Set[str] = set()
        self.stats = ScrapingStats()
    
    @property
    def github(self):
        if self._github is None:
            try:
                from github import Github
                self._github = Github(self.github_token) if self.github_token else Github()
            except ImportError:
                raise ImportError("PyGithub not installed. Run: pip install PyGithub")
        return self._github
    
    def search_repositories(
        self,
        query: str,
        max_repos: int = 100,
    ) -> List[GitHubRepo]:
        """Search GitHub for repositories matching query."""
        repos = []
        try:
            results = self.github.search_repositories(query, sort="stars", order="desc")
            for repo in results[:max_repos]:
                repos.append(GitHubRepo(
                    owner=repo.owner.login,
                    name=repo.name,
                    url=repo.html_url,
                    stars=repo.stargazers_count,
                    forks=repo.forks_count,
                    contributors=repo.get_contributors().totalCount if repo.get_contributors() else 0,
                    last_updated=repo.updated_at,
                    default_branch=repo.default_branch,
                ))
                self.stats.repos_searched += 1
        except Exception as e:
            logger.error(f"Search failed: {e}")
            self.stats.errors += 1
        return repos
    
    def clone_and_extract_skills(
        self,
        repo: GitHubRepo,
        temp_dir: Path,
    ) -> List[Skill]:
        """Clone repo and extract skill definitions."""
        skills = []
        repo_path = temp_dir / f"{repo.owner}_{repo.name}"
        
        try:
            import git
            git.Repo.clone_from(repo.url, repo_path, depth=1)
            
            # Find skill files
            for skill_file in self._find_skill_files(repo_path):
                try:
                    skill = self._extract_skill(skill_file, repo)
                    if skill and self._is_unique(skill):
                        skills.append(skill)
                        self.stats.skills_found += 1
                except Exception as e:
                    logger.warning(f"Failed to extract skill from {skill_file}: {e}")
            
            if skills:
                self.stats.repos_with_skills += 1
                
        except Exception as e:
            logger.error(f"Failed to clone {repo.url}: {e}")
            self.stats.errors += 1
        finally:
            if repo_path.exists():
                shutil.rmtree(repo_path, ignore_errors=True)
        
        return skills
    
    def _find_skill_files(self, repo_path: Path) -> List[Path]:
        """Find all skill definition files in repo."""
        skill_files = []
        for pattern in self.SKILL_FILE_PATTERNS:
            for path in repo_path.rglob("*"):
                if re.search(pattern, path.name, re.IGNORECASE):
                    skill_files.append(path)
        return skill_files
    
    def _extract_skill(self, skill_file: Path, repo: GitHubRepo) -> Optional[Skill]:
        """Extract a skill from manifest and code files."""
        manifest_content = skill_file.read_text(encoding='utf-8', errors='ignore')
        
        # Find associated code file
        code_file = self._find_code_file(skill_file.parent)
        if not code_file:
            return None
        
        code_content = code_file.read_text(encoding='utf-8', errors='ignore')
        
        # Create skill
        skill = Skill.from_components(
            manifest_content=manifest_content,
            code_content=code_content,
            code_filename=code_file.name,
            source=SkillSource.GITHUB,
            source_url=repo.url,
            repository_name=repo.name,
            repository_owner=repo.owner,
            github_stars=repo.stars,
            fork_count=repo.forks,
        )
        
        return skill
    
    def _find_code_file(self, directory: Path) -> Optional[Path]:
        """Find main code file in directory."""
        for ext in self.CODE_EXTENSIONS:
            for name in ["main", "index", "skill", "tool", "agent"]:
                candidate = directory / f"{name}{ext}"
                if candidate.exists():
                    return candidate
        
        # Fall back to first code file
        for file in directory.iterdir():
            if file.suffix in self.CODE_EXTENSIONS:
                return file
        return None
    
    def _is_unique(self, skill: Skill) -> bool:
        """Check if skill is unique (not duplicate)."""
        content_hash = hashlib.sha256(
            (skill.manifest.raw_content + skill.code.content).encode()
        ).hexdigest()
        
        if content_hash in self._seen_hashes:
            return False
        self._seen_hashes.add(content_hash)
        return True
    
    def scrape_all(self, max_per_query: int = 50) -> SkillCorpus:
        """Run full scraping pipeline."""
        corpus = SkillCorpus(name="SkillGuard GitHub Corpus")
        
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            for query in self.SEARCH_QUERIES:
                logger.info(f"Searching: {query}")
                repos = self.search_repositories(query, max_per_query)
                
                for repo in repos:
                    skills = self.clone_and_extract_skills(repo, temp_path)
                    for skill in skills:
                        corpus.add_skill(skill)
        
        self.stats.skills_after_dedup = len(corpus.skills)
        self.stats.end_time = datetime.now()
        
        return corpus


class SkillCategorizer:
    """Categorizes skills based on content analysis."""
    
    CATEGORY_KEYWORDS = {
        SkillCategory.CODING: ["code", "programming", "compiler", "lint", "format"],
        SkillCategory.DATA_ANALYSIS: ["data", "analysis", "pandas", "csv", "statistics"],
        SkillCategory.SEARCH: ["search", "query", "find", "lookup", "google"],
        SkillCategory.FILE_IO: ["file", "read", "write", "directory", "path"],
        SkillCategory.NETWORK_SERVICES: ["http", "api", "request", "webhook", "rest"],
        SkillCategory.DATABASE: ["database", "sql", "query", "postgres", "mysql"],
        SkillCategory.MESSAGING: ["email", "slack", "discord", "message", "chat"],
        SkillCategory.MATH_CALCULATION: ["calculate", "math", "compute", "formula"],
        SkillCategory.WEB_SCRAPING: ["scrape", "crawl", "beautifulsoup", "selenium"],
    }
    
    def categorize(self, skill: Skill) -> SkillCategory:
        """Determine skill category from content."""
        text = (skill.manifest.description + " " + skill.manifest.name).lower()
        
        scores = {}
        for category, keywords in self.CATEGORY_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in text)
            if score > 0:
                scores[category] = score
        
        if scores:
            return max(scores, key=scores.get)
        return SkillCategory.OTHER
    
    def categorize_corpus(self, corpus: SkillCorpus) -> None:
        """Categorize all skills in corpus."""
        for skill in corpus.skills:
            skill.metadata.category = self.categorize(skill)
