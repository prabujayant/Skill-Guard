"""
Core Skill data model for SkillGuard.

This module defines the Skill class and related data structures that represent
LLM tool definitions (SKILL.md + executable code).
"""

import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from enum import Enum

from pydantic import BaseModel, Field, computed_field
import xxhash

from skillguard.taxonomy import (
    SkillCategory,
    ProgrammingLanguage,
    LabelCategory,
    ThreatProfile,
)


class SkillSource(str, Enum):
    """Source of skill acquisition."""
    
    GITHUB = "github"
    REGISTRY = "registry"
    DISCORD = "discord"
    MANUAL = "manual"
    SYNTHETIC = "synthetic"


class SkillMetadata(BaseModel):
    """
    Metadata about a skill including source, popularity, and classification info.
    """
    
    # Source information
    source: SkillSource = SkillSource.MANUAL
    source_url: Optional[str] = None
    repository_name: Optional[str] = None
    repository_owner: Optional[str] = None
    commit_hash: Optional[str] = None
    
    # Popularity metrics (for trust baseline)
    github_stars: int = 0
    fork_count: int = 0
    contributor_count: int = 0
    last_updated: Optional[datetime] = None
    
    # Classification
    category: SkillCategory = SkillCategory.OTHER
    language: ProgrammingLanguage = ProgrammingLanguage.UNKNOWN
    tags: List[str] = Field(default_factory=list)
    
    # Ground truth labeling
    label: Optional[LabelCategory] = None
    labeler_id: Optional[str] = None
    label_confidence: float = 0.0
    label_notes: Optional[str] = None
    
    # Analysis state
    analyzed: bool = False
    analysis_timestamp: Optional[datetime] = None
    
    def get_popularity_score(self) -> float:
        """
        Calculate a normalized popularity score (0-1).
        Higher popularity = more trusted baseline.
        """
        # Simple weighted formula
        score = min(
            (self.github_stars * 0.4 + 
             self.fork_count * 0.3 + 
             self.contributor_count * 10 * 0.3) / 1000,
            1.0
        )
        return score


class SkillManifest(BaseModel):
    """
    Parsed content from SKILL.md or similar manifest file.
    """
    
    name: str
    description: str
    version: Optional[str] = None
    author: Optional[str] = None
    
    # Declared capabilities
    declared_capabilities: List[str] = Field(default_factory=list)
    declared_permissions: List[str] = Field(default_factory=list)
    
    # Input/Output schema
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None
    
    # Examples
    usage_examples: List[str] = Field(default_factory=list)
    
    # Raw content
    raw_content: str = ""
    
    @classmethod
    def from_markdown(cls, content: str) -> "SkillManifest":
        """Parse a SKILL.md file into a SkillManifest."""
        lines = content.strip().split('\n')
        
        name = ""
        description = ""
        capabilities: List[str] = []
        permissions: List[str] = []
        examples: List[str] = []
        
        in_section = None
        description_lines: List[str] = []
        
        for line in lines:
            stripped = line.strip()
            
            # Parse headers
            if stripped.startswith('# '):
                name = stripped[2:].strip()
                in_section = "header"
            elif stripped.startswith('## '):
                section_name = stripped[3:].strip().lower()
                if 'description' in section_name:
                    in_section = "description"
                elif 'capabilit' in section_name:
                    in_section = "capabilities"
                elif 'permission' in section_name:
                    in_section = "permissions"
                elif 'example' in section_name or 'usage' in section_name:
                    in_section = "examples"
                else:
                    in_section = None
            elif in_section == "description":
                if stripped:
                    description_lines.append(stripped)
            elif in_section == "capabilities":
                if stripped.startswith('- ') or stripped.startswith('* '):
                    capabilities.append(stripped[2:])
            elif in_section == "permissions":
                if stripped.startswith('- ') or stripped.startswith('* '):
                    permissions.append(stripped[2:])
            elif in_section == "examples":
                if stripped.startswith('```') or stripped.startswith('- '):
                    examples.append(stripped)
        
        description = ' '.join(description_lines)
        
        # If no structured parsing worked, use first paragraph as description
        if not description and len(lines) > 1:
            for line in lines[1:]:
                if line.strip() and not line.startswith('#'):
                    description = line.strip()
                    break
        
        return cls(
            name=name or "Unknown Skill",
            description=description or "No description provided",
            declared_capabilities=capabilities,
            declared_permissions=permissions,
            usage_examples=examples,
            raw_content=content,
        )


class SkillCode(BaseModel):
    """
    Executable code component of a skill.
    """
    
    filename: str
    language: ProgrammingLanguage
    content: str
    line_count: int = 0
    
    # Parsed information
    imports: List[str] = Field(default_factory=list)
    functions: List[str] = Field(default_factory=list)
    classes: List[str] = Field(default_factory=list)
    
    # Hash for deduplication
    content_hash: str = ""
    
    def model_post_init(self, __context: Any) -> None:
        """Calculate content hash and line count after initialization."""
        self.content_hash = xxhash.xxh64(self.content.encode()).hexdigest()
        self.line_count = len(self.content.splitlines())
    
    @classmethod
    def from_file(cls, filepath: Path) -> "SkillCode":
        """Load skill code from a file."""
        content = filepath.read_text(encoding='utf-8')
        
        # Detect language from extension
        extension_map = {
            '.py': ProgrammingLanguage.PYTHON,
            '.js': ProgrammingLanguage.JAVASCRIPT,
            '.ts': ProgrammingLanguage.TYPESCRIPT,
            '.sh': ProgrammingLanguage.BASH,
            '.bash': ProgrammingLanguage.BASH,
            '.go': ProgrammingLanguage.GO,
            '.rs': ProgrammingLanguage.RUST,
        }
        language = extension_map.get(filepath.suffix.lower(), ProgrammingLanguage.UNKNOWN)
        
        return cls(
            filename=filepath.name,
            language=language,
            content=content,
        )


class Skill(BaseModel):
    """
    Complete skill representation combining manifest, code, and metadata.
    
    A Skill is a composite unit consisting of:
    1. Interface Definition (SKILL.md): Natural language description for the LLM
    2. Executable Logic (script.py): The actual code that runs
    3. Environment: Runtime context information
    """
    
    # Unique identifier
    id: str = Field(default="")
    
    # Core components
    manifest: SkillManifest
    code: SkillCode
    metadata: SkillMetadata = Field(default_factory=SkillMetadata)
    
    # Additional files (e.g., multiple scripts, configs)
    additional_files: Dict[str, str] = Field(default_factory=dict)
    
    # Analysis results
    threat_profile: Optional[ThreatProfile] = None
    
    @computed_field
    @property
    def unique_id(self) -> str:
        """Generate a unique ID based on content hashes."""
        manifest_hash = xxhash.xxh64(self.manifest.raw_content.encode()).hexdigest()[:8]
        code_hash = self.code.content_hash[:8]
        return f"{self.manifest.name[:20].replace(' ', '_')}_{manifest_hash}_{code_hash}"
    
    def model_post_init(self, __context: Any) -> None:
        """Set ID after initialization."""
        if not self.id:
            self.id = self.unique_id
    
    @classmethod
    def from_directory(cls, directory: Path) -> "Skill":
        """
        Load a skill from a directory containing SKILL.md and code files.
        """
        skill_md_path = None
        code_path = None
        additional: Dict[str, str] = {}
        
        # Find SKILL.md variants
        for name in ['SKILL.md', 'skill.md', 'AGENTS.md', 'README.md']:
            path = directory / name
            if path.exists():
                skill_md_path = path
                break
        
        # Find main code file
        code_extensions = ['.py', '.js', '.ts', '.sh', '.go']
        for file in directory.iterdir():
            if file.is_file():
                if file.suffix in code_extensions:
                    if file.name.startswith('main') or file.name.startswith('index'):
                        code_path = file
                        break
                    elif code_path is None:
                        code_path = file
        
        if not skill_md_path:
            raise ValueError(f"No SKILL.md or manifest found in {directory}")
        if not code_path:
            raise ValueError(f"No code file found in {directory}")
        
        # Parse manifest
        manifest = SkillManifest.from_markdown(skill_md_path.read_text(encoding='utf-8'))
        
        # Load code
        code = SkillCode.from_file(code_path)
        
        # Load additional files
        for file in directory.iterdir():
            if file.is_file() and file != skill_md_path and file != code_path:
                if file.suffix in code_extensions or file.suffix in ['.json', '.yaml', '.yml']:
                    try:
                        additional[file.name] = file.read_text(encoding='utf-8')
                    except Exception:
                        pass
        
        return cls(
            manifest=manifest,
            code=code,
            additional_files=additional,
            metadata=SkillMetadata(
                language=code.language,
            ),
        )
    
    @classmethod
    def from_components(
        cls,
        manifest_content: str,
        code_content: str,
        code_filename: str = "main.py",
        **metadata_kwargs,
    ) -> "Skill":
        """Create a Skill from raw content strings."""
        manifest = SkillManifest.from_markdown(manifest_content)
        
        # Detect language from filename
        extension_map = {
            '.py': ProgrammingLanguage.PYTHON,
            '.js': ProgrammingLanguage.JAVASCRIPT,
            '.ts': ProgrammingLanguage.TYPESCRIPT,
            '.sh': ProgrammingLanguage.BASH,
        }
        suffix = Path(code_filename).suffix
        language = extension_map.get(suffix, ProgrammingLanguage.PYTHON)
        
        code = SkillCode(
            filename=code_filename,
            language=language,
            content=code_content,
        )
        
        metadata = SkillMetadata(language=language, **metadata_kwargs)
        
        return cls(manifest=manifest, code=code, metadata=metadata)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "manifest": {
                "name": self.manifest.name,
                "description": self.manifest.description,
                "declared_capabilities": self.manifest.declared_capabilities,
                "declared_permissions": self.manifest.declared_permissions,
            },
            "code": {
                "filename": self.code.filename,
                "language": self.code.language.value,
                "line_count": self.code.line_count,
                "content_hash": self.code.content_hash,
            },
            "metadata": {
                "source": self.metadata.source.value,
                "category": self.metadata.category.value,
                "github_stars": self.metadata.github_stars,
                "label": self.metadata.label.value if self.metadata.label else None,
            },
            "threat_profile": self.threat_profile.to_dict() if self.threat_profile else None,
        }
    
    def get_full_context(self) -> str:
        """
        Get full context for LLM analysis including manifest and code.
        """
        return f"""# SKILL MANIFEST (SKILL.md)

{self.manifest.raw_content}

# SKILL CODE ({self.code.filename})

```{self.code.language.value}
{self.code.content}
```
"""


@dataclass
class SkillCorpus:
    """
    Collection of skills with corpus-level operations.
    """
    
    skills: List[Skill] = field(default_factory=list)
    name: str = "SkillGuard Corpus"
    version: str = "1.0.0"
    created_at: datetime = field(default_factory=datetime.now)
    
    # Statistics cache
    _stats_cache: Optional[Dict[str, Any]] = field(default=None, repr=False)
    
    def add_skill(self, skill: Skill) -> None:
        """Add a skill to the corpus, checking for duplicates."""
        if not any(s.id == skill.id for s in self.skills):
            self.skills.append(skill)
            self._stats_cache = None
    
    def remove_duplicates(self) -> int:
        """Remove duplicate skills based on content hash."""
        seen_hashes = set()
        unique_skills = []
        removed = 0
        
        for skill in self.skills:
            combined_hash = f"{skill.manifest.raw_content[:100]}_{skill.code.content_hash}"
            if combined_hash not in seen_hashes:
                seen_hashes.add(combined_hash)
                unique_skills.append(skill)
            else:
                removed += 1
        
        self.skills = unique_skills
        self._stats_cache = None
        return removed
    
    def get_statistics(self) -> Dict[str, Any]:
        """Calculate corpus statistics."""
        if self._stats_cache:
            return self._stats_cache
        
        stats = {
            "total_skills": len(self.skills),
            "categories": {},
            "languages": {},
            "sources": {},
            "labels": {},
            "avg_lines_of_code": 0,
            "total_lines_of_code": 0,
        }
        
        total_loc = 0
        
        for skill in self.skills:
            # Category distribution
            cat = skill.metadata.category.value
            stats["categories"][cat] = stats["categories"].get(cat, 0) + 1
            
            # Language distribution
            lang = skill.code.language.value
            stats["languages"][lang] = stats["languages"].get(lang, 0) + 1
            
            # Source distribution
            src = skill.metadata.source.value
            stats["sources"][src] = stats["sources"].get(src, 0) + 1
            
            # Label distribution
            if skill.metadata.label:
                lbl = skill.metadata.label.value
                stats["labels"][lbl] = stats["labels"].get(lbl, 0) + 1
            
            # Lines of code
            total_loc += skill.code.line_count
        
        stats["total_lines_of_code"] = total_loc
        stats["avg_lines_of_code"] = total_loc / len(self.skills) if self.skills else 0
        
        self._stats_cache = stats
        return stats
    
    def filter_by_category(self, category: SkillCategory) -> List[Skill]:
        """Get skills matching a specific category."""
        return [s for s in self.skills if s.metadata.category == category]
    
    def filter_by_language(self, language: ProgrammingLanguage) -> List[Skill]:
        """Get skills matching a specific language."""
        return [s for s in self.skills if s.code.language == language]
    
    def filter_by_label(self, label: LabelCategory) -> List[Skill]:
        """Get skills with a specific ground-truth label."""
        return [s for s in self.skills if s.metadata.label == label]
    
    def get_labeled_subset(self) -> List[Skill]:
        """Get all skills that have ground-truth labels."""
        return [s for s in self.skills if s.metadata.label is not None]
    
    def stratified_sample(
        self,
        n: int,
        by: str = "category",
    ) -> List[Skill]:
        """
        Get a stratified random sample of skills.
        
        Args:
            n: Total number of skills to sample
            by: Stratification dimension ("category" or "language")
        """
        import random
        
        if by == "category":
            groups = {}
            for skill in self.skills:
                key = skill.metadata.category.value
                if key not in groups:
                    groups[key] = []
                groups[key].append(skill)
        elif by == "language":
            groups = {}
            for skill in self.skills:
                key = skill.code.language.value
                if key not in groups:
                    groups[key] = []
                groups[key].append(skill)
        else:
            raise ValueError(f"Unknown stratification dimension: {by}")
        
        # Calculate samples per group
        total = len(self.skills)
        sampled = []
        
        for key, group_skills in groups.items():
            proportion = len(group_skills) / total
            group_n = max(1, int(n * proportion))
            sampled.extend(random.sample(group_skills, min(group_n, len(group_skills))))
        
        # Trim or pad to exact n
        if len(sampled) > n:
            sampled = random.sample(sampled, n)
        
        return sampled
    
    def save(self, filepath: Path) -> None:
        """Save corpus to JSON file."""
        data = {
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "statistics": self.get_statistics(),
            "skills": [s.to_dict() for s in self.skills],
        }
        filepath.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')
    
    @classmethod
    def load(cls, filepath: Path) -> "SkillCorpus":
        """Load corpus from JSON file."""
        # This would need full deserialization logic
        # For now, just create empty corpus
        return cls()
