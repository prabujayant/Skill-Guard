"""
Semantic Feature Extraction for SkillGuard ML Pipeline.

Extracts NLP-based semantic features using embeddings and capability analysis.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional, Tuple
import numpy as np

from loguru import logger


@dataclass
class SemanticFeatures:
    """Container for semantic features."""
    
    # Embeddings (768-dim for transformer models)
    description_embedding: Optional[np.ndarray] = None
    code_embedding: Optional[np.ndarray] = None
    
    # Alignment score
    embedding_cosine_sim: float = 0.0
    
    # Capability analysis
    declared_capabilities: Set[str] = field(default_factory=set)
    actual_capabilities: Set[str] = field(default_factory=set)
    capability_mismatch_count: int = 0
    
    # Topic features
    description_topics: List[float] = field(default_factory=list)
    code_topics: List[float] = field(default_factory=list)
    
    # Text statistics
    description_length: int = 0
    description_word_count: int = 0
    has_permissions_section: bool = False
    has_capabilities_section: bool = False
    
    def to_scalar_vector(self) -> np.ndarray:
        """Get scalar features only (without embeddings)."""
        return np.array([
            self.embedding_cosine_sim,
            self.capability_mismatch_count,
            self.description_length,
            self.description_word_count,
            int(self.has_permissions_section),
            int(self.has_capabilities_section),
            len(self.declared_capabilities),
            len(self.actual_capabilities),
        ], dtype=np.float32)
    
    @staticmethod
    def scalar_feature_names() -> List[str]:
        """Get names of scalar features."""
        return [
            "embedding_cosine_sim",
            "capability_mismatch_count",
            "description_length",
            "description_word_count",
            "has_permissions_section",
            "has_capabilities_section",
            "num_declared_capabilities",
            "num_actual_capabilities",
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "embedding_cosine_sim": self.embedding_cosine_sim,
            "capability_mismatch_count": self.capability_mismatch_count,
            "declared_capabilities": list(self.declared_capabilities),
            "actual_capabilities": list(self.actual_capabilities),
            "description_length": self.description_length,
            "has_permissions_section": self.has_permissions_section,
        }


class SemanticFeatureExtractor:
    """
    Extracts semantic features using NLP techniques.
    
    Features include:
    1. Text embeddings (description and code)
    2. Semantic alignment score
    3. Capability mismatch detection
    """
    
    # Capability keywords
    CAPABILITY_KEYWORDS = {
        'network': {'network', 'http', 'https', 'request', 'api', 'url', 'web', 'download', 'upload', 'fetch'},
        'file_read': {'read', 'load', 'open', 'file', 'parse', 'import'},
        'file_write': {'write', 'save', 'export', 'create', 'modify', 'update', 'delete'},
        'execute': {'execute', 'run', 'shell', 'command', 'system', 'process', 'subprocess'},
        'database': {'database', 'sql', 'query', 'db', 'postgres', 'mysql', 'mongodb'},
        'crypto': {'encrypt', 'decrypt', 'hash', 'sign', 'verify', 'key', 'password'},
        'email': {'email', 'mail', 'smtp', 'send'},
        'auth': {'auth', 'login', 'token', 'oauth', 'credential'},
    }
    
    # Code patterns indicating capabilities
    CODE_CAPABILITY_PATTERNS = {
        'network': [r'requests\.', r'urllib', r'http\.client', r'socket\.', r'aiohttp'],
        'file_read': [r'open\s*\(', r'\.read\s*\(', r'Path\s*\(.*\)\.read'],
        'file_write': [r'\.write\s*\(', r'\.save\s*\(', r'Path\s*\(.*\)\.write'],
        'execute': [r'subprocess\.', r'os\.system', r'os\.popen', r'eval\s*\(', r'exec\s*\('],
        'database': [r'sqlite3', r'psycopg', r'pymysql', r'sqlalchemy'],
        'crypto': [r'hashlib', r'cryptography', r'Crypto\.', r'bcrypt'],
        'email': [r'smtplib', r'email\.', r'sendmail'],
        'auth': [r'oauth', r'jwt', r'token', r'Bearer'],
    }
    
    def __init__(self, use_embeddings: bool = True):
        """
        Initialize semantic feature extractor.
        
        Args:
            use_embeddings: Whether to compute embeddings (requires sentence-transformers)
        """
        self.use_embeddings = use_embeddings
        self._embedding_model = None
        self._code_model = None
    
    @property
    def embedding_model(self):
        """Lazy-load embedding model."""
        if self._embedding_model is None and self.use_embeddings:
            try:
                from sentence_transformers import SentenceTransformer
                self._embedding_model = SentenceTransformer('BAAI/bge-small-en-v1.5')
                logger.info("Loaded BGE embedding model")
            except ImportError:
                logger.warning("sentence-transformers not installed, embeddings disabled")
                self.use_embeddings = False
        return self._embedding_model
    
    def extract(self, description: str, code: str) -> SemanticFeatures:
        """
        Extract semantic features from description and code.
        
        Args:
            description: SKILL.md content or description text
            code: Source code string
            
        Returns:
            SemanticFeatures dataclass
        """
        features = SemanticFeatures()
        
        # Text statistics
        features.description_length = len(description)
        features.description_word_count = len(description.split())
        features.has_permissions_section = 'permission' in description.lower()
        features.has_capabilities_section = 'capabilit' in description.lower()
        
        # Capability analysis
        features.declared_capabilities = self._extract_declared_capabilities(description)
        features.actual_capabilities = self._extract_actual_capabilities(code)
        
        # Calculate mismatch (capabilities in code but not declared)
        undeclared = features.actual_capabilities - features.declared_capabilities
        features.capability_mismatch_count = len(undeclared)
        
        # Compute embeddings if available
        if self.use_embeddings and self.embedding_model:
            try:
                features.description_embedding = self.embedding_model.encode(
                    description[:512],  # Truncate
                    normalize_embeddings=True
                )
                
                # For code, use docstrings and function signatures
                code_summary = self._extract_code_summary(code)
                features.code_embedding = self.embedding_model.encode(
                    code_summary[:512],
                    normalize_embeddings=True
                )
                
                # Cosine similarity (embeddings are normalized)
                features.embedding_cosine_sim = float(np.dot(
                    features.description_embedding,
                    features.code_embedding
                ))
            except Exception as e:
                logger.warning(f"Embedding extraction failed: {e}")
        
        return features
    
    def _extract_declared_capabilities(self, description: str) -> Set[str]:
        """Extract capabilities mentioned in description."""
        desc_lower = description.lower()
        capabilities = set()
        
        for cap_name, keywords in self.CAPABILITY_KEYWORDS.items():
            if any(kw in desc_lower for kw in keywords):
                capabilities.add(cap_name)
        
        return capabilities
    
    def _extract_actual_capabilities(self, code: str) -> Set[str]:
        """Extract capabilities from code patterns."""
        capabilities = set()
        
        for cap_name, patterns in self.CODE_CAPABILITY_PATTERNS.items():
            if any(re.search(pattern, code) for pattern in patterns):
                capabilities.add(cap_name)
        
        return capabilities
    
    def _extract_code_summary(self, code: str) -> str:
        """Extract a text summary of code for embedding."""
        # Get docstrings and function names
        summary_parts = []
        
        # Try to parse AST
        try:
            import ast
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                # Get function docstrings
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    summary_parts.append(f"function {node.name}")
                    docstring = ast.get_docstring(node)
                    if docstring:
                        summary_parts.append(docstring[:100])
                
                # Get class docstrings
                elif isinstance(node, ast.ClassDef):
                    summary_parts.append(f"class {node.name}")
                    docstring = ast.get_docstring(node)
                    if docstring:
                        summary_parts.append(docstring[:100])
        except SyntaxError:
            # Fall back to regex
            func_pattern = re.compile(r'def\s+(\w+)\s*\(')
            for match in func_pattern.finditer(code):
                summary_parts.append(f"function {match.group(1)}")
        
        if summary_parts:
            return ' '.join(summary_parts)
        else:
            # Last resort: use first 200 chars of code
            return code[:200]
    
    def compute_batch_embeddings(
        self,
        descriptions: List[str],
        codes: List[str]
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Compute embeddings for a batch of skills.
        
        Returns:
            Tuple of (description_embeddings, code_embeddings)
        """
        if not self.use_embeddings or not self.embedding_model:
            return None, None
        
        # Truncate and prepare
        desc_texts = [d[:512] for d in descriptions]
        code_texts = [self._extract_code_summary(c)[:512] for c in codes]
        
        desc_embs = self.embedding_model.encode(desc_texts, normalize_embeddings=True)
        code_embs = self.embedding_model.encode(code_texts, normalize_embeddings=True)
        
        return desc_embs, code_embs
