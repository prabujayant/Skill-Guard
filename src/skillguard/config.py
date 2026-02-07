"""
Configuration management for SkillGuard.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class LLMConfig(BaseModel):
    """Configuration for LLM providers."""
    
    openai_api_key: Optional[SecretStr] = Field(
        default_factory=lambda: SecretStr(os.getenv("OPENAI_API_KEY", ""))
    )
    anthropic_api_key: Optional[SecretStr] = Field(
        default_factory=lambda: SecretStr(os.getenv("ANTHROPIC_API_KEY", ""))
    )
    openai_model: str = "gpt-4o"
    anthropic_model: str = "claude-3-5-sonnet-20241022"
    temperature: float = 0.0
    max_tokens: int = 4096
    timeout: int = 60
    retry_attempts: int = 3
    

class SIFAConfig(BaseModel):
    """Configuration for Static Information Flow Analysis."""
    
    # Dangerous function patterns by category
    dangerous_functions: Dict[str, List[str]] = Field(default_factory=lambda: {
        "code_execution": [
            "eval", "exec", "compile", "execfile",
            "subprocess.run", "subprocess.call", "subprocess.Popen",
            "os.system", "os.popen", "os.spawn", "os.spawnl", "os.spawnle",
            "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve",
            "os.spawnvp", "os.spawnvpe", "os.execl", "os.execle",
            "os.execlp", "os.execlpe", "os.execv", "os.execve",
            "os.execvp", "os.execvpe",
            "__import__", "importlib.import_module",
        ],
        "network": [
            "socket.socket", "socket.connect", "socket.bind",
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "urllib.request.urlopen", "urllib.request.urlretrieve",
            "http.client.HTTPConnection", "http.client.HTTPSConnection",
            "aiohttp.ClientSession", "httpx.Client", "httpx.AsyncClient",
        ],
        "file_system": [
            "open", "os.open", "os.remove", "os.unlink", "os.rmdir",
            "os.rename", "os.makedirs", "os.mkdir",
            "shutil.copy", "shutil.copy2", "shutil.copytree",
            "shutil.move", "shutil.rmtree",
            "pathlib.Path.write_text", "pathlib.Path.write_bytes",
            "pathlib.Path.unlink", "pathlib.Path.rmdir",
        ],
        "environment": [
            "os.environ", "os.getenv", "os.putenv",
            "os.environ.get", "os.environ.setdefault",
        ],
        "serialization": [
            "pickle.load", "pickle.loads", "pickle.dump", "pickle.dumps",
            "marshal.load", "marshal.loads",
            "yaml.load", "yaml.unsafe_load",
        ],
    })
    
    # Suspicious patterns (regex)
    suspicious_patterns: List[str] = Field(default_factory=lambda: [
        r"base64\.(b64decode|b64encode|decode)",
        r"codecs\.(decode|encode)",
        r"binascii\.(a2b|b2a)",
        r"\\x[0-9a-fA-F]{2}",  # Hex escape sequences
        r"\\u[0-9a-fA-F]{4}",  # Unicode escape sequences
        r"chr\(\d+\)",  # Character code obfuscation
        r"getattr\(.+,\s*['\"]__",  # Dunder attribute access
    ])
    
    # Sensitive file paths
    sensitive_paths: List[str] = Field(default_factory=lambda: [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "~/.ssh", "~/.aws", "~/.config",
        ".env", ".git/config", ".gitconfig",
        "id_rsa", "id_ed25519", "authorized_keys",
    ])
    
    # Weight for scoring
    weight: float = 0.4


class HybridScoringConfig(BaseModel):
    """Configuration for hybrid scoring."""
    
    sifa_weight: float = 0.4
    llm_weight: float = 0.4
    popularity_weight: float = 0.2
    
    # Risk thresholds
    thresholds: Dict[str, int] = Field(default_factory=lambda: {
        "benign": 20,
        "suspicious": 50,
        "high_risk": 80,
        "malicious": 100,
    })


class DatabaseConfig(BaseModel):
    """Database configuration."""
    
    url: str = Field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL",
            "sqlite:///./skillguard.db"
        )
    )
    echo: bool = False


class Settings(BaseSettings):
    """Main application settings."""
    
    # Project paths
    project_root: Path = Field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent.parent / "data")
    output_dir: Path = Field(default_factory=lambda: Path(__file__).parent.parent.parent / "output")
    
    # Sub-configurations
    llm: LLMConfig = Field(default_factory=LLMConfig)
    sifa: SIFAConfig = Field(default_factory=SIFAConfig)
    hybrid: HybridScoringConfig = Field(default_factory=HybridScoringConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # GitHub scraping
    github_token: Optional[str] = Field(default_factory=lambda: os.getenv("GITHUB_TOKEN"))
    github_rate_limit: int = 30  # Requests per minute
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
    # Concurrency
    max_workers: int = 4
    batch_size: int = 100
    
    class Config:
        env_prefix = "SKILLGUARD_"
        env_file = ".env"
        env_file_encoding = "utf-8"


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get the global settings instance."""
    return settings


def update_settings(**kwargs: Any) -> Settings:
    """Update settings with new values."""
    global settings
    settings = Settings(**kwargs)
    return settings
