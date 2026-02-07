"""
Threat Taxonomy for SkillGuard - Aligned with Google's Secure AI Framework (SAIF).

This module defines the threat categories, severity levels, and classification
schemes used by SkillGuard to categorize detected security issues.
"""

from enum import Enum, auto
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


class ThreatCategory(str, Enum):
    """
    Main threat categories aligned with Google SAIF.
    
    These categories represent the primary classification of security threats
    that can be detected in LLM tool definitions.
    """
    
    # Category A: Arbitrary Code Execution (ACE)
    ARBITRARY_CODE_EXECUTION = "arbitrary_code_execution"
    
    # Category B: Data Exfiltration
    DATA_EXFILTRATION = "data_exfiltration"
    
    # Category C: Reverse Shells
    REVERSE_SHELL = "reverse_shell"
    
    # Category D: Privilege Escalation
    PRIVILEGE_ESCALATION = "privilege_escalation"
    
    # Category E: Semantic Mismatch (The Trojan)
    SEMANTIC_MISMATCH = "semantic_mismatch"
    
    # Category F: Supply Chain Injection
    SUPPLY_CHAIN_INJECTION = "supply_chain_injection"
    
    # Additional categories
    CREDENTIAL_THEFT = "credential_theft"
    DENIAL_OF_SERVICE = "denial_of_service"
    INFORMATION_DISCLOSURE = "information_disclosure"
    OBFUSCATION = "obfuscation"
    
    # Classification result
    BENIGN = "benign"
    UNKNOWN = "unknown"


class ThreatSeverity(str, Enum):
    """Severity levels for detected threats."""
    
    CRITICAL = "critical"   # Immediate exploitation risk
    HIGH = "high"           # Significant security impact
    MEDIUM = "medium"       # Moderate risk, requires attention
    LOW = "low"             # Minor concern
    INFO = "info"           # Informational finding
    NONE = "none"           # No threat detected


class SkillCategory(str, Enum):
    """Categories for skill classification."""
    
    CODING = "coding"
    DATA_ANALYSIS = "data_analysis"
    SEARCH = "search"
    FILE_IO = "file_io"
    NETWORK_SERVICES = "network_services"
    DATABASE = "database"
    AUTHENTICATION = "authentication"
    MESSAGING = "messaging"
    AUTOMATION = "automation"
    UTILITY = "utility"
    MATH_CALCULATION = "math_calculation"
    WEB_SCRAPING = "web_scraping"
    OTHER = "other"


class ProgrammingLanguage(str, Enum):
    """Supported programming languages for skill analysis."""
    
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    NODEJS = "nodejs"
    BASH = "bash"
    GO = "go"
    RUST = "rust"
    UNKNOWN = "unknown"


class LabelCategory(str, Enum):
    """Ground-truth labeling categories for manual annotation."""
    
    BENIGN = "benign"         # Code matches declared functionality
    SUSPICIOUS = "suspicious"  # Minor red flags but no clear malicious intent
    MALICIOUS = "malicious"   # Clear security violations


@dataclass
class ThreatIndicator:
    """
    Represents a specific threat indicator found during analysis.
    """
    
    name: str
    description: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float  # 0.0 to 1.0
    line_numbers: List[int] = field(default_factory=list)
    code_snippet: Optional[str] = None
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "line_numbers": self.line_numbers,
            "code_snippet": self.code_snippet,
            "remediation": self.remediation,
            "references": self.references,
        }


@dataclass
class ThreatProfile:
    """
    Complete threat profile for a skill, aggregating all detected indicators.
    """
    
    skill_id: str
    overall_severity: ThreatSeverity
    risk_score: float  # 0 to 100
    indicators: List[ThreatIndicator] = field(default_factory=list)
    categories_detected: List[ThreatCategory] = field(default_factory=list)
    sifa_score: float = 0.0
    llm_score: float = 0.0
    popularity_penalty: float = 0.0
    final_label: LabelCategory = LabelCategory.BENIGN
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """Add a threat indicator to the profile."""
        self.indicators.append(indicator)
        if indicator.category not in self.categories_detected:
            self.categories_detected.append(indicator.category)
    
    def get_risk_level(self) -> str:
        """Get human-readable risk level."""
        if self.risk_score <= 20:
            return "BENIGN"
        elif self.risk_score <= 50:
            return "SUSPICIOUS"
        elif self.risk_score <= 80:
            return "HIGH-RISK"
        else:
            return "MALICIOUS"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "skill_id": self.skill_id,
            "overall_severity": self.overall_severity.value,
            "risk_score": self.risk_score,
            "risk_level": self.get_risk_level(),
            "indicators": [ind.to_dict() for ind in self.indicators],
            "categories_detected": [cat.value for cat in self.categories_detected],
            "sifa_score": self.sifa_score,
            "llm_score": self.llm_score,
            "popularity_penalty": self.popularity_penalty,
            "final_label": self.final_label.value,
            "analysis_metadata": self.analysis_metadata,
        }


# Threat category descriptions for documentation and reporting
THREAT_DESCRIPTIONS: Dict[ThreatCategory, Dict[str, str]] = {
    ThreatCategory.ARBITRARY_CODE_EXECUTION: {
        "name": "Arbitrary Code Execution (ACE)",
        "description": (
            "Unsafe use of subprocess, eval, exec, or OS commands with unchecked user input. "
            "This allows attackers to execute arbitrary system commands."
        ),
        "indicators": "subprocess.run, os.system, eval, exec with user-controlled arguments",
        "impact": "Complete system compromise, data destruction, malware installation",
        "saif_mapping": "Execution Integrity",
    },
    ThreatCategory.DATA_EXFILTRATION: {
        "name": "Data Exfiltration",
        "description": (
            "Code sending sensitive data to hardcoded C2 servers or external endpoints. "
            "This includes environment variables, file contents, and memory dumps."
        ),
        "indicators": "HTTP requests to external IPs, encoded data transmission",
        "impact": "API key theft, credential exposure, sensitive data leakage",
        "saif_mapping": "Data Protection",
    },
    ThreatCategory.REVERSE_SHELL: {
        "name": "Reverse Shell",
        "description": (
            "Direct socket connections initiating remote command execution. "
            "Allows attackers to gain interactive shell access."
        ),
        "indicators": "socket.connect(), hardcoded IP:port pairs, bind shells",
        "impact": "Complete remote access, persistent backdoor",
        "saif_mapping": "Network Security",
    },
    ThreatCategory.PRIVILEGE_ESCALATION: {
        "name": "Privilege Escalation",
        "description": (
            "Skills escalating permissions beyond their declared scope. "
            "For example, a read-only tool modifying system files."
        ),
        "indicators": "File operations outside declared paths, sudo usage",
        "impact": "Unauthorized access to restricted resources",
        "saif_mapping": "Access Control",
    },
    ThreatCategory.SEMANTIC_MISMATCH: {
        "name": "Semantic Mismatch (Trojan)",
        "description": (
            "Declared functionality contradicts actual capabilities. "
            "The SKILL.md description doesn't match what the code actually does."
        ),
        "indicators": "Calculator makes network requests, utility writes files",
        "impact": "Deceptive behavior, trust violation",
        "saif_mapping": "Trust and Verification",
    },
    ThreatCategory.SUPPLY_CHAIN_INJECTION: {
        "name": "Supply Chain Injection",
        "description": (
            "Hidden imports or obfuscated code that loads malicious payloads at runtime. "
            "Uses encoding or string manipulation to hide actual imports."
        ),
        "indicators": "base64 encoding, hex encoding, Unicode escape sequences",
        "impact": "Runtime payload execution, delayed exploitation",
        "saif_mapping": "Supply Chain Security",
    },
    ThreatCategory.CREDENTIAL_THEFT: {
        "name": "Credential Theft",
        "description": (
            "Code specifically designed to extract and transmit authentication credentials."
        ),
        "indicators": "Accessing .env files, password/token extraction patterns",
        "impact": "Account compromise, lateral movement",
        "saif_mapping": "Identity and Access Management",
    },
    ThreatCategory.OBFUSCATION: {
        "name": "Code Obfuscation",
        "description": (
            "Use of encoding, compression, or other techniques to hide malicious code."
        ),
        "indicators": "base64, hex encoding, string concatenation for imports",
        "impact": "Evasion of security tools, hidden malicious behavior",
        "saif_mapping": "Detection and Response",
    },
}


def get_severity_score(severity: ThreatSeverity) -> int:
    """Convert severity enum to numeric score."""
    mapping = {
        ThreatSeverity.CRITICAL: 100,
        ThreatSeverity.HIGH: 80,
        ThreatSeverity.MEDIUM: 50,
        ThreatSeverity.LOW: 20,
        ThreatSeverity.INFO: 5,
        ThreatSeverity.NONE: 0,
    }
    return mapping.get(severity, 0)


def get_category_severity(category: ThreatCategory) -> ThreatSeverity:
    """Get default severity for a threat category."""
    severity_mapping = {
        ThreatCategory.REVERSE_SHELL: ThreatSeverity.CRITICAL,
        ThreatCategory.ARBITRARY_CODE_EXECUTION: ThreatSeverity.CRITICAL,
        ThreatCategory.DATA_EXFILTRATION: ThreatSeverity.HIGH,
        ThreatCategory.CREDENTIAL_THEFT: ThreatSeverity.HIGH,
        ThreatCategory.PRIVILEGE_ESCALATION: ThreatSeverity.HIGH,
        ThreatCategory.SEMANTIC_MISMATCH: ThreatSeverity.HIGH,
        ThreatCategory.SUPPLY_CHAIN_INJECTION: ThreatSeverity.HIGH,
        ThreatCategory.OBFUSCATION: ThreatSeverity.MEDIUM,
        ThreatCategory.DENIAL_OF_SERVICE: ThreatSeverity.MEDIUM,
        ThreatCategory.INFORMATION_DISCLOSURE: ThreatSeverity.MEDIUM,
        ThreatCategory.BENIGN: ThreatSeverity.NONE,
        ThreatCategory.UNKNOWN: ThreatSeverity.LOW,
    }
    return severity_mapping.get(category, ThreatSeverity.MEDIUM)
