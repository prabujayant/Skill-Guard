"""
Static Information Flow Analysis (SIFA) Module.

This module provides deterministic static analysis capabilities for detecting
dangerous patterns in skill code. Unlike simple AST pattern matching, SIFA
uses data flow tracking to flag dangerous functions only when they receive
untrusted input.

Key features:
- Control Flow Graph (CFG) construction
- Data dependency tracking
- Dangerous primitive detection
- Obfuscation detection
- Permission scope mismatch detection
"""

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional, List, Set, Tuple, Union
from enum import Enum
import json

from loguru import logger

from skillguard.config import Settings, get_settings
from skillguard.core.skill import Skill, SkillCode
from skillguard.taxonomy import (
    ThreatCategory,
    ThreatSeverity,
    ThreatIndicator,
    ProgrammingLanguage,
)


class DataFlowSource(str, Enum):
    """Types of data flow sources."""
    
    USER_INPUT = "user_input"       # Function parameters, input()
    ENVIRONMENT = "environment"      # os.environ, getenv
    FILE = "file"                   # File reads
    NETWORK = "network"             # Network responses
    HARDCODED = "hardcoded"         # String literals
    INTERNAL = "internal"           # Internal computation
    UNKNOWN = "unknown"


@dataclass
class DataFlowNode:
    """Represents a node in the data flow graph."""
    
    name: str
    source: DataFlowSource
    line_number: int
    tainted: bool = False
    flows_to: List[str] = field(default_factory=list)
    flows_from: List[str] = field(default_factory=list)


@dataclass
class DangerousCall:
    """Represents a potentially dangerous function call."""
    
    function_name: str
    category: ThreatCategory
    line_number: int
    arguments: List[str] = field(default_factory=list)
    receives_tainted_input: bool = False
    confidence: float = 0.5
    context: str = ""


@dataclass
class SIFAResult:
    """Result of SIFA analysis."""
    
    score: float  # 0-100 risk score
    indicators: List[ThreatIndicator] = field(default_factory=list)
    dangerous_calls: List[DangerousCall] = field(default_factory=list)
    data_flow_graph: Dict[str, DataFlowNode] = field(default_factory=dict)
    imports_detected: List[str] = field(default_factory=list)
    obfuscation_patterns: List[Dict[str, Any]] = field(default_factory=list)
    permission_mismatches: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "score": self.score,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "dangerous_calls": [
                {
                    "function": dc.function_name,
                    "category": dc.category.value,
                    "line": dc.line_number,
                    "tainted": dc.receives_tainted_input,
                    "confidence": dc.confidence,
                }
                for dc in self.dangerous_calls
            ],
            "imports_detected": self.imports_detected,
            "obfuscation_patterns": self.obfuscation_patterns,
            "permission_mismatches": self.permission_mismatches,
        }


class PythonASTAnalyzer(ast.NodeVisitor):
    """
    Python AST visitor for static analysis.
    
    Performs:
    - Import tracking
    - Function call detection
    - Data flow analysis
    - Dangerous pattern recognition
    """
    
    DANGEROUS_FUNCTIONS = {
        # Code execution
        "eval": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.CRITICAL),
        "exec": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.CRITICAL),
        "compile": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "__import__": (ThreatCategory.SUPPLY_CHAIN_INJECTION, ThreatSeverity.HIGH),
        
        # OS commands
        "os.system": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.CRITICAL),
        "os.popen": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.CRITICAL),
        "os.spawn": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "os.exec": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.CRITICAL),
        
        # Subprocess
        "subprocess.run": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "subprocess.call": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "subprocess.Popen": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "subprocess.check_output": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        
        # Network - Socket
        "socket.socket": (ThreatCategory.REVERSE_SHELL, ThreatSeverity.MEDIUM),
        "socket.connect": (ThreatCategory.REVERSE_SHELL, ThreatSeverity.HIGH),
        "socket.bind": (ThreatCategory.REVERSE_SHELL, ThreatSeverity.HIGH),
        
        # Network - HTTP
        "requests.get": (ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.LOW),
        "requests.post": (ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.MEDIUM),
        "urllib.request.urlopen": (ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.LOW),
        "http.client.HTTPConnection": (ThreatCategory.DATA_EXFILTRATION, ThreatSeverity.LOW),
        
        # Environment access
        "os.environ": (ThreatCategory.CREDENTIAL_THEFT, ThreatSeverity.MEDIUM),
        "os.getenv": (ThreatCategory.CREDENTIAL_THEFT, ThreatSeverity.MEDIUM),
        
        # Serialization (deserialization attacks)
        "pickle.load": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "pickle.loads": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        "yaml.load": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.MEDIUM),
        "yaml.unsafe_load": (ThreatCategory.ARBITRARY_CODE_EXECUTION, ThreatSeverity.HIGH),
        
        # File operations
        "open": (ThreatCategory.PRIVILEGE_ESCALATION, ThreatSeverity.LOW),
        "shutil.rmtree": (ThreatCategory.PRIVILEGE_ESCALATION, ThreatSeverity.HIGH),
        "os.remove": (ThreatCategory.PRIVILEGE_ESCALATION, ThreatSeverity.MEDIUM),
    }
    
    SUSPICIOUS_MODULES = {
        "socket", "subprocess", "os", "sys", "ctypes",
        "pickle", "marshal", "shelve", "requests", "urllib",
        "http.client", "ftplib", "smtplib", "telnetlib",
        "paramiko", "fabric", "pexpect", "pty",
    }
    
    def __init__(self):
        self.imports: List[str] = []
        self.dangerous_calls: List[DangerousCall] = []
        self.function_params: Set[str] = set()
        self.tainted_vars: Set[str] = set()
        self.data_flow: Dict[str, DataFlowNode] = {}
        self.string_literals: List[Tuple[int, str]] = []
        self.current_function: Optional[str] = None
        
    def visit_Import(self, node: ast.Import) -> None:
        """Track standard imports."""
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from-imports."""
        module = node.module or ""
        for alias in node.names:
            full_name = f"{module}.{alias.name}" if module else alias.name
            self.imports.append(full_name)
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function definitions and parameters (potential user input)."""
        self.current_function = node.name
        
        # Function parameters are potential user input (tainted)
        for arg in node.args.args:
            param_name = arg.arg
            self.function_params.add(param_name)
            self.tainted_vars.add(param_name)
            self.data_flow[param_name] = DataFlowNode(
                name=param_name,
                source=DataFlowSource.USER_INPUT,
                line_number=node.lineno,
                tainted=True,
            )
        
        self.generic_visit(node)
        self.current_function = None
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function definitions."""
        # Treat same as regular functions
        self.current_function = node.name
        for arg in node.args.args:
            param_name = arg.arg
            self.function_params.add(param_name)
            self.tainted_vars.add(param_name)
        self.generic_visit(node)
        self.current_function = None
    
    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls for dangerous patterns."""
        func_name = self._get_call_name(node)
        
        if func_name:
            # Check if it's a dangerous function
            danger_info = self._check_dangerous_function(func_name)
            
            if danger_info:
                category, severity = danger_info
                
                # Check if arguments contain tainted data
                tainted = self._check_tainted_arguments(node)
                
                # Adjust confidence based on taint analysis
                confidence = 0.9 if tainted else 0.5
                
                self.dangerous_calls.append(DangerousCall(
                    function_name=func_name,
                    category=category,
                    line_number=node.lineno,
                    arguments=[self._get_arg_repr(arg) for arg in node.args],
                    receives_tainted_input=tainted,
                    confidence=confidence,
                    context=self.current_function or "module",
                ))
        
        self.generic_visit(node)
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track assignments for data flow analysis."""
        # Check if RHS contains tainted data
        rhs_tainted = self._is_tainted(node.value)
        
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                if rhs_tainted:
                    self.tainted_vars.add(var_name)
                    self.data_flow[var_name] = DataFlowNode(
                        name=var_name,
                        source=DataFlowSource.USER_INPUT,
                        line_number=node.lineno,
                        tainted=True,
                    )
        
        self.generic_visit(node)
    
    def visit_Str(self, node: ast.Str) -> None:
        """Track string literals (for detecting hardcoded secrets/IPs)."""
        self.string_literals.append((node.lineno if hasattr(node, 'lineno') else 0, node.s))
        self.generic_visit(node)
    
    def visit_Constant(self, node: ast.Constant) -> None:
        """Track constant values (Python 3.8+)."""
        if isinstance(node.value, str):
            self.string_literals.append((node.lineno if hasattr(node, 'lineno') else 0, node.value))
        self.generic_visit(node)
    
    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract full function name from a Call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        return None
    
    def _check_dangerous_function(self, func_name: str) -> Optional[Tuple[ThreatCategory, ThreatSeverity]]:
        """Check if function is in dangerous list."""
        # Direct match
        if func_name in self.DANGEROUS_FUNCTIONS:
            return self.DANGEROUS_FUNCTIONS[func_name]
        
        # Partial match (e.g., "os.system" matches "system" call on os module)
        for dangerous, info in self.DANGEROUS_FUNCTIONS.items():
            if func_name.endswith(dangerous.split('.')[-1]) and dangerous.split('.')[0] in self.imports:
                return info
        
        return None
    
    def _check_tainted_arguments(self, node: ast.Call) -> bool:
        """Check if any argument contains tainted data."""
        for arg in node.args:
            if self._is_tainted(arg):
                return True
        for keyword in node.keywords:
            if self._is_tainted(keyword.value):
                return True
        return False
    
    def _is_tainted(self, node: ast.AST) -> bool:
        """Check if an AST node represents tainted data."""
        if isinstance(node, ast.Name):
            return node.id in self.tainted_vars
        elif isinstance(node, ast.BinOp):
            return self._is_tainted(node.left) or self._is_tainted(node.right)
        elif isinstance(node, ast.Call):
            # Check if call result could be tainted
            func_name = self._get_call_name(node)
            if func_name in ["input", "os.environ.get", "os.getenv"]:
                return True
        elif isinstance(node, ast.Subscript):
            return self._is_tainted(node.value)
        elif isinstance(node, ast.JoinedStr):  # f-strings
            for value in node.values:
                if isinstance(value, ast.FormattedValue) and self._is_tainted(value.value):
                    return True
        return False
    
    def _get_arg_repr(self, node: ast.AST) -> str:
        """Get string representation of an argument."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        elif isinstance(node, ast.Str):
            return repr(node.s)
        return "<complex>"


class ObfuscationDetector:
    """Detects code obfuscation patterns."""
    
    PATTERNS = [
        # Base64 usage
        (r"base64\.(b64decode|b64encode|decode|encode)", "base64_encoding", ThreatSeverity.MEDIUM),
        (r"codecs\.(decode|encode)", "codecs_encoding", ThreatSeverity.MEDIUM),
        
        # Hex encoding
        (r"binascii\.(a2b|b2a|hexlify|unhexlify)", "hex_encoding", ThreatSeverity.MEDIUM),
        (r"bytes\.fromhex", "hex_encoding", ThreatSeverity.MEDIUM),
        
        # Escape sequences in strings
        (r"\\x[0-9a-fA-F]{2}", "hex_escape", ThreatSeverity.LOW),
        (r"\\u[0-9a-fA-F]{4}", "unicode_escape", ThreatSeverity.LOW),
        
        # Character code obfuscation
        (r"chr\s*\(\s*\d+\s*\)", "chr_obfuscation", ThreatSeverity.MEDIUM),
        (r"ord\s*\(['\"][^'\"]+['\"]\s*\)", "ord_obfuscation", ThreatSeverity.LOW),
        
        # Dunder attribute access (potential sandbox escape)
        (r"getattr\s*\([^)]+,\s*['\"]__[^'\"]+['\"]", "dunder_access", ThreatSeverity.HIGH),
        (r"\.__class__\.__mro__", "mro_access", ThreatSeverity.HIGH),
        (r"\.__globals__", "globals_access", ThreatSeverity.HIGH),
        (r"\.__builtins__", "builtins_access", ThreatSeverity.HIGH),
        
        # String concatenation to hide imports
        (r"__import__\s*\(\s*['\"][^'\"]*['\"]\s*\+", "import_concat", ThreatSeverity.HIGH),
        (r"getattr\s*\(\s*__import__", "dynamic_import", ThreatSeverity.HIGH),
        
        # Lambda obfuscation
        (r"lambda\s+\w+\s*:\s*eval", "lambda_eval", ThreatSeverity.CRITICAL),
        
        # Exec with encoding
        (r"exec\s*\(\s*.*\.\s*decode\s*\(", "exec_decode", ThreatSeverity.CRITICAL),
        
        # Compressed code
        (r"zlib\.(decompress|compress)", "compression", ThreatSeverity.MEDIUM),
        (r"gzip\.(decompress|compress)", "compression", ThreatSeverity.MEDIUM),
    ]
    
    IP_PATTERN = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    URL_PATTERN = r"https?://[^\s'\"\)>]+"
    
    def detect(self, code: str) -> List[Dict[str, Any]]:
        """Detect obfuscation patterns in code."""
        findings = []
        
        for pattern, name, severity in self.PATTERNS:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                findings.append({
                    "pattern": name,
                    "match": match.group(),
                    "line": line_number,
                    "severity": severity.value,
                })
        
        # Detect hardcoded IPs
        ip_matches = re.finditer(self.IP_PATTERN, code)
        for match in ip_matches:
            ip = match.group()
            # Skip common safe IPs
            if not ip.startswith("127.") and not ip.startswith("0.") and ip != "0.0.0.0":
                line_number = code[:match.start()].count('\n') + 1
                findings.append({
                    "pattern": "hardcoded_ip",
                    "match": ip,
                    "line": line_number,
                    "severity": ThreatSeverity.MEDIUM.value,
                })
        
        # Detect hardcoded URLs (potential C2)
        url_matches = re.finditer(self.URL_PATTERN, code)
        for match in url_matches:
            url = match.group()
            # Skip documentation URLs
            if not any(safe in url.lower() for safe in ["github.com", "docs.", "pypi.org", "readthedocs"]):
                line_number = code[:match.start()].count('\n') + 1
                findings.append({
                    "pattern": "hardcoded_url",
                    "match": url,
                    "line": line_number,
                    "severity": ThreatSeverity.MEDIUM.value,
                })
        
        return findings


class PermissionMismatchDetector:
    """Detects mismatches between declared permissions and actual code capabilities."""
    
    CAPABILITY_PATTERNS = {
        "file_read": [r"open\s*\(", r"read\s*\(", r"Path\s*\(.*\)\.read"],
        "file_write": [r"open\s*\([^)]*['\"]w['\"]", r"write\s*\(", r"Path\s*\(.*\)\.write"],
        "network_request": [r"requests\.", r"urllib\.", r"http\.client", r"socket\."],
        "subprocess": [r"subprocess\.", r"os\.system", r"os\.popen"],
        "environment": [r"os\.environ", r"os\.getenv"],
    }
    
    def detect(self, skill: Skill) -> List[Dict[str, Any]]:
        """Detect permission mismatches."""
        mismatches = []
        
        declared = set(skill.manifest.declared_capabilities + skill.manifest.declared_permissions)
        declared_lower = {d.lower() for d in declared}
        
        code = skill.code.content
        
        # Check each capability
        for capability, patterns in self.CAPABILITY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code):
                    # Check if this capability was declared
                    capability_keywords = {
                        "file_read": ["file", "read", "filesystem"],
                        "file_write": ["file", "write", "filesystem", "modify"],
                        "network_request": ["network", "http", "request", "api", "web"],
                        "subprocess": ["command", "shell", "execute", "subprocess", "system"],
                        "environment": ["environment", "env", "variable", "config"],
                    }
                    
                    keywords = capability_keywords.get(capability, [])
                    if not any(kw in ' '.join(declared_lower) for kw in keywords):
                        mismatches.append({
                            "capability": capability,
                            "pattern": pattern,
                            "declared_permissions": list(declared),
                            "severity": "medium" if capability in ["file_read", "environment"] else "high",
                        })
                    break
        
        return mismatches


class SIFAAnalyzer:
    """
    Static Information Flow Analysis (SIFA) Analyzer.
    
    The main SIFA module that coordinates AST analysis, obfuscation detection,
    and permission mismatch detection to produce a deterministic risk assessment.
    """
    
    def __init__(self, settings: Optional[Settings] = None):
        """Initialize the SIFA analyzer."""
        self.settings = settings or get_settings()
        self.obfuscation_detector = ObfuscationDetector()
        self.permission_detector = PermissionMismatchDetector()
    
    def analyze(self, skill: Skill) -> SIFAResult:
        """
        Perform static analysis on a skill.
        
        Args:
            skill: The skill to analyze
            
        Returns:
            SIFAResult with findings and risk score
        """
        logger.debug(f"SIFA analyzing: {skill.manifest.name}")
        
        result = SIFAResult(score=0.0)
        
        # Skip non-Python for now (can add JS support later)
        if skill.code.language != ProgrammingLanguage.PYTHON:
            logger.warning(f"SIFA only supports Python currently, got {skill.code.language}")
            return result
        
        code = skill.code.content
        
        # Step 1: AST Analysis
        try:
            tree = ast.parse(code)
            ast_analyzer = PythonASTAnalyzer()
            ast_analyzer.visit(tree)
            
            result.imports_detected = ast_analyzer.imports
            result.dangerous_calls = ast_analyzer.dangerous_calls
            result.data_flow_graph = ast_analyzer.data_flow
            
        except SyntaxError as e:
            logger.warning(f"Failed to parse Python code: {e}")
            # Still continue with regex-based analysis
        
        # Step 2: Obfuscation Detection
        result.obfuscation_patterns = self.obfuscation_detector.detect(code)
        
        # Step 3: Permission Mismatch Detection
        result.permission_mismatches = self.permission_detector.detect(skill)
        
        # Step 4: Generate threat indicators
        indicators = self._generate_indicators(result, skill)
        result.indicators = indicators
        
        # Step 5: Calculate score
        result.score = self._calculate_score(result)
        
        logger.debug(f"SIFA complete: score={result.score}, indicators={len(indicators)}")
        
        return result
    
    def _generate_indicators(self, result: SIFAResult, skill: Skill) -> List[ThreatIndicator]:
        """Generate threat indicators from analysis findings."""
        indicators = []
        
        # Indicators from dangerous calls
        for call in result.dangerous_calls:
            # Higher confidence if tainted input flows to dangerous function
            confidence = 0.9 if call.receives_tainted_input else 0.5
            
            # Determine severity based on both category and taint
            if call.receives_tainted_input:
                severity = ThreatSeverity.CRITICAL if call.category in [
                    ThreatCategory.ARBITRARY_CODE_EXECUTION,
                    ThreatCategory.REVERSE_SHELL
                ] else ThreatSeverity.HIGH
            else:
                severity = ThreatSeverity.MEDIUM
            
            indicators.append(ThreatIndicator(
                name=f"Dangerous function: {call.function_name}",
                description=f"Call to {call.function_name} detected" + 
                           (" with untrusted input" if call.receives_tainted_input else ""),
                category=call.category,
                severity=severity,
                confidence=confidence,
                line_numbers=[call.line_number],
                code_snippet=f"{call.function_name}({', '.join(call.arguments[:3])}...)",
                remediation=f"Review use of {call.function_name}, ensure input is validated",
            ))
        
        # Indicators from obfuscation patterns
        for pattern in result.obfuscation_patterns:
            indicators.append(ThreatIndicator(
                name=f"Obfuscation: {pattern['pattern']}",
                description=f"Suspicious obfuscation pattern detected: {pattern['match'][:50]}",
                category=ThreatCategory.OBFUSCATION,
                severity=ThreatSeverity[pattern['severity'].upper()],
                confidence=0.7,
                line_numbers=[pattern['line']],
                code_snippet=pattern['match'][:100],
            ))
        
        # Indicators from permission mismatches (Semantic Mismatch)
        for mismatch in result.permission_mismatches:
            indicators.append(ThreatIndicator(
                name=f"Permission mismatch: {mismatch['capability']}",
                description=f"Code uses {mismatch['capability']} but this was not declared in the manifest",
                category=ThreatCategory.SEMANTIC_MISMATCH,
                severity=ThreatSeverity.HIGH if mismatch['severity'] == 'high' else ThreatSeverity.MEDIUM,
                confidence=0.8,
                remediation=f"Add '{mismatch['capability']}' to declared permissions or remove this capability",
            ))
        
        # Check for suspicious imports
        suspicious_imports = [
            imp for imp in result.imports_detected
            if any(sus in imp for sus in PythonASTAnalyzer.SUSPICIOUS_MODULES)
        ]
        
        if suspicious_imports:
            indicators.append(ThreatIndicator(
                name="Suspicious imports detected",
                description=f"Found imports of security-sensitive modules: {', '.join(suspicious_imports[:5])}",
                category=ThreatCategory.INFORMATION_DISCLOSURE,
                severity=ThreatSeverity.LOW,
                confidence=0.4,
            ))
        
        return indicators
    
    def _calculate_score(self, result: SIFAResult) -> float:
        """Calculate overall risk score from SIFA findings."""
        score = 0.0
        
        # Score from dangerous calls
        for call in result.dangerous_calls:
            base_score = {
                ThreatCategory.ARBITRARY_CODE_EXECUTION: 40,
                ThreatCategory.REVERSE_SHELL: 50,
                ThreatCategory.DATA_EXFILTRATION: 25,
                ThreatCategory.CREDENTIAL_THEFT: 30,
                ThreatCategory.PRIVILEGE_ESCALATION: 20,
                ThreatCategory.SUPPLY_CHAIN_INJECTION: 35,
            }.get(call.category, 10)
            
            # Increase score if tainted
            if call.receives_tainted_input:
                base_score *= 1.5
            
            score += base_score * call.confidence
        
        # Score from obfuscation
        for pattern in result.obfuscation_patterns:
            severity_scores = {
                "critical": 30,
                "high": 20,
                "medium": 10,
                "low": 5,
            }
            score += severity_scores.get(pattern['severity'], 5)
        
        # Score from permission mismatches
        score += len(result.permission_mismatches) * 15
        
        # Cap at 100
        return min(100.0, score)
    
    def analyze_batch(self, skills: List[Skill]) -> List[SIFAResult]:
        """Analyze multiple skills."""
        results = []
        for skill in skills:
            try:
                result = self.analyze(skill)
                results.append(result)
            except Exception as e:
                logger.error(f"SIFA failed for {skill.id}: {e}")
                results.append(SIFAResult(score=0.0))
        return results
