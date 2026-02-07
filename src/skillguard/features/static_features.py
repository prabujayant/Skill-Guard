"""
Static Feature Extraction for SkillGuard ML Pipeline.

Extracts code-level features through static analysis for ML classification.
"""

import ast
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional
import numpy as np

from loguru import logger


@dataclass
class StaticFeatures:
    """Container for all static code features."""
    
    # Structural features
    num_functions: int = 0
    num_classes: int = 0
    num_imports: int = 0
    lines_of_code: int = 0
    cyclomatic_complexity: float = 0.0
    max_nesting_depth: int = 0
    
    # Dangerous primitive counts
    eval_calls: int = 0
    exec_calls: int = 0
    subprocess_calls: int = 0
    os_system_calls: int = 0
    network_calls: int = 0
    socket_calls: int = 0
    file_reads: int = 0
    file_writes: int = 0
    env_access: int = 0
    
    # Data flow features
    user_input_to_eval: bool = False
    user_input_to_subprocess: bool = False
    user_input_to_network: bool = False
    
    # Hardcoded suspicious patterns
    hardcoded_ips: int = 0
    external_urls: int = 0
    base64_strings: int = 0
    hex_strings: int = 0
    
    # Obfuscation indicators
    dynamic_imports: int = 0
    getattr_calls: int = 0
    compile_calls: int = 0
    chr_ord_usage: int = 0
    
    # Permission indicators
    pickle_usage: int = 0
    yaml_unsafe: int = 0
    marshal_usage: int = 0
    
    def to_vector(self) -> np.ndarray:
        """Convert features to numpy vector for ML models."""
        return np.array([
            self.num_functions,
            self.num_classes,
            self.num_imports,
            self.lines_of_code,
            self.cyclomatic_complexity,
            self.max_nesting_depth,
            self.eval_calls,
            self.exec_calls,
            self.subprocess_calls,
            self.os_system_calls,
            self.network_calls,
            self.socket_calls,
            self.file_reads,
            self.file_writes,
            self.env_access,
            int(self.user_input_to_eval),
            int(self.user_input_to_subprocess),
            int(self.user_input_to_network),
            self.hardcoded_ips,
            self.external_urls,
            self.base64_strings,
            self.hex_strings,
            self.dynamic_imports,
            self.getattr_calls,
            self.compile_calls,
            self.chr_ord_usage,
            self.pickle_usage,
            self.yaml_unsafe,
            self.marshal_usage,
        ], dtype=np.float32)
    
    @staticmethod
    def feature_names() -> List[str]:
        """Get feature names for interpretability."""
        return [
            "num_functions", "num_classes", "num_imports", "lines_of_code",
            "cyclomatic_complexity", "max_nesting_depth",
            "eval_calls", "exec_calls", "subprocess_calls", "os_system_calls",
            "network_calls", "socket_calls", "file_reads", "file_writes", "env_access",
            "user_input_to_eval", "user_input_to_subprocess", "user_input_to_network",
            "hardcoded_ips", "external_urls", "base64_strings", "hex_strings",
            "dynamic_imports", "getattr_calls", "compile_calls", "chr_ord_usage",
            "pickle_usage", "yaml_unsafe", "marshal_usage",
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {name: val for name, val in zip(self.feature_names(), self.to_vector())}


class StaticFeatureExtractor:
    """
    Extracts static code features for ML classification.
    
    Features are designed to capture:
    1. Code structure (complexity, size)
    2. Dangerous API usage
    3. Data flow patterns
    4. Obfuscation indicators
    """
    
    # Regex patterns
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    URL_PATTERN = re.compile(r'https?://[^\s\'">\)]+')
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    HEX_PATTERN = re.compile(r'(?:0x[0-9a-fA-F]{4,}|\\x[0-9a-fA-F]{2})')
    
    # Dangerous function sets
    EVAL_FUNCS = {'eval', 'exec', 'execfile'}
    SUBPROCESS_FUNCS = {'subprocess.run', 'subprocess.call', 'subprocess.Popen', 
                        'subprocess.check_output', 'subprocess.check_call'}
    OS_SYSTEM_FUNCS = {'os.system', 'os.popen', 'os.spawn', 'os.exec'}
    NETWORK_FUNCS = {'requests.get', 'requests.post', 'requests.put', 'requests.delete',
                     'urllib.request.urlopen', 'httpx.get', 'httpx.post', 'aiohttp'}
    SOCKET_FUNCS = {'socket.socket', 'socket.connect', 'socket.bind', 'socket.listen'}
    FILE_READ_FUNCS = {'open', 'read', 'readline', 'readlines'}
    FILE_WRITE_FUNCS = {'write', 'writelines'}
    ENV_FUNCS = {'os.environ', 'os.getenv', 'os.environ.get'}
    
    def __init__(self):
        self._ast_visitor = None
    
    def extract(self, code: str) -> StaticFeatures:
        """
        Extract all static features from code.
        
        Args:
            code: Python source code string
            
        Returns:
            StaticFeatures dataclass with all extracted features
        """
        features = StaticFeatures()
        
        # Basic metrics
        features.lines_of_code = len(code.splitlines())
        
        # Try AST-based analysis
        try:
            tree = ast.parse(code)
            self._extract_ast_features(tree, features, code)
        except SyntaxError as e:
            logger.warning(f"Failed to parse code: {e}")
            # Fall back to regex-based analysis
        
        # Regex-based pattern detection (always run)
        self._extract_pattern_features(code, features)
        
        return features
    
    def _extract_ast_features(self, tree: ast.AST, features: StaticFeatures, code: str) -> None:
        """Extract features using AST analysis."""
        visitor = _FeatureVisitor()
        visitor.visit(tree)
        
        # Structural features
        features.num_functions = visitor.num_functions
        features.num_classes = visitor.num_classes
        features.num_imports = visitor.num_imports
        features.cyclomatic_complexity = visitor.cyclomatic_complexity
        features.max_nesting_depth = visitor.max_nesting_depth
        
        # Dangerous calls
        features.eval_calls = visitor.call_counts.get('eval', 0) + visitor.call_counts.get('exec', 0)
        features.exec_calls = visitor.call_counts.get('exec', 0)
        features.subprocess_calls = sum(visitor.call_counts.get(f.split('.')[-1], 0) 
                                        for f in self.SUBPROCESS_FUNCS)
        features.os_system_calls = visitor.call_counts.get('system', 0) + visitor.call_counts.get('popen', 0)
        features.socket_calls = visitor.call_counts.get('socket', 0) + visitor.call_counts.get('connect', 0)
        features.env_access = visitor.call_counts.get('getenv', 0) + visitor.env_access_count
        
        # Network calls
        for func in ['get', 'post', 'put', 'delete', 'urlopen']:
            features.network_calls += visitor.call_counts.get(func, 0)
        
        # File operations
        features.file_reads = visitor.call_counts.get('open', 0) + visitor.call_counts.get('read', 0)
        features.file_writes = visitor.call_counts.get('write', 0)
        
        # Obfuscation
        features.dynamic_imports = visitor.call_counts.get('__import__', 0)
        features.getattr_calls = visitor.call_counts.get('getattr', 0)
        features.compile_calls = visitor.call_counts.get('compile', 0)
        features.chr_ord_usage = visitor.call_counts.get('chr', 0) + visitor.call_counts.get('ord', 0)
        
        # Unsafe serialization
        features.pickle_usage = visitor.call_counts.get('load', 0) + visitor.call_counts.get('loads', 0)
        
        # Data flow (taint analysis)
        features.user_input_to_eval = visitor.tainted_to_eval
        features.user_input_to_subprocess = visitor.tainted_to_subprocess
        features.user_input_to_network = visitor.tainted_to_network
    
    def _extract_pattern_features(self, code: str, features: StaticFeatures) -> None:
        """Extract features using regex patterns."""
        # Hardcoded IPs (exclude localhost)
        ips = self.IP_PATTERN.findall(code)
        features.hardcoded_ips = len([ip for ip in ips if not ip.startswith('127.') and ip != '0.0.0.0'])
        
        # External URLs (exclude common safe domains)
        urls = self.URL_PATTERN.findall(code)
        safe_domains = ['github.com', 'pypi.org', 'python.org', 'docs.python.org', 'readthedocs']
        features.external_urls = len([u for u in urls if not any(d in u for d in safe_domains)])
        
        # Base64 strings (potential encoded payloads)
        features.base64_strings = len(self.BASE64_PATTERN.findall(code))
        
        # Hex strings
        features.hex_strings = len(self.HEX_PATTERN.findall(code))
        
        # YAML unsafe
        if 'yaml.load' in code and 'Loader' not in code:
            features.yaml_unsafe = 1
        if 'yaml.unsafe_load' in code:
            features.yaml_unsafe = 1
        
        # Marshal usage
        if 'marshal.load' in code:
            features.marshal_usage = 1


class _FeatureVisitor(ast.NodeVisitor):
    """AST visitor for feature extraction."""
    
    def __init__(self):
        self.num_functions = 0
        self.num_classes = 0
        self.num_imports = 0
        self.cyclomatic_complexity = 1  # Base complexity
        self.max_nesting_depth = 0
        self.current_depth = 0
        
        self.call_counts: Dict[str, int] = {}
        self.env_access_count = 0
        
        # Taint tracking
        self.tainted_vars: Set[str] = set()
        self.tainted_to_eval = False
        self.tainted_to_subprocess = False
        self.tainted_to_network = False
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.num_functions += 1
        # Parameters are tainted (user input)
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
        self.generic_visit(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.num_functions += 1
        for arg in node.args.args:
            self.tainted_vars.add(arg.arg)
        self.generic_visit(node)
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.num_classes += 1
        self.generic_visit(node)
    
    def visit_Import(self, node: ast.Import) -> None:
        self.num_imports += len(node.names)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.num_imports += len(node.names)
        self.generic_visit(node)
    
    def visit_If(self, node: ast.If) -> None:
        self.cyclomatic_complexity += 1
        self._visit_with_depth(node)
    
    def visit_For(self, node: ast.For) -> None:
        self.cyclomatic_complexity += 1
        self._visit_with_depth(node)
    
    def visit_While(self, node: ast.While) -> None:
        self.cyclomatic_complexity += 1
        self._visit_with_depth(node)
    
    def visit_Try(self, node: ast.Try) -> None:
        self.cyclomatic_complexity += len(node.handlers)
        self._visit_with_depth(node)
    
    def visit_Call(self, node: ast.Call) -> None:
        func_name = self._get_func_name(node)
        if func_name:
            self.call_counts[func_name] = self.call_counts.get(func_name, 0) + 1
            
            # Check taint propagation to dangerous sinks
            if func_name in ('eval', 'exec'):
                if self._has_tainted_arg(node):
                    self.tainted_to_eval = True
            elif func_name in ('run', 'call', 'Popen', 'system', 'popen'):
                if self._has_tainted_arg(node):
                    self.tainted_to_subprocess = True
            elif func_name in ('get', 'post', 'put', 'delete', 'urlopen'):
                if self._has_tainted_arg(node):
                    self.tainted_to_network = True
        
        self.generic_visit(node)
    
    def visit_Subscript(self, node: ast.Subscript) -> None:
        # Check for os.environ access
        if isinstance(node.value, ast.Attribute):
            if hasattr(node.value, 'attr') and node.value.attr == 'environ':
                self.env_access_count += 1
        self.generic_visit(node)
    
    def _visit_with_depth(self, node: ast.AST) -> None:
        self.current_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_depth)
        self.generic_visit(node)
        self.current_depth -= 1
    
    def _get_func_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None
    
    def _has_tainted_arg(self, node: ast.Call) -> bool:
        """Check if any argument is tainted."""
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.tainted_vars:
                return True
        return False
