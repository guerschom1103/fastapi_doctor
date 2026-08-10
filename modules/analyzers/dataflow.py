"""
Data Flow Analyzer for FastAPI Doctor
Tracks sensitive data through the codebase
"""
import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple
from modules.utils.file_utils import rel
from modules.utils.security_utils import SecurityUtils

class DataFlowAnalyzer:
    """Analyze data flow to track sensitive information."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.metrics = {
            "sensitive_vars_found": 0,
            "data_flows_tracked": 0,
            "potential_leaks": 0,
        }
    
    def analyze(self) -> Dict:
        """Run data flow analysis."""
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            try:
                tree = ast.parse(source, filename=str(path))
                self._analyze_file(path, tree)
            except SyntaxError:
                continue
        
        return {
            "findings": self.findings,
            "metrics": self.metrics,
        }
    
    def _analyze_file(self, path: Path, tree: ast.AST):
        """Analyze a single file for data flow issues."""
        visitor = DataFlowVisitor(path, self.root, self.content_cache)
        visitor.visit(tree)
        self.findings.extend(visitor.findings)
        self.metrics["sensitive_vars_found"] += visitor.sensitive_vars_found
        self.metrics["data_flows_tracked"] += visitor.data_flows_tracked
        self.metrics["potential_leaks"] += visitor.potential_leaks

class DataFlowVisitor(ast.NodeVisitor):
    """AST visitor for data flow analysis."""
    
    def __init__(self, path: Path, root: Path, content_cache: Dict[Path, str]):
        self.path = path
        self.root = root
        self.content_cache = content_cache
        self.findings = []
        self.sensitive_vars = set()
        self.sensitive_vars_found = 0
        self.data_flows_tracked = 0
        self.potential_leaks = 0
        
    def visit_Assign(self, node):
        """Track variable assignments."""
        # Check if assignment involves sensitive data
        if isinstance(node.value, ast.Constant):
            value = node.value.value
            if isinstance(value, str) and len(value) > 8:
                # Check if variable name suggests sensitive data
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if SecurityUtils.is_sensitive_variable_name(var_name):
                            self.sensitive_vars.add(var_name)
                            self.sensitive_vars_found += 1
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Track function calls that might leak sensitive data."""
        leaked_names = {
            child.id
            for arg in node.args
            for child in ast.walk(arg)
            if isinstance(child, ast.Name) and child.id in self.sensitive_vars
        }
        # Check for logging of sensitive variables
        if isinstance(node.func, ast.Attribute):
            if node.func.attr in ["info", "debug", "warning", "error", "critical"]:
                for name in leaked_names:
                    self.potential_leaks += 1
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "Data Flow",
                        "title": "Sensitive data potentially logged",
                        "detail": f"Variable '{name}' appears to contain sensitive data and is being passed to logging function.",
                        "file": rel(self.path, self.root),
                        "line": node.lineno,
                        "recommendation": "Avoid logging sensitive data. Use masking or redaction.",
                        "rule_id": "DATAFLOW-LOGGING-LEAK"
                    })
        
        # Check for print statements with sensitive data
        elif isinstance(node.func, ast.Name) and node.func.id == "print":
            for name in leaked_names:
                self.potential_leaks += 1
                self.findings.append({
                    "severity": "MEDIUM",
                    "category": "Data Flow",
                    "title": "Sensitive data printed to stdout",
                    "detail": f"Variable '{name}' appears to contain sensitive data and is being printed.",
                    "file": rel(self.path, self.root),
                    "line": node.lineno,
                    "recommendation": "Remove debug prints or mask sensitive data.",
                    "rule_id": "DATAFLOW-PRINT-LEAK"
                })
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node):
        """Track function parameters for sensitive data."""
        # Check function parameters
        for arg in node.args.args:
            if SecurityUtils.is_sensitive_variable_name(arg.arg):
                self.sensitive_vars.add(arg.arg)
                self.sensitive_vars_found += 1
        
        self.generic_visit(node)
