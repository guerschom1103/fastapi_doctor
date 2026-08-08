"""
Performance Analyzer for FastAPI Doctor
Analyze performance issues and optimizations
"""
import ast
import re
from pathlib import Path
from typing import Dict, List
from modules.utils.file_utils import rel

class PerformanceAnalyzer:
    """Analyze performance issues in code."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.metrics = {
            "n_plus_one_patterns": 0,
            "expensive_loops": 0,
            "redundant_calculations": 0,
            "large_data_structures": 0,
            "inefficient_algorithms": 0,
        }
    
    def analyze(self) -> Dict:
        """Run performance analysis."""
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            try:
                tree = ast.parse(source, filename=str(path))
                self._analyze_ast(path, tree, source)
            except SyntaxError:
                continue
        
        return {
            "findings": self.findings,
            "metrics": self.metrics,
        }
    
    def _analyze_ast(self, path: Path, tree: ast.AST, source: str):
        """AST-based performance analysis."""
        visitor = PerformanceASTVisitor(path, self.root, source)
        visitor.visit(tree)
        self.findings.extend(visitor.findings)
        self.metrics["n_plus_one_patterns"] += visitor.n_plus_one_patterns
        self.metrics["expensive_loops"] += visitor.expensive_loops
        self.metrics["redundant_calculations"] += visitor.redundant_calculations
        self.metrics["large_data_structures"] += visitor.large_data_structures
        self.metrics["inefficient_algorithms"] += visitor.inefficient_algorithms

class PerformanceASTVisitor(ast.NodeVisitor):
    """AST visitor for performance analysis."""
    
    def __init__(self, path: Path, root: Path, source: str):
        self.path = path
        self.root = root
        self.source = source
        self.findings = []
        self.n_plus_one_patterns = 0
        self.expensive_loops = 0
        self.redundant_calculations = 0
        self.large_data_structures = 0
        self.inefficient_algorithms = 0
        self.current_loop_depth = 0
    
    def visit_For(self, node):
        """Visit for loops."""
        self.current_loop_depth += 1
        
        # Check for N+1 query patterns
        self._check_n_plus_one(node)
        
        # Check for expensive operations in loops
        self._check_expensive_loop_operations(node)
        
        self.generic_visit(node)
        self.current_loop_depth -= 1
    
    def visit_While(self, node):
        """Visit while loops."""
        self.current_loop_depth += 1
        
        # Check for expensive operations in loops
        self._check_expensive_loop_operations(node)
        
        self.generic_visit(node)
        self.current_loop_depth -= 1
    
    def visit_ListComp(self, node):
        """Visit list comprehensions."""
        # Check for large list comprehensions
        if len(node.generators) > 2:
            self.inefficient_algorithms += 1
            self.findings.append({
                "severity": "LOW",
                "category": "Performance",
                "title": "Complex list comprehension",
                "detail": "List comprehension with multiple generators may be inefficient.",
                "file": rel(self.path, self.root),
                "line": node.lineno,
                "recommendation": "Consider using explicit loops for complex comprehensions.",
                "rule_id": "PERF-COMPLEX-COMPREHENSION"
            })
        
        self.generic_visit(node)
    
    def visit_DictComp(self, node):
        """Visit dict comprehensions."""
        # Check for large dict comprehensions
        if len(node.generators) > 2:
            self.inefficient_algorithms += 1
            self.findings.append({
                "severity": "LOW",
                "category": "Performance",
                "title": "Complex dict comprehension",
                "detail": "Dict comprehension with multiple generators may be inefficient.",
                "file": rel(self.path, self.root),
                "line": node.lineno,
                "recommendation": "Consider using explicit loops for complex comprehensions.",
                "rule_id": "PERF-COMPLEX-DICT-COMP"
            })
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Visit function calls."""
        # Check for expensive function calls
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            expensive_calls = [
                "deepcopy", "copy.deepcopy", "pickle.dumps", "json.dumps",
                "xml.etree.ElementTree", "re.compile", "sorted", "list.sort"
            ]
            
            if func_name in expensive_calls or any(f.endswith(func_name) for f in expensive_calls):
                if self.current_loop_depth > 0:
                    self.expensive_loops += 1
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "Performance",
                        "title": "Expensive operation in loop",
                        "detail": f"Expensive function '{func_name}' called inside a loop.",
                        "file": rel(self.path, self.root),
                        "line": node.lineno,
                        "recommendation": "Move expensive operations outside loops when possible.",
                        "rule_id": "PERF-EXPENSIVE-IN-LOOP"
                    })
        
        self.generic_visit(node)
    
    def _check_n_plus_one(self, node):
        """Check for N+1 query patterns."""
        # Simple pattern detection: database queries in loops
        loop_body = ast.unparse(node.body) if hasattr(ast, 'unparse') else str(node.body)
        
        # Look for database query patterns in loops
        query_patterns = [
            r"\.get\(", r"\.filter\(", r"\.query\(", r"\.select\(",
            r"session\.query\(", r"db\.query\(", r"\.find_one\(", r"\.find\("
        ]
        
        for pattern in query_patterns:
            if re.search(pattern, loop_body, re.IGNORECASE):
                self.n_plus_one_patterns += 1
                self.findings.append({
                    "severity": "MEDIUM",
                    "category": "Performance",
                    "title": "Potential N+1 query pattern",
                    "detail": "Database query detected inside a loop (N+1 problem).",
                    "file": rel(self.path, self.root),
                    "line": node.lineno,
                    "recommendation": "Use eager loading (JOINs) or batch queries to avoid N+1.",
                    "rule_id": "PERF-N-PLUS-ONE"
                })
                break
    
    def _check_expensive_loop_operations(self, node):
        """Check for expensive operations in loops."""
        # Check for function calls that create large data structures
        loop_body = ast.unparse(node.body) if hasattr(ast, 'unparse') else str(node.body)
        
        expensive_patterns = [
            r"list\(range\(\d+\)\)",  # list(range(large_number))
            r"\[\s*\]\s*\*\s*\d+",    # [] * large_number
            r"\.append\(.*\)",         # Multiple appends
            r"\.extend\(.*\)",         # Multiple extends
        ]
        
        for pattern in expensive_patterns:
            if re.search(pattern, loop_body):
                self.expensive_loops += 1
                self.findings.append({
                    "severity": "LOW",
                    "category": "Performance",
                    "title": "Inefficient list operation in loop",
                    "detail": "List creation or extension detected inside a loop.",
                    "file": rel(self.path, self.root),
                    "line": node.lineno,
                    "recommendation": "Pre-allocate lists or use list comprehensions when possible.",
                    "rule_id": "PERF-LIST-IN-LOOP"
                })
                break
    
    def visit_Assign(self, node):
        """Visit assignments."""
        # Check for large list/dict literals
        if isinstance(node.value, (ast.List, ast.Dict, ast.Set, ast.Tuple)):
            # Estimate size (very rough)
            element_count = 0
            if isinstance(node.value, ast.List):
                element_count = len(node.value.elts)
            elif isinstance(node.value, ast.Dict):
                element_count = len(node.value.keys)
            elif isinstance(node.value, ast.Set):
                element_count = len(node.value.elts)
            elif isinstance(node.value, ast.Tuple):
                element_count = len(node.value.elts)
            
            if element_count > 50:
                self.large_data_structures += 1
                self.findings.append({
                    "severity": "LOW",
                    "category": "Performance",
                    "title": "Large data structure literal",
                    "detail": f"Data structure with {element_count} elements defined inline.",
                    "file": rel(self.path, self.root),
                    "line": node.lineno,
                    "recommendation": "Consider loading large data from files or databases.",
                    "rule_id": "PERF-LARGE-DATA-STRUCTURE"
                })
        
        self.generic_visit(node)
    
    def visit_BinOp(self, node):
        """Visit binary operations."""
        # Check for redundant calculations
        if isinstance(node.op, (ast.Add, ast.Mult, ast.Sub, ast.Div)):
            # Simple check: same calculation repeated
            left_str = ast.unparse(node.left) if hasattr(ast, 'unparse') else str(node.left)
            right_str = ast.unparse(node.right) if hasattr(ast, 'unparse') else str(node.right)
            
            # Very basic pattern matching
            if self.current_loop_depth > 0 and len(left_str) > 20 or len(right_str) > 20:
                self.redundant_calculations += 1
                # Don't add finding for every case, just count
        
        self.generic_visit(node)