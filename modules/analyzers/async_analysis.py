"""
Async/Await Analyzer for FastAPI Doctor
Analyze async/await patterns and performance
"""
import ast
import re
from pathlib import Path
from typing import Dict, List
from modules.utils.file_utils import rel

class AsyncAnalyzer:
    """Analyze async/await patterns for performance and correctness."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.metrics = {
            "async_functions": 0,
            "sync_in_async": 0,
            "missing_awaits": 0,
            "blocking_calls": 0,
            "nested_async": 0,
        }
    
    def analyze(self) -> Dict:
        """Run async/await analysis."""
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
        """AST-based async analysis."""
        visitor = AsyncASTVisitor(path, self.root, source)
        visitor.visit(tree)
        self.findings.extend(visitor.findings)
        self.metrics["async_functions"] += visitor.async_functions
        self.metrics["sync_in_async"] += visitor.sync_in_async
        self.metrics["missing_awaits"] += visitor.missing_awaits
        self.metrics["blocking_calls"] += visitor.blocking_calls
        self.metrics["nested_async"] += visitor.nested_async

class AsyncASTVisitor(ast.NodeVisitor):
    """AST visitor for async/await analysis."""
    
    def __init__(self, path: Path, root: Path, source: str):
        self.path = path
        self.root = root
        self.source = source
        self.findings = []
        self.async_functions = 0
        self.sync_in_async = 0
        self.missing_awaits = 0
        self.blocking_calls = 0
        self.nested_async = 0
        self.current_function_is_async = False
        self.function_stack = []
    
    def visit_AsyncFunctionDef(self, node):
        """Visit async function definition."""
        self.async_functions += 1
        parent_is_async = bool(self.function_stack) and self.function_stack[-1][0] == "async"
        previous_async_state = self.current_function_is_async
        self.current_function_is_async = True
        self.function_stack.append(("async", node.name))
        
        # Check for nested async functions (can be problematic)
        if parent_is_async:
            self.nested_async += 1
            self.findings.append({
                "severity": "LOW",
                "category": "Async Performance",
                "title": "Fonction async imbriquée dans une fonction async",
                "detail": f"La fonction async `{node.name}` est recréée à chaque appel de sa fonction parente.",
                "file": rel(self.path, self.root),
                "line": node.lineno,
                "recommendation": "La déplacer au niveau du module seulement si elle ne capture aucun état local.",
                "rule_id": "ASYNC-NESTED-FUNCTION",
                "confidence": "LOW",
            })
        
        self.generic_visit(node)
        self.function_stack.pop()
        self.current_function_is_async = previous_async_state
    
    def visit_FunctionDef(self, node):
        """Visit sync function definition."""
        self.function_stack.append(("sync", node.name))
        self.generic_visit(node)
        self.function_stack.pop()
    
    def visit_Await(self, node):
        """Visit await expression."""
        # Check what's being awaited
        if isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Name):
                func_name = func.id
                # Check for common blocking functions that shouldn't be awaited
                blocking_funcs = ["time.sleep", "open", "input", "print"]
                if any(func_name == f.split('.')[-1] for f in blocking_funcs):
                    self.blocking_calls += 1
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "Async Performance",
                        "title": "Blocking call in await",
                        "detail": f"Blocking function '{func_name}' is being awaited.",
                        "file": rel(self.path, self.root),
                        "line": node.lineno,
                        "recommendation": "Use async alternatives: asyncio.sleep instead of time.sleep.",
                        "rule_id": "ASYNC-BLOCKING-AWAIT"
                    })
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Visit function calls."""
        if self.current_function_is_async:
            dotted_name = ""
            if isinstance(node.func, ast.Name):
                dotted_name = node.func.id
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                dotted_name = f"{node.func.value.id}.{node.func.attr}"

            blocking_calls = {"open", "input", "time.sleep", "requests.get", "requests.post"}
            if dotted_name in blocking_calls:
                self.sync_in_async += 1
                self.blocking_calls += 1
                self.findings.append({
                    "severity": "MEDIUM",
                    "category": "Async Performance",
                    "title": "Blocking I/O in async function",
                    "detail": f"Blocking call '{dotted_name}' used in an async function.",
                    "file": rel(self.path, self.root),
                    "line": node.lineno,
                    "recommendation": "Use an async alternative or run the blocking call in a thread pool.",
                    "rule_id": "ASYNC-BLOCKING-IO",
                })
                self.generic_visit(node)
                return

            # Check for async function calls without await
            if isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
                # Common async function patterns
                async_patterns = [
                    "fetch", "get", "post", "put", "delete", "execute",
                    "query", "read", "write", "send", "receive"
                ]
                
                # Check if this looks like an async function but isn't awaited
                if any(pattern in func_name.lower() for pattern in async_patterns):
                    # Look at the line to see if it's awaited
                    line = self.source.splitlines()[node.lineno - 1]
                    if "await " not in line:
                        self.missing_awaits += 1
                        self.findings.append({
                            "severity": "MEDIUM",
                            "category": "Async Correctness",
                            "title": "Possible missing await",
                            "detail": f"Function call '{func_name}' in async function may need await.",
                            "file": rel(self.path, self.root),
                            "line": node.lineno,
                            "recommendation": "Check if this function returns a coroutine and needs await.",
                            "rule_id": "ASYNC-MISSING-AWAIT"
                        })
            
            # Check for blocking I/O calls in async functions
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
                blocking_funcs = ["open", "read", "write", "input", "print", "sleep"]
                
                if func_name in blocking_funcs or any(f.endswith(func_name) for f in blocking_funcs):
                    self.sync_in_async += 1
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "Async Performance",
                        "title": "Blocking I/O in async function",
                        "detail": f"Blocking I/O function '{func_name}' called in async function.",
                        "file": rel(self.path, self.root),
                        "line": node.lineno,
                        "recommendation": "Use async alternatives: aiofiles for file I/O, aiohttp for HTTP.",
                        "rule_id": "ASYNC-BLOCKING-IO"
                    })
        
        self.generic_visit(node)
    
    def visit_With(self, node):
        """Visit with statements (context managers)."""
        if self.current_function_is_async:
            # Check for async context managers
            for item in node.items:
                if isinstance(item.context_expr, ast.Call):
                    func = item.context_expr.func
                    if isinstance(func, ast.Name):
                        func_name = func.id
                        # Common async context managers
                        async_contexts = ["connect", "session", "transaction", "pool"]
                        if any(ctx in func_name.lower() for ctx in async_contexts):
                            # Check if it's used with async with
                            line = self.source.splitlines()[node.lineno - 1]
                            if "async with" not in line:
                                self.findings.append({
                                    "severity": "LOW",
                                    "category": "Async Correctness",
                                    "title": "Possible sync context manager in async function",
                                    "detail": f"Context manager '{func_name}' may need 'async with'.",
                                    "file": rel(self.path, self.root),
                                    "line": node.lineno,
                                    "recommendation": "Use 'async with' for async context managers.",
                                    "rule_id": "ASYNC-CONTEXT-MANAGER"
                                })
        
        self.generic_visit(node)
