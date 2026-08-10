"""
Architecture Analyzer for FastAPI Doctor
Analyze architectural patterns and violations
"""
import ast
import re
from pathlib import Path
from typing import Dict, List, Set
from modules.utils.file_utils import rel

class ArchitectureAnalyzer:
    """Analyze architectural patterns and violations."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.metrics = {
            "clean_architecture_violations": 0,
            "circular_imports": 0,
            "god_classes": 0,
            "tight_coupling": 0,
            "separation_of_concerns": 0,
        }
    
    def analyze(self) -> Dict:
        """Run architecture analysis."""
        # Analyze imports and dependencies
        import_graph = self._build_import_graph()
        
        # Check for circular imports
        self._check_circular_imports(import_graph)
        
        # Analyze each file for architectural issues
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            try:
                self._analyze_file(path, source, import_graph)
            except SyntaxError:
                continue
        
        return {
            "findings": self.findings,
            "metrics": self.metrics,
        }
    
    def _build_import_graph(self) -> Dict[str, Set[str]]:
        """Build a graph of imports between files."""
        graph: Dict[str, Set[str]] = {}
        module_to_file: Dict[str, str] = {}
        for path in self.files:
            file_key = rel(path, self.root)
            parts = list(Path(file_key).with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts.pop()
            module_to_file[".".join(parts)] = file_key
        
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            file_key = rel(path, self.root)
            imported_modules = set()
            
            # Parse imports
            try:
                tree = ast.parse(source)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            imported_modules.add(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            imported_modules.add(node.module)
            except SyntaxError:
                continue
            
            targets = set()
            for imported in imported_modules:
                candidate = imported
                while candidate:
                    if candidate in module_to_file:
                        targets.add(module_to_file[candidate])
                        break
                    candidate = candidate.rpartition(".")[0]
            graph[file_key] = targets
        
        return graph
    
    def _check_circular_imports(self, graph: Dict[str, Set[str]]):
        """Check for circular imports."""
        visited = set()
        recursion_stack = set()
        
        def dfs(node: str, path: List[str]):
            if node in recursion_stack:
                # Circular import detected
                cycle_start = path.index(node)
                cycle = path[cycle_start:] + [node]
                self.metrics["circular_imports"] += 1
                self.findings.append({
                    "severity": "MEDIUM",
                    "category": "Architecture",
                    "title": "Circular import detected",
                    "detail": f"Circular import: {' -> '.join(cycle)}",
                    "file": node,
                    "line": None,
                    "recommendation": "Refactor to break circular dependencies.",
                    "rule_id": "ARCH-CIRCULAR-IMPORT"
                })
                return True
            
            if node in visited:
                return False
            
            visited.add(node)
            recursion_stack.add(node)
            path.append(node)
            
            for neighbor in graph.get(node, set()):
                if neighbor in graph:
                    dfs(neighbor, path.copy())
            
            recursion_stack.remove(node)
            path.pop()
            return False
        
        for node in graph:
            if node not in visited:
                dfs(node, [])
    
    def _analyze_file(self, path: Path, source: str, import_graph: Dict[str, Set[str]]):
        """Analyze a single file for architectural issues."""
        file_key = rel(path, self.root)
        
        # Check for Clean Architecture violations
        self._check_clean_architecture(path, source, file_key)
        
        # Check for God classes
        self._check_god_classes(path, source)
        
        # Check for tight coupling
        self._check_tight_coupling(path, source, file_key, import_graph)
        
        # Check separation of concerns
        self._check_separation_of_concerns(path, source)
    
    def _check_clean_architecture(self, path: Path, source: str, file_key: str):
        """Check for Clean Architecture violations."""
        # Simple heuristic: check if domain logic imports framework code
        domain_keywords = ["domain", "model", "entity", "value_object", "service"]
        framework_keywords = ["fastapi", "sqlalchemy", "flask", "django", "requests"]
        
        is_domain_file = any(keyword in file_key.lower() for keyword in domain_keywords)
        
        if is_domain_file:
            for framework in framework_keywords:
                if framework in source.lower():
                    self.metrics["clean_architecture_violations"] += 1
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "Architecture",
                        "title": "Clean Architecture violation",
                        "detail": f"Domain file imports framework code ({framework}).",
                        "file": file_key,
                        "line": None,
                        "recommendation": "Keep domain logic independent of frameworks.",
                        "rule_id": "ARCH-CLEAN-VIOLATION"
                    })
                    break
    
    def _check_god_classes(self, path: Path, source: str):
        """Check for God classes (classes doing too much)."""
        try:
            tree = ast.parse(source)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Count methods and attributes
                    method_count = 0
                    attribute_count = 0
                    line_count = 0
                    
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_count += 1
                            # Estimate method size
                            end_line = getattr(item, 'end_lineno', item.lineno)
                            line_count += (end_line - item.lineno)
                        elif isinstance(item, ast.AnnAssign):
                            attribute_count += 1
                        elif isinstance(item, ast.Assign):
                            attribute_count += 1
                    
                    # Heuristic: God class if too many methods or too long
                    if method_count > 15 or line_count > 300:
                        self.metrics["god_classes"] += 1
                        self.findings.append({
                            "severity": "LOW",
                            "category": "Architecture",
                            "title": "Potential God class",
                            "detail": f"Class '{node.name}' has {method_count} methods and ~{line_count} lines.",
                            "file": rel(path, self.root),
                            "line": node.lineno,
                            "recommendation": "Consider splitting into smaller, focused classes.",
                            "rule_id": "ARCH-GOD-CLASS"
                        })
        
        except SyntaxError:
            pass
    
    def _check_tight_coupling(self, path: Path, source: str, file_key: str, import_graph: Dict[str, Set[str]]):
        """Check for tight coupling."""
        # Count imports from this file
        imports = import_graph.get(file_key, set())
        
        # Heuristic: too many imports suggests tight coupling
        if len(imports) > 10:
            self.metrics["tight_coupling"] += 1
            self.findings.append({
                "severity": "LOW",
                "category": "Architecture",
                "title": "High coupling (many imports)",
                "detail": f"File imports {len(imports)} different modules.",
                "file": file_key,
                "line": None,
                "recommendation": "Reduce dependencies and apply dependency inversion.",
                "rule_id": "ARCH-HIGH-COUPLING"
            })
        
        # Importing a Service/Repository is normal in FastAPI. Without knowledge of
        # project boundaries, class names alone cannot establish tight coupling.
    
    def _check_separation_of_concerns(self, path: Path, source: str):
        """Check for separation of concerns violations."""
        lines = source.splitlines()
        file_key = rel(path, self.root)
        
        # Check for mixed concerns in file names
        concerns = ["api", "model", "service", "repository", "controller", "view", "schema"]
        file_concerns = [c for c in concerns if c in file_key.lower()]
        
        if len(file_concerns) > 1:
            self.metrics["separation_of_concerns"] += 1
            self.findings.append({
                "severity": "LOW",
                "category": "Architecture",
                "title": "Mixed concerns in file",
                "detail": f"File appears to mix {', '.join(file_concerns)} concerns.",
                "file": file_key,
                "line": None,
                "recommendation": "Separate concerns into different files/modules.",
                "rule_id": "ARCH-MIXED-CONCERNS"
            })
        
        # Check for database logic in API layer
        if "api" in file_key.lower() or "route" in file_key.lower():
            db_keywords = ["session.query", "db.query", "SELECT", "INSERT", "UPDATE", "DELETE"]
            for i, line in enumerate(lines, 1):
                if any(keyword in line for keyword in db_keywords):
                    self.metrics["separation_of_concerns"] += 1
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "Architecture",
                        "title": "Database logic in API layer",
                        "detail": "Database operations should be in repository/service layer.",
                        "file": file_key,
                        "line": i,
                        "recommendation": "Move database logic to repository layer.",
                        "rule_id": "ARCH-DB-IN-API"
                    })
                    break
