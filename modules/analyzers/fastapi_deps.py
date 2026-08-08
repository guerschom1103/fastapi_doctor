"""
FastAPI Dependency Analyzer for FastAPI Doctor
Analyze FastAPI dependency graph and security
"""
import ast
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from modules.utils.file_utils import rel

class FastAPIDependencyAnalyzer:
    """Analyze FastAPI dependency injection and security."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.dependency_graph = {}
        self.metrics = {
            "routes_found": 0,
            "dependencies_found": 0,
            "unprotected_routes": 0,
            "dependency_cycles": 0,
        }
    
    def analyze(self) -> Dict:
        """Run FastAPI dependency analysis."""
        routes = []
        dependencies = {}
        
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            try:
                file_routes, file_deps = self._analyze_file(path, source)
                routes.extend(file_routes)
                dependencies.update(file_deps)
            except SyntaxError:
                continue
        
        # Build dependency graph
        self._build_dependency_graph(routes, dependencies)
        
        # Analyze security
        self._analyze_security(routes, dependencies)
        
        return {
            "findings": self.findings,
            "graph": self.dependency_graph,
            "metrics": self.metrics,
        }
    
    def _analyze_file(self, path: Path, source: str) -> Tuple[List, Dict]:
        """Analyze a single file for FastAPI routes and dependencies."""
        routes = []
        dependencies = {}
        
        lines = source.splitlines()
        current_function = None
        current_deps = []
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Detect route decorators
            route_match = re.search(r'@(\w+)\.(get|post|put|patch|delete|options|head|websocket)\s*\(', line)
            if route_match:
                # Found a route
                self.metrics["routes_found"] += 1
                route_info = {
                    "file": rel(path, self.root),
                    "line": i,
                    "method": route_match.group(2).upper(),
                    "function": current_function,
                    "dependencies": current_deps.copy(),
                    "protected": False,
                }
                routes.append(route_info)
            
            # Detect function definitions
            func_match = re.match(r'^(async\s+)?def\s+(\w+)\s*\(', line_stripped)
            if func_match:
                current_function = func_match.group(2)
                current_deps = []
            
            # Detect dependency injections
            if "Depends(" in line:
                self.metrics["dependencies_found"] += 1
                dep_match = re.search(r'Depends\(([^)]+)\)', line)
                if dep_match:
                    dep_name = dep_match.group(1).strip()
                    current_deps.append(dep_name)
                    
                    # Store dependency
                    if current_function:
                        dependencies[current_function] = dependencies.get(current_function, []) + [dep_name]
            
            # Detect security dependencies
            security_keywords = [
                "Security(", "OAuth2PasswordBearer", "HTTPBearer", "HTTPBasic",
                "JWTBearer", "APIKeyHeader", "APIKeyQuery", "APIKeyCookie"
            ]
            if any(keyword in line for keyword in security_keywords):
                # Mark the current route as protected if we're in a route context
                if routes and current_function == routes[-1]["function"]:
                    routes[-1]["protected"] = True
        
        return routes, dependencies
    
    def _build_dependency_graph(self, routes: List, dependencies: Dict):
        """Build a graph of dependencies."""
        graph = {}
        
        # Add routes to graph
        for route in routes:
            route_name = route["function"] or f"route_{route['line']}"
            graph[route_name] = {
                "type": "route",
                "method": route["method"],
                "file": route["file"],
                "line": route["line"],
                "dependencies": route["dependencies"],
                "protected": route["protected"],
            }
        
        # Add dependencies to graph
        for dep_name, dep_deps in dependencies.items():
            if dep_name not in graph:
                graph[dep_name] = {
                    "type": "dependency",
                    "dependencies": dep_deps,
                }
        
        self.dependency_graph = graph
        
        # Check for cycles
        self._check_dependency_cycles(graph)
    
    def _check_dependency_cycles(self, graph: Dict):
        """Check for circular dependencies."""
        visited = set()
        recursion_stack = set()
        
        def dfs(node: str):
            if node not in graph:
                return False
            
            visited.add(node)
            recursion_stack.add(node)
            
            for neighbor in graph[node].get("dependencies", []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in recursion_stack:
                    # Cycle detected
                    self.metrics["dependency_cycles"] += 1
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "FastAPI Architecture",
                        "title": "Circular dependency detected",
                        "detail": f"Circular dependency involving '{node}' and '{neighbor}'.",
                        "file": None,
                        "line": None,
                        "recommendation": "Refactor dependencies to remove circular references.",
                        "rule_id": "FASTAPI-CIRCULAR-DEP"
                    })
                    return True
            
            recursion_stack.remove(node)
            return False
        
        for node in graph:
            if node not in visited:
                dfs(node)
    
    def _analyze_security(self, routes: List, dependencies: Dict):
        """Analyze security of routes."""
        unprotected_routes = [r for r in routes if not r["protected"]]
        self.metrics["unprotected_routes"] = len(unprotected_routes)
        
        for route in unprotected_routes:
            # Skip health checks and public endpoints
            if route["function"] and any(keyword in route["function"].lower() 
                                       for keyword in ["health", "status", "public", "docs", "openapi"]):
                continue
            
            self.findings.append({
                "severity": "MEDIUM",
                "category": "FastAPI Security",
                "title": "Route without explicit security",
                "detail": f"{route['method']} route at {route['file']}:{route['line']} has no detected security mechanism.",
                "file": route["file"],
                "line": route["line"],
                "recommendation": "Add authentication/authorization with Depends() or Security().",
                "rule_id": "FASTAPI-UNPROTECTED-ROUTE"
            })
        
        # Check for missing dependency imports
        for dep_name in dependencies:
            # Simple check: look for the dependency definition
            dep_defined = False
            for path in self.files:
                source = self.content_cache.get(path, "")
                if f"def {dep_name}(" in source or f"async def {dep_name}(" in source:
                    dep_defined = True
                    break
            
            if not dep_defined:
                self.findings.append({
                    "severity": "LOW",
                    "category": "FastAPI Architecture",
                    "title": "Potential missing dependency",
                    "detail": f"Dependency '{dep_name}' is referenced but not found in the codebase.",
                    "file": None,
                    "line": None,
                    "recommendation": "Define the dependency function or check for typos.",
                    "rule_id": "FASTAPI-MISSING-DEP"
                })