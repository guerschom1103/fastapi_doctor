"""
SQL Injection Analyzer for FastAPI Doctor
Advanced SQL injection detection
"""
import ast
import re
from pathlib import Path
from typing import Dict, List
from modules.utils.file_utils import rel
from modules.utils.security_utils import SecurityUtils


def looks_like_sql(text: str) -> bool:
    """Require SQL structure, not merely an English word such as 'update'."""
    normalized = " ".join(text.lower().split())
    return bool(
        re.search(r"\bselect\b.+\bfrom\b", normalized)
        or re.search(r"\binsert\s+into\b", normalized)
        or re.search(r"\bupdate\b.+\bset\b", normalized)
        or re.search(r"\bdelete\s+from\b", normalized)
    )

class SQLInjectionAnalyzer:
    """Advanced SQL injection detection analyzer."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.metrics = {
            "sql_statements_found": 0,
            "potential_injections": 0,
            "parameterized_queries": 0,
        }
    
    def analyze(self) -> Dict:
        """Run SQL injection analysis."""
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            # Text-based detection first
            self._analyze_text(path, source)
            
            # AST-based detection for deeper analysis
            try:
                tree = ast.parse(source, filename=str(path))
                self._analyze_ast(path, tree, source)
            except SyntaxError:
                continue
        
        return {
            "findings": self.findings,
            "metrics": self.metrics,
        }
    
    def _analyze_text(self, path: Path, source: str):
        """Text-based SQL injection detection."""
        lines = source.splitlines()
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower()
            
            # Check for SQL keywords
            has_sql = looks_like_sql(line)
            
            if has_sql:
                self.metrics["sql_statements_found"] += 1
                
                # Check for dangerous patterns
                if SecurityUtils.is_sql_injection_pattern(line):
                    self.metrics["potential_injections"] += 1
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "SQL Injection",
                        "title": "Potential SQL injection vulnerability",
                        "detail": f"SQL statement with potential injection pattern: {line[:100]}...",
                        "file": rel(path, self.root),
                        "line": i,
                        "recommendation": "Use parameterized queries or ORM methods instead of string concatenation.",
                        "rule_id": "SQL-INJECTION-PATTERN"
                    })
                
                # Check for f-strings in SQL
                if ("f\"" in line or "f'" in line) and has_sql:
                    self.metrics["potential_injections"] += 1
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "SQL Injection",
                        "title": "F-string in SQL statement",
                        "detail": "F-strings in SQL statements can lead to injection vulnerabilities.",
                        "file": rel(path, self.root),
                        "line": i,
                        "recommendation": "Use parameterized queries with SQLAlchemy or database drivers.",
                        "rule_id": "SQL-INJECTION-FSTRING"
                    })
                
                # Check for .format() in SQL
                if ".format(" in line and has_sql:
                    self.metrics["potential_injections"] += 1
                    self.findings.append({
                        "severity": "HIGH",
                        "category": "SQL Injection",
                        "title": "String format in SQL statement",
                        "detail": "String formatting in SQL statements can lead to injection vulnerabilities.",
                        "file": rel(path, self.root),
                        "line": i,
                        "recommendation": "Use parameterized queries instead of string formatting.",
                        "rule_id": "SQL-INJECTION-FORMAT"
                    })
    
    def _analyze_ast(self, path: Path, tree: ast.AST, source: str):
        """AST-based SQL injection detection."""
        visitor = SQLInjectionVisitor(path, self.root, source)
        visitor.visit(tree)
        self.findings.extend(visitor.findings)
        self.metrics["sql_statements_found"] += visitor.sql_statements_found
        self.metrics["potential_injections"] += visitor.potential_injections
        self.metrics["parameterized_queries"] += visitor.parameterized_queries

class SQLInjectionVisitor(ast.NodeVisitor):
    """AST visitor for SQL injection detection."""
    
    def __init__(self, path: Path, root: Path, source: str):
        self.path = path
        self.root = root
        self.source = source
        self.findings = []
        self.sql_statements_found = 0
        self.potential_injections = 0
        self.parameterized_queries = 0
        
    def visit_Call(self, node):
        """Check function calls for SQL injection patterns."""
        # Check for SQLAlchemy text() function
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "text":
                self.sql_statements_found += 1
                
                # Check if text() is used with string formatting
                for arg in node.args:
                    if isinstance(arg, ast.JoinedStr):  # f-string
                        self.potential_injections += 1
                        self.findings.append({
                            "severity": "HIGH",
                            "category": "SQL Injection",
                            "title": "F-string in SQLAlchemy text()",
                            "detail": "F-strings in SQLAlchemy text() can lead to SQL injection.",
                            "file": rel(self.path, self.root),
                            "line": node.lineno,
                            "recommendation": "Use SQLAlchemy's parameter binding with :param syntax.",
                            "rule_id": "SQLALCHEMY-FSTRING-TEXT"
                        })
        
        # Check for execute() calls with string concatenation
        elif isinstance(node.func, ast.Name):
            if node.func.id in ["execute", "executemany"]:
                self.sql_statements_found += 1
                
                # Check first argument for dangerous patterns
                if node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                        # String concatenation in execute()
                        self.potential_injections += 1
                        self.findings.append({
                            "severity": "CRITICAL",
                            "category": "SQL Injection",
                            "title": "String concatenation in database execute()",
                            "detail": "String concatenation in execute() calls is highly vulnerable to SQL injection.",
                            "file": rel(self.path, self.root),
                            "line": node.lineno,
                            "recommendation": "Use parameterized queries with placeholders (?, %s, :name).",
                            "rule_id": "SQL-CONCAT-EXECUTE"
                        })
        
        self.generic_visit(node)
    
    def visit_JoinedStr(self, node):
        """Check f-strings for SQL patterns."""
        # Get the line where this f-string appears
        line_num = node.lineno
        lines = self.source.splitlines()
        if line_num <= len(lines):
            line = lines[line_num - 1]
            
            # Check if this f-string contains SQL keywords
            static_text = "".join(
                value.value for value in node.values
                if isinstance(value, ast.Constant) and isinstance(value.value, str)
            )
            if looks_like_sql(static_text):
                self.potential_injections += 1
                self.findings.append({
                    "severity": "HIGH",
                    "category": "SQL Injection",
                    "title": "F-string with SQL keywords",
                    "detail": "F-string appears to contain SQL keywords, which could indicate injection risk.",
                    "file": rel(self.path, self.root),
                    "line": line_num,
                    "recommendation": "Review for SQL injection vulnerability. Use parameterized queries.",
                    "rule_id": "SQL-INJECTION-FSTRING-KEYWORDS"
                })
        
        self.generic_visit(node)
