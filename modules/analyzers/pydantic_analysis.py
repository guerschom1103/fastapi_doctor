"""
Pydantic Analyzer for FastAPI Doctor
Analyze Pydantic models and validation
"""
import ast
import re
from pathlib import Path
from typing import Dict, List
from modules.utils.file_utils import rel

class PydanticAnalyzer:
    """Analyze Pydantic models for best practices and issues."""
    
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
        self.findings = []
        self.metrics = {
            "pydantic_models_found": 0,
            "models_with_validators": 0,
            "models_with_config": 0,
            "untyped_fields": 0,
            "models_with_aliases": 0,
        }
    
    def analyze(self) -> Dict:
        """Run Pydantic analysis."""
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            try:
                self._analyze_file(path, source)
            except SyntaxError:
                continue
        
        return {
            "findings": self.findings,
            "metrics": self.metrics,
        }
    
    def _analyze_file(self, path: Path, source: str):
        """Analyze a single file for Pydantic models."""
        lines = source.splitlines()
        in_pydantic_class = False
        current_class = None
        class_start_line = 0
        fields = []
        
        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            # Detect Pydantic class definition
            class_match = re.match(r'^class\s+(\w+)\s*\(.*(BaseModel|pydantic)', line_stripped, re.IGNORECASE)
            if class_match:
                in_pydantic_class = True
                current_class = class_match.group(1)
                class_start_line = i
                fields = []
                self.metrics["pydantic_models_found"] += 1
            
            # Check for class end
            elif in_pydantic_class and line_stripped and not line_stripped.startswith((' ', '\t')):
                # End of class
                self._analyze_pydantic_class(path, current_class, class_start_line, i, fields, source)
                in_pydantic_class = False
                current_class = None
            
            # Inside Pydantic class, look for fields
            elif in_pydantic_class and current_class:
                # Look for field definitions
                field_match = re.match(r'^(\w+)\s*:', line_stripped)
                if field_match:
                    field_name = field_match.group(1)
                    
                    # Check if field has type annotation
                    if ':' in line and '=' in line:
                        # Has type annotation
                        type_part = line.split(':', 1)[1].split('=', 1)[0].strip()
                        if not type_part or type_part == '...':
                            self.metrics["untyped_fields"] += 1
                            self.findings.append({
                                "severity": "LOW",
                                "category": "Pydantic",
                                "title": "Untyped Pydantic field",
                                "detail": f"Field '{field_name}' in model '{current_class}' has no type annotation.",
                                "file": rel(path, self.root),
                                "line": i,
                                "recommendation": "Add type annotations to all Pydantic fields.",
                                "rule_id": "PYDANTIC-UNTYPED-FIELD"
                            })
                    
                    fields.append((field_name, i))
            
            # Look for validators
            if "@validator" in line or "@root_validator" in line:
                self.metrics["models_with_validators"] += 1
            
            # Look for Config class
            if "class Config:" in line_stripped and in_pydantic_class:
                self.metrics["models_with_config"] += 1
            
            # Look for Field aliases
            if "Field(" in line and "alias=" in line:
                self.metrics["models_with_aliases"] += 1
    
    def _analyze_pydantic_class(self, path: Path, class_name: str, start_line: int, 
                               end_line: int, fields: List, source: str):
        """Analyze a complete Pydantic class."""
        class_content = "\n".join(source.splitlines()[start_line-1:end_line])
        
        # Check for __init__ method (should not be defined in Pydantic models)
        if "__init__" in class_content:
            self.findings.append({
                "severity": "MEDIUM",
                "category": "Pydantic",
                "title": "Pydantic model with custom __init__",
                "detail": f"Model '{class_name}' defines a custom __init__ method.",
                "file": rel(path, self.root),
                "line": start_line,
                "recommendation": "Avoid custom __init__ in Pydantic models; use validators instead.",
                "rule_id": "PYDANTIC-CUSTOM-INIT"
            })
        
        # Check for mutable default values
        for field_name, line_num in fields:
            line = source.splitlines()[line_num-1]
            if "= []" in line or "= {}" in line or "= set()" in line:
                self.findings.append({
                    "severity": "MEDIUM",
                    "category": "Pydantic",
                    "title": "Mutable default in Pydantic field",
                    "detail": f"Field '{field_name}' in model '{class_name}' has mutable default value.",
                    "file": rel(path, self.root),
                    "line": line_num,
                    "recommendation": "Use default_factory for mutable defaults: default_factory=list, dict, or set.",
                    "rule_id": "PYDANTIC-MUTABLE-DEFAULT"
                })
        
        # Check for missing validators on sensitive fields
        sensitive_fields = ["password", "secret", "token", "key", "credential"]
        for field_name, line_num in fields:
            if any(sensitive in field_name.lower() for sensitive in sensitive_fields):
                # Check if there's a validator for this field
                if f"@validator('{field_name}'" not in class_content and \
                   f'@validator("{field_name}"' not in class_content:
                    self.findings.append({
                        "severity": "LOW",
                        "category": "Pydantic Security",
                        "title": "Sensitive field without validator",
                        "detail": f"Sensitive field '{field_name}' in model '{class_name}' has no validator.",
                        "file": rel(path, self.root),
                        "line": line_num,
                        "recommendation": "Add a validator for sensitive fields to enforce security rules.",
                        "rule_id": "PYDANTIC-SENSITIVE-NO-VALIDATOR"
                    })
        
        # AST-based analysis for deeper checks
        try:
            tree = ast.parse(class_content)
            self._analyze_pydantic_ast(path, class_name, start_line, tree)
        except SyntaxError:
            pass
    
    def _analyze_pydantic_ast(self, path: Path, class_name: str, start_line: int, tree: ast.AST):
        """AST-based analysis of Pydantic class."""
        visitor = PydanticASTVisitor(path, self.root, class_name, start_line)
        visitor.visit(tree)
        self.findings.extend(visitor.findings)

class PydanticASTVisitor(ast.NodeVisitor):
    """AST visitor for Pydantic model analysis."""
    
    def __init__(self, path: Path, root: Path, class_name: str, start_line: int):
        self.path = path
        self.root = root
        self.class_name = class_name
        self.start_line = start_line
        self.findings = []
    
    def visit_ClassDef(self, node):
        """Analyze class definition."""
        # Check for proper inheritance
        has_base_model = False
        for base in node.bases:
            if isinstance(base, ast.Name):
                if base.id == "BaseModel":
                    has_base_model = True
                    break
            elif isinstance(base, ast.Attribute):
                if base.attr == "BaseModel":
                    has_base_model = True
                    break
        
        if not has_base_model:
            self.findings.append({
                "severity": "LOW",
                "category": "Pydantic",
                "title": "Possible non-Pydantic class",
                "detail": f"Class '{self.class_name}' doesn't appear to inherit from BaseModel.",
                "file": rel(self.path, self.root),
                "line": self.start_line + node.lineno - 1,
                "recommendation": "Ensure Pydantic models inherit from BaseModel.",
                "rule_id": "PYDANTIC-NO-BASEMODEL"
            })
        
        self.generic_visit(node)
    
    def visit_AnnAssign(self, node):
        """Analyze annotated assignments (Pydantic fields)."""
        if isinstance(node.target, ast.Name):
            field_name = node.target.id
            
            # Check for Optional without default
            if node.annotation:
                annotation_str = ast.unparse(node.annotation) if hasattr(ast, 'unparse') else str(node.annotation)
                if "Optional[" in annotation_str and node.value is None:
                    self.findings.append({
                        "severity": "LOW",
                        "category": "Pydantic",
                        "title": "Optional field without default",
                        "detail": f"Field '{field_name}' is Optional but has no default value.",
                        "file": rel(self.path, self.root),
                        "line": self.start_line + node.lineno - 1,
                        "recommendation": "Add default=None to Optional fields.",
                        "rule_id": "PYDANTIC-OPTIONAL-NO-DEFAULT"
                    })
        
        self.generic_visit(node)