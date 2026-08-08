"""
Basic Analyzer for FastAPI Doctor
Contains the original analysis logic from v2.1.0
"""
import ast
import re
from pathlib import Path
from typing import Dict, List
from modules.utils.file_utils import rel, read_text
from modules.utils.security_utils import SecurityUtils

class BasicAnalyzer:
    """Basic analyzer with original v2.1.0 logic."""
    
    def __init__(self, root: Path, files: List[Path], all_paths: List[Path], 
                 findings: List[Dict], content_cache: Dict[Path, str], deep: bool):
        self.root = root
        self.files = files
        self.all_paths = all_paths
        self.findings = findings
        self.content_cache = content_cache
        self.deep = deep
        self.metrics = {
            "python_files": len(files),
            "syntax_errors": 0,
            "functions": 0,
            "classes": 0,
            "routes": 0,
            "async_functions": 0,
            "decorated_routes": 0,
            "dependencies": 0,
            "files_scanned": 0,
            "env_files": 0,
            "large_files": 0,
        }
    
    def analyze(self) -> Dict:
        """Run basic analysis (original v2.1.0 logic)."""
        self._ast_analysis()
        self._filesystem_security()
        self._framework_analysis()
        self._docker_analysis()
        return self.metrics
    
    def _ast_analysis(self):
        """Original AST analysis from v2.1.0."""
        route_methods = {"get", "post", "put", "patch", "delete", "options", "head", "websocket"}
        
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            try:
                tree = ast.parse(source, filename=str(path))
            except SyntaxError as exc:
                self.metrics["syntax_errors"] += 1
                self._add_finding(
                    "CRITICAL", "Correctness", "Python syntax error",
                    f"{exc.msg}", rel(path, self.root), exc.lineno,
                    "Corriger l'erreur de syntaxe avant toute mise en production.",
                    "PY-SYNTAX"
                )
                continue
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.metrics["functions"] += 1
                    if isinstance(node, ast.AsyncFunctionDef):
                        self.metrics["async_functions"] += 1
                    
                    for dec in node.decorator_list:
                        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                            if dec.func.attr in route_methods:
                                self.metrics["routes"] += 1
                                self.metrics["decorated_routes"] += 1
                        if isinstance(dec, ast.Name) and dec.id in {"router", "app"}:
                            pass
                    
                    span = (getattr(node, "end_lineno", None) or node.lineno) - node.lineno
                    if self.deep and span > 80:
                        self._add_finding(
                            "MEDIUM", "Maintainability", "Fonction excessivement longue",
                            f"`{node.name}` s'étend sur environ {span} lignes.",
                            rel(path, self.root), node.lineno,
                            "Découper la logique en services/fonctions plus petits et testables.",
                            "PY-LONG-FUNCTION"
                        )
                    
                    if self.deep:
                        args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
                        untyped = [a.arg for a in args if a.annotation is None]
                        if untyped:
                            self._add_finding(
                                "LOW", "Type Safety", "Paramètres non annotés",
                                f"`{node.name}` contient des paramètres sans annotation: {', '.join(untyped[:8])}.",
                                rel(path, self.root), node.lineno,
                                "Ajouter des annotations et exécuter mypy ou pyright.",
                                "PY-UNTYPED"
                            )
                
                elif isinstance(node, ast.ClassDef):
                    self.metrics["classes"] += 1
                
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                        self._add_finding(
                            "HIGH", "Security", "Exécution dynamique de code",
                            f"{node.func.id}() détecté.",
                            rel(path, self.root), node.lineno,
                            "Supprimer si possible et préférer une logique explicite.",
                            "SEC-EVAL"
                        )
                    if isinstance(node.func, ast.Attribute) and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}:
                        for kw in node.keywords:
                            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                self._add_finding(
                                    "HIGH", "Security", "subprocess avec shell=True",
                                    "Risque d'injection de commande si des entrées non fiables influencent la commande.",
                                    rel(path, self.root), node.lineno,
                                    "Éviter shell=True et passer les arguments sous forme de liste.",
                                    "SEC-SHELL"
                                )
            
            for i, line in enumerate(source.splitlines(), 1):
                if re.search(r"(?i)(password|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']{8,}[\"']", line):
                    self._add_finding(
                        "HIGH", "Secrets", "Secret potentiellement codé en dur",
                        "Une valeur sensible semble assignée directement dans le code.",
                        rel(path, self.root), i,
                        "Utiliser des variables d'environnement ou un gestionnaire de secrets.",
                        "SEC-HARDCODED-SECRET"
                    )
    
    def _filesystem_security(self):
        """Original filesystem security analysis from v2.1.0."""
        from modules.utils.file_utils import is_dotenv_file
        
        for p in self.all_paths:
            self.metrics["files_scanned"] += 1
            dotenv = is_dotenv_file(p)
            
            if dotenv:
                self.metrics["env_files"] += 1
                if self.deep:
                    self._add_finding(
                        "MEDIUM", "Secrets", "Fichier .env présent dans le projet",
                        f"Le fichier {p.name} existe dans l'arborescence auditée; il doit normalement être ignoré par Git.",
                        rel(p, self.root), None,
                        "Vérifier .gitignore et s'assurer qu'aucun secret réel n'est versionné.",
                        "SEC-ENV-FILE"
                    )
            
            try:
                size = p.stat().st_size
            except OSError:
                continue
            
            if size > 50_000_000:
                self.metrics["large_files"] += 1
                self._add_finding(
                    "LOW", "Repository", "Fichier volumineux",
                    f"Taille approximative: {size/1_000_000:.1f} MB.",
                    rel(p, self.root), None,
                    "Éviter de versionner des artefacts générés ou binaires lourds.",
                    "REPO-LARGE-FILE"
                )
            
            TEXT_EXTENSIONS = {".py", ".pyi", ".toml", ".ini", ".cfg", ".yaml", ".yml", ".json", ".env"}
            if (dotenv or p.suffix.lower() in TEXT_EXTENSIONS) and size <= 5_000_000:
                text = self.content_cache[p] if p in self.content_cache else read_text(p)
                for pattern, title in SecurityUtils.detect_secrets_in_text(text):
                    self._add_finding(
                        "CRITICAL", "Secrets", title,
                        "Signature d'un secret potentiellement réel détectée.",
                        rel(p, self.root), None,
                        "Révoquer/faire tourner le secret s'il est réel et le retirer de l'historique Git.",
                        "SEC-SECRET-SCAN"
                    )
    
    def _framework_analysis(self):
        """Original framework analysis from v2.1.0."""
        combined = "\n".join(self.content_cache.get(p, "") for p in self.files[:500]).lower()
        
        # This would need the detected dict from main
        # For now, we'll do a simplified version
        if "fastapi" in combined:
            if 'allow_origins=["*"]' in combined or "allow_origins=['*']" in combined:
                self._add_finding(
                    "MEDIUM", "FastAPI Security", "CORS wildcard détecté",
                    "allow_origins=* semble autoriser toutes les origines.",
                    None, None,
                    "Limiter les origines en production.",
                    "API-CORS-WILDCARD"
                )
            if "debug=true" in combined or "debug=True" in combined:
                self._add_finding(
                    "HIGH", "Production", "Mode debug potentiellement actif",
                    "Une configuration debug=True a été détectée.",
                    None, None,
                    "Désactiver le debug en production.",
                    "PROD-DEBUG"
                )
        
        if "jwt" in combined and self.deep:
            if 'algorithm="none"' in combined or "algorithm='none'" in combined:
                self._add_finding(
                    "CRITICAL", "Authentication", "JWT algorithm=none détecté",
                    "L'algorithme none ne doit pas être accepté pour des tokens d'authentification.",
                    None, None,
                    "Imposer une liste d'algorithmes de signature autorisés.",
                    "AUTH-JWT-NONE"
                )
        
        if "sqlalchemy" in combined and self.deep and "text(" in combined:
            self._add_finding(
                "MEDIUM", "Database", "Usage de SQLAlchemy text() détecté",
                "text() n'est pas forcément dangereux, mais mérite une revue si des fragments proviennent d'entrées utilisateur.",
                None, None,
                "Utiliser des paramètres liés et éviter de concaténer des entrées utilisateur dans SQL.",
                "DB-TEXT-REVIEW"
            )
    
    def _docker_analysis(self):
        """Original Docker analysis from v2.1.0."""
        for p in self.all_paths:
            if p.name.lower() == "dockerfile":
                text = read_text(p)
                if self.deep and not re.search(r"(?m)^\s*USER\s+\S+", text):
                    self._add_finding(
                        "MEDIUM", "Docker", "Dockerfile sans USER non-root",
                        "Le conteneur pourrait s'exécuter avec un utilisateur privilégié.",
                        rel(p, self.root), None,
                        "Créer et utiliser un utilisateur non privilégié.",
                        "DOCKER-NONROOT"
                    )
                if "ADD http://" in text or "ADD https://" in text:
                    self._add_finding(
                        "LOW", "Docker", "ADD d'une URL distante",
                        "Le téléchargement direct pendant le build peut réduire la reproductibilité.",
                        rel(p, self.root), None,
                        "Préférer des étapes explicites et vérifier les artefacts téléchargés.",
                        "DOCKER-REMOTE-ADD"
                    )
    
    def _add_finding(self, severity, category, title, detail, file=None, line=None, 
                    recommendation="", rule_id=None, source="FastAPI Doctor"):
        """Helper to add findings."""
        self.findings.append({
            "severity": severity,
            "category": category,
            "title": title,
            "detail": detail,
            "file": file,
            "line": line,
            "recommendation": recommendation,
            "source": source,
            "rule_id": rule_id,
        })