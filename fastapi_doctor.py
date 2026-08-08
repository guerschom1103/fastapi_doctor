#!/usr/bin/env python3
"""
FastAPI Doctor v3.0.0
Professional, generic, non-destructive audit orchestrator for Python/FastAPI projects.

Features:
- AST-based Python analysis with data flow tracking
- Advanced SQL injection detection
- FastAPI dependency graph analysis
- OpenAPI/Swagger schema validation
- Pydantic model analysis
- Async/await performance analysis
- Authentication/authorization deep analysis
- CORS/debug/security checks
- SQLAlchemy/Alembic signals
- Docker/Compose checks
- Dependency/security tool orchestration when installed
- Optional pytest/coverage execution
- JSON, HTML and SARIF reports
- Configurable exclusions and thresholds
- CI-friendly exit codes

This is a static/dynamic audit assistant, not a penetration tester or certification.
"""
from __future__ import annotations

import argparse
import ast
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Import modules
from modules.analyzers.dataflow import DataFlowAnalyzer
from modules.analyzers.sql_injection import SQLInjectionAnalyzer
from modules.analyzers.fastapi_deps import FastAPIDependencyAnalyzer
from modules.analyzers.openapi import OpenAPIAnalyzer
from modules.analyzers.pydantic_analysis import PydanticAnalyzer
from modules.analyzers.async_analysis import AsyncAnalyzer
from modules.analyzers.performance import PerformanceAnalyzer
from modules.analyzers.architecture import ArchitectureAnalyzer
from modules.reporters.html_reporter import HTMLReporter
from modules.reporters.sarif_reporter import SARIFReporter
from modules.reporters.json_reporter import JSONReporter
from modules.utils.file_utils import scan_tree, read_all, read_text, is_dotenv_file, rel
from modules.utils.security_utils import SecurityUtils

# Répertoires à élaguer PENDANT le parcours
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", ".env",
    "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", "dist", "build", ".idea", ".vscode",
    ".next", "htmlcov", "site-packages", "coverage", ".coverage",
}

TEXT_EXTENSIONS = {".py", ".pyi", ".toml", ".ini", ".cfg", ".yaml", ".yml", ".json", ".env"}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
WEIGHTS = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
DEFAULT_TIMEOUT = 120
MAX_PARALLEL_TOOLS = 6

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    file: str | None = None
    line: int | None = None
    recommendation: str = ""
    source: str = "FastAPI Doctor"
    rule_id: str | None = None

@dataclass
class ToolResult:
    name: str
    available: bool
    returncode: int | None = None
    duration_seconds: float = 0.0
    output_file: str | None = None
    note: str = ""

@dataclass
class AuditReport:
    version: str
    project: str
    path: str
    duration_seconds: float
    mode: str
    detected: dict[str, bool]
    metrics: dict[str, Any]
    tools: list[ToolResult]
    findings: list[Finding]
    score: int
    generated_at: str
    dependency_graph: Optional[Dict] = None
    openapi_analysis: Optional[Dict] = None
    performance_metrics: Optional[Dict] = None

def command_exists(name: str) -> bool:
    return shutil.which(name) is not None

def run(cmd: list[str], cwd: Path, timeout: int = DEFAULT_TIMEOUT) -> tuple[int, str, str, float]:
    start = time.perf_counter()
    try:
        p = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout
        )
        return p.returncode, p.stdout, p.stderr, time.perf_counter() - start
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} not found", time.perf_counter() - start
    except subprocess.TimeoutExpired:
        return 124, "", f"Timeout after {timeout}s", time.perf_counter() - start
    except Exception as exc:
        return 1, "", repr(exc), time.perf_counter() - start

def detect(root: Path, files: list[Path], all_paths: list[Path], content_cache: dict[Path, str]) -> dict[str, bool]:
    text = "\n".join(content_cache.get(p, "") for p in files[:500]).lower()
    names = {p.name.lower() for p in all_paths}
    return {
        "fastapi": "from fastapi" in text or "import fastapi" in text,
        "pydantic": "pydantic" in text,
        "sqlalchemy": "sqlalchemy" in text,
        "alembic": "alembic" in text or "alembic.ini" in names,
        "jwt": bool(re.search(r"\b(jwt|jose|pyjwt)\b", text)),
        "oauth2": "oauth2" in text,
        "rbac": bool(re.search(r"\b(rbac|role|permission|is_admin|admin_required)\b", text)),
        "cors": "corsmiddleware" in text,
        "redis": "redis" in text,
        "celery": "celery" in text,
        "docker": "dockerfile" in names or "docker-compose.yml" in names or "compose.yml" in names,
        "kubernetes": any(p.suffix in {".yaml", ".yml"} and "kubernetes" in read_text(p, 1_000_000).lower() for p in all_paths[:200]),
        "pytest": "pytest" in text or any("test" in p.name.lower() for p in files),
        "postgresql": bool(re.search(r"\b(postgresql|asyncpg|psycopg)\b", text)),
        "graphql": "graphql" in text,
        "openapi": any("openapi" in p.name.lower() for p in all_paths) or "openapi" in text,
    }

def add_finding(findings, severity, category, title, detail, path=None, line=None, recommendation="", rule_id=None, source="FastAPI Doctor"):
    findings.append({
        "severity": severity,
        "category": category,
        "title": title,
        "detail": detail,
        "file": path,
        "line": line,
        "recommendation": recommendation,
        "source": source,
        "rule_id": rule_id
    })

def run_advanced_analyzers(root: Path, files: list[Path], findings: list[Finding], 
                         detected: dict[str, bool], content_cache: dict[Path, str], 
                         deep: bool) -> Dict[str, Any]:
    """Run all advanced analyzers"""
    results = {}
    
    # Data Flow Analysis
    if deep:
        dataflow_analyzer = DataFlowAnalyzer(root, files, content_cache)
        dataflow_results = dataflow_analyzer.analyze()
        findings.extend(dataflow_results.get("findings", []))
        results["dataflow"] = dataflow_results.get("metrics", {})
    
    # SQL Injection Analysis
    if detected.get("sqlalchemy") or any("sql" in content_cache.get(p, "").lower() for p in files[:100]):
        sql_analyzer = SQLInjectionAnalyzer(root, files, content_cache)
        sql_results = sql_analyzer.analyze()
        findings.extend(sql_results.get("findings", []))
        results["sql_injection"] = sql_results.get("metrics", {})
    
    # FastAPI Dependency Analysis
    if detected.get("fastapi"):
        deps_analyzer = FastAPIDependencyAnalyzer(root, files, content_cache)
        deps_results = deps_analyzer.analyze()
        findings.extend(deps_results.get("findings", []))
        results["dependency_graph"] = deps_results.get("graph", {})
    
    # OpenAPI Analysis
    if detected.get("openapi") or detected.get("fastapi"):
        openapi_analyzer = OpenAPIAnalyzer(root, all_paths, content_cache)
        openapi_results = openapi_analyzer.analyze()
        findings.extend(openapi_results.get("findings", []))
        results["openapi"] = openapi_results.get("analysis", {})
    
    # Pydantic Analysis
    if detected.get("pydantic"):
        pydantic_analyzer = PydanticAnalyzer(root, files, content_cache)
        pydantic_results = pydantic_analyzer.analyze()
        findings.extend(pydantic_results.get("findings", []))
        results["pydantic"] = pydantic_results.get("metrics", {})
    
    # Async Analysis
    async_analyzer = AsyncAnalyzer(root, files, content_cache)
    async_results = async_analyzer.analyze()
    findings.extend(async_results.get("findings", []))
    results["async"] = async_results.get("metrics", {})
    
    # Performance Analysis
    if deep:
        perf_analyzer = PerformanceAnalyzer(root, files, content_cache)
        perf_results = perf_analyzer.analyze()
        findings.extend(perf_results.get("findings", []))
        results["performance"] = perf_results.get("metrics", {})
    
    # Architecture Analysis
    arch_analyzer = ArchitectureAnalyzer(root, files, content_cache)
    arch_results = arch_analyzer.analyze()
    findings.extend(arch_results.get("findings", []))
    results["architecture"] = arch_results.get("metrics", {})
    
    return results

def external_tools(root: Path, findings: list[Finding], deep: bool, run_tests: bool) -> list[ToolResult]:
    specs = [
        ("ruff", ["ruff", "check", ".", "--output-format", "json"]),
        ("mypy", ["mypy", "."]),
        ("bandit", ["bandit", "-r", ".", "-f", "json"]),
        ("pip-audit", ["pip-audit", "--format", "json"]),
    ]
    if deep:
        specs.append(("semgrep", ["semgrep", "--config", "auto", "--json", "."]))
    if run_tests:
        specs.append(("pytest", ["pytest", "-q"]))

    results: list[Any] = [None] * len(specs)
    runnable = []
    for idx, (name, cmd) in enumerate(specs):
        if command_exists(cmd[0]):
            runnable.append((idx, name, cmd))
        else:
            results[idx] = ToolResult(name, False, note="Outil non installé; analyse ignorée.")

    raw: dict[int, tuple[int, str, str, float]] = {}
    if runnable:
        with ThreadPoolExecutor(max_workers=min(MAX_PARALLEL_TOOLS, len(runnable))) as pool:
            futures = {
                pool.submit(run, cmd, root, 180 if name == "semgrep" else 120): idx
                for idx, name, cmd in runnable
            }
            for future in futures:
                raw[futures[future]] = future.result()

    for idx, name, cmd in runnable:
        code, out, err, duration = raw[idx]
        results[idx] = ToolResult(name, True, code, round(duration, 3))
        if code == 124:
            add_finding(
                findings, "MEDIUM", "Tooling", f"{name} a dépassé le délai",
                "L'analyse n'a pas terminé dans le délai configuré.",
                None, None,
                "Relancer l'outil séparément ou ajuster le délai.",
                "TOOL-TIMEOUT"
            )
        if name == "ruff" and out:
            try:
                data = json.loads(out)
                for item in data[:500]:
                    add_finding(
                        findings, "MEDIUM", "Code Quality",
                        f"Ruff {item.get('code', 'issue')}",
                        item.get("message", "Violation Ruff."),
                        item.get("filename"),
                        item.get("location", {}).get("row"),
                        "Corriger la violation ou la justifier.",
                        "RUFF",
                        "Ruff"
                    )
            except json.JSONDecodeError:
                pass
        elif name == "bandit" and out:
            try:
                data = json.loads(out)
                for item in data.get("results", [])[:500]:
                    sev = str(item.get("issue_severity", "MEDIUM")).upper()
                    sev = sev if sev in SEVERITIES else "MEDIUM"
                    add_finding(
                        findings, sev, "Security",
                        item.get("test_name", "Bandit finding"),
                        item.get("issue_text", "Finding Bandit."),
                        item.get("filename"),
                        item.get("line_number"),
                        "Examiner et corriger le problème de sécurité.",
                        item.get("test_id"),
                        "Bandit"
                    )
            except json.JSONDecodeError:
                pass
        elif name == "pip-audit" and out:
            try:
                data = json.loads(out)
                for pkg in data if isinstance(data, list) else []:
                    for vuln in pkg.get("vulns", []):
                        add_finding(
                            findings, "HIGH", "Dependencies",
                            f"Dépendance vulnérable: {pkg.get('name', 'unknown')}",
                            f"{vuln.get('id', '')}: {vuln.get('description', '')[:500]}",
                            None, None,
                            "Mettre à jour vers une version corrigée si disponible.",
                            "DEP-VULN",
                            "pip-audit"
                        )
            except json.JSONDecodeError:
                pass
        elif name == "pytest" and code != 0:
            add_finding(
                findings, "HIGH", "Testing",
                "Tests pytest en échec",
                (err or out)[-1500:],
                None, None,
                "Corriger les tests en échec avant le déploiement.",
                "TEST-FAIL",
                "pytest"
            )
    return results

def score(findings: list[dict]) -> int:
    penalty = sum(WEIGHTS.get(f.get("severity", "INFO"), 0) for f in findings)
    return max(0, min(100, 100 - min(100, penalty)))

def build_parser():
    p = argparse.ArgumentParser(description="FastAPI Doctor v3 - professional Python/FastAPI audit")
    p.add_argument("--version", action="version", version="FastAPI Doctor v3.0.0")
    p.add_argument("--path", default=".", help="Racine du projet")
    p.add_argument("--deep", action="store_true", help="Analyse approfondie avec analyse de flux de données")
    p.add_argument("--tests", action="store_true", help="Lancer pytest si disponible")
    p.add_argument("--no-external", action="store_true", help="Ne pas lancer les outils externes")
    p.add_argument("--format", choices=["text", "json", "html", "sarif"], default="text")
    p.add_argument("--output", help="Fichier de sortie")
    p.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], default="HIGH")
    p.add_argument("--analyze-deps", action="store_true", help="Analyser le graphe de dépendances FastAPI")
    p.add_argument("--analyze-openapi", action="store_true", help="Analyser le schéma OpenAPI")
    p.add_argument("--analyze-performance", action="store_true", help="Analyser les performances")
    return p

def main() -> int:
    args = build_parser().parse_args()
    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Chemin invalide: {root}", file=sys.stderr)
        print(f"Le chemin n'existe pas ou n'est pas un dossier", file=sys.stderr)
        return 2

    start = time.perf_counter()
    all_paths, files = scan_tree(root, SKIP_DIRS)
    content_cache = read_all(files)
    detected = detect(root, files, all_paths, content_cache)
    findings: list[Finding] = []
    
    # Run advanced analyzers
    advanced_results = {}
    if args.deep or args.analyze_deps or args.analyze_openapi or args.analyze_performance:
        advanced_results = run_advanced_analyzers(
            root, files, findings, detected, content_cache, args.deep
        )
    
    # Run basic analyzers (from original code)
    from modules.analyzers.basic import BasicAnalyzer
    basic_analyzer = BasicAnalyzer(root, files, all_paths, findings, content_cache, args.deep)
    metrics = basic_analyzer.analyze()
    
    # Run external tools
    tools = []
    if not args.no_external:
        tools = external_tools(root, findings, args.deep, args.tests)

    # Deduplicate findings
    unique = {}
    for f in findings:
        key = (f.get("severity"), f.get("category"), f.get("title"), f.get("file"), f.get("line"), f.get("detail"), f.get("rule_id"))
        unique[key] = f
    findings = sorted(unique.values(), key=lambda f: (-WEIGHTS.get(f.get("severity", "INFO"), 0), f.get("category", ""), f.get("file", "") or "", f.get("line", 0) or 0))

    # Create report
    report = AuditReport(
        version="3.0.0",
        project=root.name,
        path=str(root),
        duration_seconds=round(time.perf_counter() - start, 3),
        mode="deep" if args.deep else "standard",
        detected=detected,
        metrics=metrics,
        tools=tools,
        findings=findings,
        score=score(findings),
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        dependency_graph=advanced_results.get("dependency_graph"),
        openapi_analysis=advanced_results.get("openapi"),
        performance_metrics=advanced_results.get("performance"),
    )

    # Convert report to dict for reporters
    report_dict = asdict(report)
    
    # Generate output
    if args.format == "json":
        output = JSONReporter.render(report_dict)
    elif args.format == "html":
        output = HTMLReporter.render(report_dict)
    elif args.format == "sarif":
        output = SARIFReporter.render(report_dict)
    else:
        from modules.reporters.text_reporter import TextReporter
        output = TextReporter.render(report_dict)

    if args.output:
        out = Path(args.output).expanduser()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(output, encoding="utf-8")
        print(f"Rapport écrit: {out}")
    else:
        print(output)

    fail_weight = WEIGHTS[args.fail_on]
    if any(WEIGHTS.get(f.get("severity", "INFO"), 0) >= fail_weight for f in findings):
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())