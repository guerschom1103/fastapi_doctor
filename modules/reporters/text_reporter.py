"""
Text Reporter for FastAPI Doctor
"""
from typing import Any, Dict

class TextReporter:
    """Text report generator."""
    
    @staticmethod
    def render(report: Dict[str, Any]) -> str:
        """Render report as text."""
        counts = {s: sum(1 for f in report["findings"] if f["severity"] == s) 
                 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        
        lines = [
            f"FASTAPI DOCTOR v{report['version']}",
            "=" * 72,
            f"Projet : {report['project']}",
            f"Score  : {report['score']}/100",
            f"Mode   : {report['mode']}",
            f"Durée  : {report['duration_seconds']}s",
            "",
            "Findings: " + " | ".join(f"{s}: {counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[s]) if report["findings"] else "Findings: aucun",
            "=" * 72,
        ]
        
        for f in report["findings"][:500]:
            loc = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else (f.get("file") or "")
            lines += [
                f"[{f['severity']}] {f['category']} | {f['title']}",
                f"  Location: {loc}",
                f"  {f['detail']}",
                f"  Recommendation: {f['recommendation']}",
                f"  Source: {f['source']}",
                "",
            ]
        
        # Add advanced analysis summary
        if report.get("dependency_graph"):
            lines.append("[ADVANCED] Dependency graph analysis completed")
        if report.get("openapi_analysis"):
            lines.append("[ADVANCED] OpenAPI analysis completed")
        if report.get("performance_metrics"):
            lines.append("[ADVANCED] Performance analysis completed")
        
        return "\n".join(lines)