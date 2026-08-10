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
            "Signalements : " + " | ".join(f"{s}: {counts[s]}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[s]) if report["findings"] else "Signalements : aucun",
            "=" * 72,
        ]
        
        for f in report["findings"][:500]:
            loc = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else (f.get("file") or "")
            lines += [
                f"[{f['severity']}] {f['category']} | {f['title']}",
                f"  Emplacement : {loc}",
                f"  {f['detail']}",
                f"  Recommandation : {f['recommendation']}",
                f"  Confiance : {f.get('confidence', 'MEDIUM')}",
                f"  Source: {f['source']}",
                "",
            ]
        
        # Add advanced analysis summary
        if report.get("dependency_graph"):
            lines.append("[AVANCÉ] Analyse du graphe de dépendances terminée")
        if report.get("openapi_analysis"):
            lines.append("[AVANCÉ] Analyse OpenAPI terminée")
        if report.get("performance_metrics"):
            lines.append("[AVANCÉ] Analyse des performances terminée")
        
        return "\n".join(lines)
