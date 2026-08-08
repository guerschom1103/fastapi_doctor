"""
HTML Reporter for FastAPI Doctor
"""
import html
import json
from typing import Any, Dict

class HTMLReporter:
    """HTML report generator."""
    
    @staticmethod
    def render(report: Dict[str, Any]) -> str:
        """Render report as HTML."""
        counts = {s: sum(1 for f in report["findings"] if f["severity"] == s) 
                 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        
        rows = []
        for f in report["findings"]:
            loc = f"{f['file']}:{f['line']}" if f.get("file") and f.get("line") else (f.get("file") or "")
            rows.append(
                f"<tr><td><b>{html.escape(f['severity'])}</b></td>"
                f"<td>{html.escape(f['category'])}</td><td>{html.escape(f['title'])}</td>"
                f"<td>{html.escape(loc)}</td><td>{html.escape(f['detail'])}</td>"
                f"<td>{html.escape(f['recommendation'])}</td><td>{html.escape(f['source'])}</td></tr>"
            )
        
        # Advanced analysis sections
        advanced_sections = ""
        if report.get("dependency_graph"):
            advanced_sections += f"""
            <div class="card">
                <h2>Dependency Graph Analysis</h2>
                <pre>{html.escape(json.dumps(report['dependency_graph'], ensure_ascii=False, indent=2))}</pre>
            </div>
            """
        
        if report.get("openapi_analysis"):
            advanced_sections += f"""
            <div class="card">
                <h2>OpenAPI Analysis</h2>
                <pre>{html.escape(json.dumps(report['openapi_analysis'], ensure_ascii=False, indent=2))}</pre>
            </div>
            """
        
        if report.get("performance_metrics"):
            advanced_sections += f"""
            <div class="card">
                <h2>Performance Metrics</h2>
                <pre>{html.escape(json.dumps(report['performance_metrics'], ensure_ascii=False, indent=2))}</pre>
            </div>
            """
        
        return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>FastAPI Doctor v{html.escape(report['version'])} - {html.escape(report['project'])}</title>
<style>
body{{font-family:system-ui,sans-serif;margin:32px;background:#f6f7f9;color:#202124}}
.card{{background:white;padding:20px;border-radius:12px;margin-bottom:20px;box-shadow:0 2px 10px #0001}}
.score{{font-size:48px;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:white}}
th,td{{padding:10px;border:1px solid #ddd;text-align:left;vertical-align:top}}
th{{background:#eee}}
.severity-critical {{color: #dc3545; font-weight: bold}}
.severity-high {{color: #fd7e14; font-weight: bold}}
.severity-medium {{color: #ffc107; font-weight: bold}}
.severity-low {{color: #28a745; font-weight: bold}}
.severity-info {{color: #17a2b8; font-weight: bold}}
</style></head><body>
<div class="card"><h1>FastAPI Doctor v{html.escape(report['version'])}</h1>
<div>Projet: <b>{html.escape(report['project'])}</b></div>
<div class="score">{report['score']}/100</div>
<p>Mode: {html.escape(report['mode'])} · Durée: {report['duration_seconds']}s</p>
<p>{' · '.join(f'<span class="severity-{s.lower()}">{s}: {counts[s]}</span>' for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") if counts[s]) or 'Aucun finding'}</p></div>
<div class="card"><h2>Technologies détectées</h2><pre>{html.escape(json.dumps(report['detected'], ensure_ascii=False, indent=2))}</pre></div>
<div class="card"><h2>Métriques</h2><pre>{html.escape(json.dumps(report['metrics'], ensure_ascii=False, indent=2))}</pre></div>
{advanced_sections}
<div class="card"><h2>Findings</h2><table><thead><tr><th>Severity</th><th>Catégorie</th><th>Titre</th><th>Emplacement</th><th>Détail</th><th>Recommandation</th><th>Source</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div></body></html>"""