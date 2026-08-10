"""Interactive French HTML report for FastAPI Doctor."""
import html
import json
from typing import Any, Dict


class HTMLReporter:
    """Generate a readable, searchable audit report."""

    @staticmethod
    def render(report: Dict[str, Any]) -> str:
        counts = {
            severity: sum(1 for finding in report["findings"] if finding["severity"] == severity)
            for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        }
        confidence_labels = {"HIGH": "Élevée", "MEDIUM": "Moyenne", "LOW": "Faible"}

        rows = []
        for finding in report["findings"]:
            location = finding.get("file") or ""
            if finding.get("line"):
                location += f":{finding['line']}"
            confidence = finding.get("confidence", "MEDIUM")
            severity = finding["severity"]
            rows.append(
                f'<tr data-severity="{html.escape(severity)}" data-confidence="{html.escape(confidence)}">'
                f'<td><b class="severity-{severity.lower()}">{html.escape(severity)}</b></td>'
                f"<td>{html.escape(finding['category'])}</td>"
                f"<td>{html.escape(finding['title'])}</td>"
                f"<td class='location'>{html.escape(location)}</td>"
                f"<td>{html.escape(finding['detail'])}</td>"
                f"<td>{html.escape(finding['recommendation'])}</td>"
                f"<td>{confidence_labels.get(confidence, 'Moyenne')}</td>"
                f"<td>{html.escape(finding['source'])}</td></tr>"
            )

        priorities = [
            finding for finding in report["findings"]
            if finding["severity"] in {"CRITICAL", "HIGH"}
            and finding.get("confidence", "MEDIUM") != "LOW"
        ][:10]
        priority_html = "".join(HTMLReporter._priority(finding) for finding in priorities)
        if not priority_html:
            priority_html = "<p>Aucun problème critique ou élevé avec une confiance suffisante.</p>"

        advanced = ""
        for key, title in (
            ("dependency_graph", "Analyse du graphe de dépendances"),
            ("openapi_analysis", "Analyse OpenAPI"),
            ("performance_metrics", "Métriques de performance"),
        ):
            if report.get(key):
                content = html.escape(json.dumps(report[key], ensure_ascii=False, indent=2))
                advanced += f'<details class="card"><summary>{title}</summary><pre>{content}</pre></details>'

        technology_json = html.escape(json.dumps(report["detected"], ensure_ascii=False, indent=2))
        metrics_json = html.escape(json.dumps(report["metrics"], ensure_ascii=False, indent=2))
        severity_summary = " · ".join(
            f'<span class="severity-{severity.lower()}">{severity}: {counts[severity]}</span>'
            for severity in counts if counts[severity]
        ) or "Aucun signalement"

        return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>FastAPI Doctor v{html.escape(report['version'])} — {html.escape(report['project'])}</title>
<style>
:root{{--critical:#b42318;--high:#d92d20;--medium:#dc6803;--low:#027a48}}
*{{box-sizing:border-box}} body{{font-family:system-ui,sans-serif;margin:0;background:#f4f6f8;color:#202124}}
main{{max-width:1500px;margin:auto;padding:28px}} .card{{background:white;padding:20px;border-radius:14px;margin-bottom:20px;box-shadow:0 2px 12px #0001}}
.hero{{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:center}} .score{{font-size:52px;font-weight:750}}
.severity-critical{{color:var(--critical)}} .severity-high{{color:var(--high)}} .severity-medium{{color:var(--medium)}} .severity-low{{color:var(--low)}}
.priority{{border-left:4px solid var(--high);padding:10px 14px;margin:12px 0;background:#fafafa}} .priority p{{margin:6px 0}}
.location{{color:#667085;font-family:ui-monospace,monospace}} .fix{{color:#344054}}
.filters{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}} .filters input,.filters select{{padding:10px;border:1px solid #ccd2d8;border-radius:8px;background:white}}
.filters input{{min-width:280px}} .table-wrap{{max-height:75vh;overflow:auto}} table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{padding:10px;border:1px solid #e1e5e9;text-align:left;vertical-align:top}} th{{background:#eef1f4;position:sticky;top:0;z-index:1}}
summary{{font-size:1.35em;font-weight:650;cursor:pointer}} pre{{overflow:auto}} small{{color:#667085}}
@media(max-width:700px){{main{{padding:12px}} .hero{{grid-template-columns:1fr}} .table-wrap{{max-height:none}}}}
</style></head><body><main>
<section class="card hero"><div><h1>FastAPI Doctor v{html.escape(report['version'])}</h1>
<p>Projet : <b>{html.escape(report['project'])}</b></p><p>Mode : {html.escape(report['mode'])} · Durée : {report['duration_seconds']}s</p>
<p>{severity_summary}</p><small>Le score regroupe les répétitions et tient compte du niveau de confiance.</small></div>
<div class="score">{report['score']}/100</div></section>
<section class="card"><h2>Priorités à examiner</h2>{priority_html}</section>
<details class="card"><summary>Technologies détectées</summary><pre>{technology_json}</pre></details>
<details class="card"><summary>Métriques</summary><pre>{metrics_json}</pre></details>{advanced}
<section class="card"><h2>Tous les signalements</h2><div class="filters">
<input id="search" placeholder="Rechercher un fichier, une règle…">
<select id="severity"><option value="">Toutes les gravités</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
<select id="confidence"><option value="">Toutes les confiances</option><option value="HIGH">Élevée</option><option value="MEDIUM">Moyenne</option><option value="LOW">Faible</option></select>
<span id="visible-count"></span></div><div class="table-wrap"><table><thead><tr>
<th>Gravité</th><th>Catégorie</th><th>Titre</th><th>Emplacement</th><th>Détail</th><th>Recommandation</th><th>Confiance</th><th>Source</th>
</tr></thead><tbody id="findings">{''.join(rows)}</tbody></table></div></section>
<script>
const rows=[...document.querySelectorAll('#findings tr')],search=document.querySelector('#search'),severity=document.querySelector('#severity'),confidence=document.querySelector('#confidence'),count=document.querySelector('#visible-count');
function filterRows(){{let visible=0,q=search.value.toLowerCase();rows.forEach(row=>{{let show=(!q||row.textContent.toLowerCase().includes(q))&&(!severity.value||row.dataset.severity===severity.value)&&(!confidence.value||row.dataset.confidence===confidence.value);row.hidden=!show;if(show)visible++}});count.textContent=`${{visible}} signalement(s) affiché(s)`}}
[search,severity,confidence].forEach(element=>element.addEventListener('input',filterRows));filterRows();
</script></main></body></html>"""

    @staticmethod
    def _priority(finding: Dict[str, Any]) -> str:
        location = finding.get("file") or ""
        if finding.get("line"):
            location += f":{finding['line']}"
        severity = finding["severity"]
        return (
            "<article class='priority'>"
            f"<strong class='severity-{severity.lower()}'>{html.escape(severity)}</strong> "
            f"<b>{html.escape(finding['title'])}</b>"
            f"<div class='location'>{html.escape(location)}</div>"
            f"<p>{html.escape(finding['detail'])}</p>"
            f"<p class='fix'>Conseil : {html.escape(finding['recommendation'])}</p></article>"
        )
