"""
SARIF Reporter for FastAPI Doctor
"""
import json
import re
from typing import Any, Dict

class SARIFReporter:
    """SARIF report generator for GitHub Code Scanning."""
    
    @staticmethod
    def render(report: Dict[str, Any]) -> str:
        """Render report as SARIF."""
        rules = {}
        results = []
        
        for f in report["findings"]:
            rid = f.get("rule_id") or re.sub(r"[^A-Za-z0-9_.-]+", "-", f["title"].lower())[:80]
            rules.setdefault(rid, {
                "id": rid,
                "name": f["title"],
                "shortDescription": {"text": f["title"]},
                "help": {"text": f["recommendation"] or f["detail"]},
            })
            
            level = "error" if f["severity"] in {"CRITICAL", "HIGH"} else "warning" if f["severity"] == "MEDIUM" else "note"
            result = {
                "ruleId": rid,
                "level": level,
                "message": {"text": f["detail"]},
            }
            
            if f.get("file"):
                loc = {"physicalLocation": {"artifactLocation": {"uri": f["file"]}}}
                if f.get("line"):
                    loc["physicalLocation"]["region"] = {"startLine": f["line"]}
                result["locations"] = [loc]
            
            results.append(result)
        
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "FastAPI Doctor",
                        "version": report["version"],
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }
        
        return json.dumps(sarif, ensure_ascii=False, indent=2)