"""
JSON Reporter for FastAPI Doctor
"""
import json
from typing import Any, Dict

class JSONReporter:
    """JSON report generator."""
    
    @staticmethod
    def render(report: Dict[str, Any]) -> str:
        """Render report as JSON."""
        return json.dumps(report, ensure_ascii=False, indent=2)