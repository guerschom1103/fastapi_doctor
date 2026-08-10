"""
OpenAPI Analyzer for FastAPI Doctor
Analyze OpenAPI/Swagger documentation
"""
import json
import re
import yaml
from pathlib import Path
from typing import Dict, List, Optional
from modules.utils.file_utils import rel, read_text

class OpenAPIAnalyzer:
    """Analyze OpenAPI/Swagger documentation and schemas."""
    
    def __init__(self, root: Path, all_paths: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.all_paths = all_paths
        self.files = [path for path in all_paths if path.suffix in (".py", ".pyi")]
        self.content_cache = content_cache
        self.findings = []
        self.analysis = {
            "openapi_files_found": 0,
            "schemas_found": 0,
            "endpoints_documented": 0,
            "missing_descriptions": 0,
            "security_schemes": 0,
        }
    
    def analyze(self) -> Dict:
        """Run OpenAPI analysis."""
        # Find OpenAPI files
        openapi_files = self._find_openapi_files()
        
        # Analyze each OpenAPI file
        for file_path in openapi_files:
            self._analyze_openapi_file(file_path)
        
        # Check for FastAPI OpenAPI generation
        self._check_fastapi_openapi()
        
        return {
            "findings": self.findings,
            "analysis": self.analysis,
        }
    
    def _find_openapi_files(self) -> List[Path]:
        """Find OpenAPI/Swagger files in the project."""
        openapi_files = []
        
        for path in self.all_paths:
            name_lower = path.name.lower()
            if any(keyword in name_lower for keyword in [
                "openapi", "swagger", "api-docs", "openapi.yaml", 
                "openapi.yml", "openapi.json", "swagger.yaml", 
                "swagger.yml", "swagger.json"
            ]):
                openapi_files.append(path)
                self.analysis["openapi_files_found"] += 1
        
        return openapi_files
    
    def _analyze_openapi_file(self, file_path: Path):
        """Analyze a single OpenAPI file."""
        try:
            content = read_text(file_path, 10_000_000)
            if not content:
                return
            
            # Try to parse as JSON
            try:
                spec = json.loads(content)
            except json.JSONDecodeError:
                # Try to parse as YAML
                try:
                    spec = yaml.safe_load(content)
                except yaml.YAMLError:
                    self.findings.append({
                        "severity": "LOW",
                        "category": "OpenAPI",
                        "title": "Invalid OpenAPI file",
                        "detail": f"Could not parse {file_path.name} as JSON or YAML.",
                        "file": rel(file_path, self.root),
                        "line": None,
                        "recommendation": "Fix the OpenAPI file format.",
                        "rule_id": "OPENAPI-INVALID-FORMAT"
                    })
                    return
            
            # Analyze OpenAPI spec
            self._analyze_openapi_spec(spec, file_path)
            
        except Exception as e:
            self.findings.append({
                "severity": "LOW",
                "category": "OpenAPI",
                "title": "Error analyzing OpenAPI file",
                "detail": f"Error analyzing {file_path.name}: {str(e)}",
                "file": rel(file_path, self.root),
                "line": None,
                "recommendation": "Check the OpenAPI file for errors.",
                "rule_id": "OPENAPI-ANALYSIS-ERROR"
            })
    
    def _analyze_openapi_spec(self, spec: Dict, file_path: Path):
        """Analyze OpenAPI specification."""
        # Check OpenAPI version
        openapi_version = spec.get("openapi", "")
        if not openapi_version.startswith("3."):
            self.findings.append({
                "severity": "LOW",
                "category": "OpenAPI",
                "title": "Outdated OpenAPI version",
                "detail": f"OpenAPI version {openapi_version} may be outdated.",
                "file": rel(file_path, self.root),
                "line": None,
                "recommendation": "Consider upgrading to OpenAPI 3.x.",
                "rule_id": "OPENAPI-OUTDATED-VERSION"
            })
        
        # Count schemas
        schemas = spec.get("components", {}).get("schemas", {})
        self.analysis["schemas_found"] += len(schemas)
        
        # Count endpoints
        paths = spec.get("paths", {})
        endpoint_count = 0
        missing_descriptions = 0
        
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() in ["get", "post", "put", "patch", "delete", "options", "head"]:
                    endpoint_count += 1
                    
                    # Check for description
                    if not details.get("description"):
                        missing_descriptions += 1
                        self.findings.append({
                            "severity": "LOW",
                            "category": "OpenAPI",
                            "title": "Endpoint missing description",
                            "detail": f"{method.upper()} {path} is missing a description.",
                            "file": rel(file_path, self.root),
                            "line": None,
                            "recommendation": "Add a description to improve documentation.",
                            "rule_id": "OPENAPI-MISSING-DESCRIPTION"
                        })
                    
                    # Check for response schemas
                    responses = details.get("responses", {})
                    if "200" in responses and not responses["200"].get("content"):
                        self.findings.append({
                            "severity": "LOW",
                            "category": "OpenAPI",
                            "title": "Endpoint missing response schema",
                            "detail": f"{method.upper()} {path} 200 response is missing content schema.",
                            "file": rel(file_path, self.root),
                            "line": None,
                            "recommendation": "Add response schemas for better documentation.",
                            "rule_id": "OPENAPI-MISSING-RESPONSE"
                        })
        
        self.analysis["endpoints_documented"] += endpoint_count
        self.analysis["missing_descriptions"] += missing_descriptions
        
        # Check security schemes
        security_schemes = spec.get("components", {}).get("securitySchemes", {})
        self.analysis["security_schemes"] += len(security_schemes)
        
        if not security_schemes:
            self.findings.append({
                "severity": "MEDIUM",
                "category": "OpenAPI",
                "title": "No security schemes defined",
                "detail": "OpenAPI specification has no security schemes defined.",
                "file": rel(file_path, self.root),
                "line": None,
                "recommendation": "Define security schemes for API authentication.",
                "rule_id": "OPENAPI-NO-SECURITY"
            })
    
    def _check_fastapi_openapi(self):
        """Check for FastAPI OpenAPI generation patterns."""
        for path in self.files:
            source = self.content_cache.get(path, "")
            if not source:
                continue
            
            # Check for FastAPI OpenAPI configuration
            lines = source.splitlines()
            for i, line in enumerate(lines, 1):
                # Check for OpenAPI configuration
                if "openapi_url" in line and "None" in line:
                    self.findings.append({
                        "severity": "MEDIUM",
                        "category": "FastAPI Security",
                        "title": "OpenAPI documentation disabled",
                        "detail": "OpenAPI documentation appears to be disabled in production.",
                        "file": rel(path, self.root),
                        "line": i,
                        "recommendation": "Ensure OpenAPI docs are only disabled in production, not development.",
                        "rule_id": "FASTAPI-OPENAPI-DISABLED"
                    })
                
                # Check for docs_url disabled
                if "docs_url" in line and "None" in line:
                    self.findings.append({
                        "severity": "LOW",
                        "category": "FastAPI Documentation",
                        "title": "Swagger UI disabled",
                        "detail": "Swagger UI documentation appears to be disabled.",
                        "file": rel(path, self.root),
                        "line": i,
                        "recommendation": "Consider keeping docs enabled for development environments.",
                        "rule_id": "FASTAPI-DOCS-DISABLED"
                    })
                
                # Check for redoc_url disabled
                if "redoc_url" in line and "None" in line:
                    self.findings.append({
                        "severity": "LOW",
                        "category": "FastAPI Documentation",
                        "title": "ReDoc disabled",
                        "detail": "ReDoc documentation appears to be disabled.",
                        "file": rel(path, self.root),
                        "line": i,
                        "recommendation": "Consider keeping ReDoc enabled for alternative documentation.",
                        "rule_id": "FASTAPI-REDOC-DISABLED"
                    })
