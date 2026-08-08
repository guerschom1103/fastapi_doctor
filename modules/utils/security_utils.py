"""
Security utilities for FastAPI Doctor
"""
import re
from typing import List, Tuple

class SecurityUtils:
    """Security-related utility functions."""
    
    @staticmethod
    def detect_secrets_in_text(text: str) -> List[Tuple[str, str]]:
        """Detect potential secrets in text."""
        patterns = [
            (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Clé privée"),
            (r"(?i)aws_access_key_id\s*=\s*[A-Z0-9]{16,}", "Clé AWS potentielle"),
            (r"(?i)aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40,}", "Secret AWS potentiel"),
            (r"(?i)github_pat_[A-Za-z0-9_]{20,}", "Token GitHub potentiel"),
            (r"(?i)ghp_[A-Za-z0-9_]{36,}", "Token GitHub (nouveau format)"),
            (r"(?i)password\s*=\s*[\"'][^\"']{8,}[\"']", "Mot de passe codé en dur"),
            (r"(?i)secret\s*=\s*[\"'][^\"']{8,}[\"']", "Secret codé en dur"),
            (r"(?i)api[_-]?key\s*=\s*[\"'][^\"']{8,}[\"']", "Clé API codée en dur"),
            (r"(?i)token\s*=\s*[\"'][^\"']{8,}[\"']", "Token codé en dur"),
        ]
        
        findings = []
        for pattern, title in patterns:
            if re.search(pattern, text):
                findings.append((pattern, title))
        return findings
    
    @staticmethod
    def is_sensitive_variable_name(name: str) -> bool:
        """Check if a variable name suggests sensitive data."""
        sensitive_keywords = [
            "password", "secret", "key", "token", "credential",
            "auth", "jwt", "oauth", "api_key", "private_key",
            "access_key", "secret_key", "bearer", "session"
        ]
        name_lower = name.lower()
        return any(keyword in name_lower for keyword in sensitive_keywords)
    
    @staticmethod
    def is_sql_injection_pattern(text: str) -> bool:
        """Detect SQL injection patterns."""
        patterns = [
            r"f\"\"?SELECT.*\{.*\}.*\"",  # f-string in SELECT
            r"f\"\"?INSERT.*\{.*\}.*\"",  # f-string in INSERT
            r"f\"\"?UPDATE.*\{.*\}.*\"",  # f-string in UPDATE
            r"f\"\"?DELETE.*\{.*\}.*\"",  # f-string in DELETE
            r"\.format\(.*\)",  # String format in SQL
            r"%s.*%",  # Old-style formatting
            r"\+.*WHERE",  # String concatenation with WHERE
            r"\+.*VALUES",  # String concatenation with VALUES
        ]
        return any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)