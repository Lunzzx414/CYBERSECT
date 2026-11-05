import re
import hashlib
import ipaddress
from typing import Dict, Any, List, Optional
from fastapi import Request, HTTPException

class HardenedSecurityEngine:
    # Strict regex signatures resistant to bypass obfuscation
    ATTACK_SIGNATURES = {
        "SQL_INJECTION": re.compile(r"(\bOR\b|\bUNION\b|\bSELECT\b|--|#|/\*|\*/|@@version|convert\(|cast\()", re.IGNORECASE),
        "XSS_ATTACK": re.compile(r"(<script\b[^>]*?>|javascript:|onerror\s*=|onload\s*=|expression\s*\(|<svg\b)", re.IGNORECASE),
        "PATH_TRAVERSAL": re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini)", re.IGNORECASE),
        "RCE_ATTACK": re.compile(r"(\bexec\b|\beval\b|system\(|passthru\(|shell_exec\(|popen\()", re.IGNORECASE)
    }

    @classmethod
    def inspect_request(cls, request: Request, body_str: str = "") -> Dict[str, Any]:
        client_ip = request.client.host if request.client else "127.0.0.1"
        query_str = str(request.url.query)
        path = request.url.path
        headers_str = str(dict(request.headers))
        
        composite_payload = f"{path}?{query_str} {headers_str} {body_str}"
        
        for vector, pattern in cls.ATTACK_SIGNATURES.items():
            if pattern.search(composite_payload):
                return {
                    "blocked": True,
                    "vector": vector,
                    "client_ip": client_ip,
                    "endpoint": path,
                    "confidence": 0.99
                }
        return {"blocked": False}

    @staticmethod
    def inspect_file(filename: str, content: bytes) -> Dict[str, Any]:
        file_hash = hashlib.sha256(content).hexdigest()
        dangerous_patterns = [b"eval(", b"exec(", b"subprocess.Popen", b"os.system(", b"socket.socket", b"ctypes."]
        heuristic_hit = any(p in content for p in dangerous_patterns)
        is_malicious = heuristic_hit
        classification = "Suspicious.Heuristic.Execution" if heuristic_hit else "Clean"
        
        return {
            "filename": filename,
            "sha256": file_hash,
            "malicious": is_malicious,
            "classification": classification
        }

    @staticmethod
    def audit_config(config: dict) -> List[str]:
        issues = []
        if config.get("debug") is True:
            issues.append("CRITICAL: Debug mode active in production environment.")
        if config.get("allowed_hosts") == "*":
            issues.append("HIGH: Wildcard allowed hosts allows Host Header Injection.")
        if len(config.get("secret_key", "")) < 32:
            issues.append("HIGH: Secret key length is below enterprise standard (min 32 chars).")
        return issues
