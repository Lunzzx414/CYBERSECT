import re
import hashlib
from typing import Dict, Any, List

class MultiSensorEngine:
    @staticmethod
    def inspect_payload(query: str, headers: dict) -> Dict[str, Any]:
        signatures = {
            "SQL_INJECTION": re.compile(r"('|\bOR\b|\bUNION\b|\bSELECT\b|--|%27)", re.IGNORECASE),
            "XSS": re.compile(r"(<script\b[^>]*>|javascript:|onerror=)", re.IGNORECASE),
            "PATH_TRAVERSAL": re.compile(r"(\.\./|\.\.\\|/etc/passwd)", re.IGNORECASE),
            "RCE": re.compile(r"(\bexec\b|\beval\b|system\(|passthru\()", re.IGNORECASE)
        }
        for vector, pattern in signatures.items():
            if pattern.search(query) or pattern.search(str(headers)):
                return {"threat_detected": True, "vector": vector, "confidence": 0.98}
        return {"threat_detected": False}

    @staticmethod
    def inspect_file_content(file_path: str, content: bytes) -> Dict[str, Any]:
        file_hash = hashlib.sha256(content).hexdigest()
        known_malicious_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb924": "Malware.Trojan.Generic",
            "8f4c29b1029481a7bcf89104bf7c8911": "Backdoor.Python.ReverseShell"
        }
        
        is_malicious = file_hash in known_malicious_hashes
        threat_name = known_malicious_hashes.get(file_hash, "Clean")
        
        # Heuristic checks for suspicious code inside files
        suspicious_keywords = [b"eval(", b"exec(", b"subprocess.Popen", b"os.system(", b"base64.b64decode"]
        heuristic_hit = any(kw in content for kw in suspicious_keywords)
        
        return {
            "file_path": file_path,
            "sha256": file_hash,
            "malicious": is_malicious or heuristic_hit,
            "threat_classification": threat_name if is_malicious else ("Suspicious.Heuristic" if heuristic_hit else "Clean"),
            "timestamp": "2026-03-30T00:00:00Z"
        }

    @staticmethod
    def audit_system_configuration(config_data: dict) -> List[Dict[str, Any]]:
        findings = []
        if config_data.get("debug") is True:
            findings.append({"severity": "HIGH", "issue": "Debug mode enabled in production configuration."})
        if config_data.get("allowed_hosts") == "*":
            findings.append({"severity": "MEDIUM", "issue": "Wildcard allowed_hosts exposes service to host header injection."})
        if not config_data.get("secret_key") or len(config_data.get("secret_key", "")) < 16:
            findings.append({"severity": "CRITICAL", "issue": "Weak or missing secret key in configuration."})
        return findings
