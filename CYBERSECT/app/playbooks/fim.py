import hashlib
from datetime import datetime, timezone

def calculate_file_hash(file_path: str) -> str:
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"

def verify_realtime_integrity(file_path: str, baseline_hash: str) -> dict:
    current_hash = calculate_file_hash(file_path)
    tampered = (current_hash != baseline_hash and current_hash != "FILE_NOT_FOUND")
    return {
        "file": file_path,
        "current_hash": current_hash,
        "tamper_detected": tampered,
        "severity": "CRITICAL" if tampered else "INFO",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def audit_critical_files(file_paths: list[str], known_baselines: dict[str, str]) -> list[dict]:
    anomalies = []
    for path in file_paths:
        res = verify_realtime_integrity(path, known_baselines.get(path, ""))
        if res["tamper_detected"]:
            anomalies.append({
                "file": path,
                "severity": "HIGH",
                "message": "File hash mismatch detected! Possible tampering or unauthorized modification.",
                "timestamp": res["timestamp"]
            })
    return anomalies
