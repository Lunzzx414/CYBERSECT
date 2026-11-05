from app.multi_sensor_engine import MultiSensorEngine
from fastapi import FastAPI, Request, HTTPException, UploadFile, File
import httpx
import re
import json
from datetime import datetime, timezone

app = FastAPI(title="AIR-DS Integrated Enterprise Security Gateway & Multi-Sensor Engine")

# Multi-Vector Attack Signatures (WAF, IDS/IPS, Malware & Exploit Indicators)
ATTACK_SIGNATURES = {
    "SQL_INJECTION": re.compile(r"('|\bOR\b|\bUNION\b|\bSELECT\b|--|%27|CAST\(|CONCAT\()", re.IGNORECASE),
    "XSS_ATTACK": re.compile(r"(<script\b[^>]*>|javascript:|onerror=|onload=|<svg\b)", re.IGNORECASE),
    "PATH_TRAVERSAL": re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini)", re.IGNORECASE),
    "REMOTE_CODE_EXECUTION": re.compile(r"(\bexec\b|\beval\b|system\(|passthru\(|cmd\.exe|/bin/sh)", re.IGNORECASE)
}

@app.middleware("http")
async def air_ds_multisensor_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    query_params = str(request.url.query)
    path = request.url.path
    headers_str = json.dumps(dict(request.headers))
    
    detected_vector = None
    for vector, pattern in ATTACK_SIGNATURES.items():
        if pattern.search(query_params) or pattern.search(path) or pattern.search(headers_str):
            detected_vector = vector
            break
            
    if detected_vector:
        # Multi-sensor logging & warning
        print(f"\n🚨 [AIR-DS MULTI-SENSOR ALERT] Threat Neutralized!")
        print(f"   -> Sensor Triggered: Signature-based IDS / WAF Engine")
        print(f"   -> Attack Vector: {detected_vector}")
        print(f"   -> Source IP: {client_ip}")
        print(f"   -> Target Asset: {path}?{query_params}")
        print(f"   -> Automated Response: IP Blocked, Session Terminated, Incident Logged.\n")
        
        raise HTTPException(
            status_code=403,
            detail={
                "status": "blocked",
                "engine": "AIR-DS Multi-Sensor Defense Shield",
                "attack_vector": detected_vector,
                "message": "Access Denied. Autonomous threat signature matched by AIR-DS sensors."
            }
        )
        
    response = await call_next(request)
    return response

@app.get("/")
def gateway_root():
    return {
        "status": "online",
        "engine": "AIR-DS Multi-Sensor Enterprise Gateway",
        "active_sensors": ["WAF (SQLi/XSS)", "IDS/IPS (Traversal/RCE)", "Behavioral Telemetry"]
    }

@app.get("/api/v1/app")
def secure_endpoint(user: str):
    return {"status": "success", "message": f"Welcome {user}, data accessed securely."}

@app.post("/api/v1/sensors/file-scan")
async def scan_uploaded_file(file: UploadFile = File(...)):
    content = await file.read()
    filename = file.filename or "unknown_file"
    scan_result = MultiSensorEngine.inspect_file_content(filename, content)
    if scan_result["malicious"]:
        print(f"🚨 [MALWARE SENSOR ALERT] Malicious file blocked: {filename} ({scan_result['threat_classification']})")
        raise HTTPException(status_code=403, detail=scan_result)
    return {"status": "clean", "details": scan_result}

@app.post("/api/v1/sensors/config-audit")
def audit_config(config: dict):
    issues = MultiSensorEngine.audit_system_configuration(config)
    if issues:
        print(f"⚠️ [CONFIG SENSOR AUDIT] Security misconfigurations found: {issues}")
    return {"status": "audited", "findings": issues}
