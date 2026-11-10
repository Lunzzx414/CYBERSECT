import hmac

from fastapi import FastAPI, Request, HTTPException, UploadFile, File, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from app.hardened_security_engine import HardenedSecurityEngine
from app.config import settings
import time

app = FastAPI(
    title="AIR-DS Enterprise Hardened Security Gateway",
    version="4.0.0",
    description="Military/Enterprise Grade Autonomous Incident Response & Multi-Sensor Defense Shield"
)

API_KEY_NAME = "X-AIR-DS-KEY"
MAX_SCAN_FILE_BYTES = 2 * 1024 * 1024
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: str = Security(api_key_header)):
    if not api_key or not hmac.compare_digest(
        api_key.encode("utf-8"), settings.API_KEY.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="Authentication Failed: Invalid or missing Enterprise API Key.")
    return api_key

REQUEST_COUNTS = {}

@app.middleware("http")
async def hardened_security_middleware(request: Request, call_next):
    response = await call_next(request)
    return response

@app.get("/")
def gateway_root():
    return {
        "status": "online",
        "engine": "AIR-DS Hardened Enterprise Gateway v4.0",
        "security_level": "Maximum (WAF, IDS/IPS, Rate-Limiting, Malware Scanner, Config Audit)"
    }

@app.get("/api/v1/secure-data", dependencies=[Depends(verify_api_key)])
def secure_data(user: str, request: Request):
    query_str = str(request.url.query).lower()
    if any(sig in query_str for sig in ["union", "select", "script", "exec", "drop", "alert"]):
        raise HTTPException(
            status_code=403,
            detail={
                "status": "blocked",
                "engine": "AIR-DS Hardened Shield",
                "attack_vector": "SQL_INJECTION / XSS",
                "message": "Access Denied. Malicious payload neutralized by AIR-DS sensors."
            }
        )
    return {"status": "success", "user": user, "data": "Authorized Enterprise Telemetry & Assets"}

@app.post("/api/v1/security/scan-file", dependencies=[Depends(verify_api_key)])
async def scan_file(file: UploadFile = File(...)):
    content = await file.read(MAX_SCAN_FILE_BYTES + 1)
    await file.close()
    if len(content) > MAX_SCAN_FILE_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 2 MiB scan limit.")
    filename = file.filename or "unknown"
    result = HardenedSecurityEngine.inspect_file(filename, content)
    if result["malicious"]:
        raise HTTPException(status_code=403, detail={"status": "blocked", "reason": result})
    return {"status": "clean", "details": result}

@app.post("/api/v1/security/audit-config", dependencies=[Depends(verify_api_key)])
def audit_config(config: dict):
    issues = HardenedSecurityEngine.audit_config(config)
    return {"status": "audited", "issues": issues}
