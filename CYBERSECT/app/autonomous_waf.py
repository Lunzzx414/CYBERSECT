from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import re

from app.alerting import send_alert_async

app = FastAPI(title="Autonomous Target Web App")

SQLI_PATTERNS = re.compile(r"('|\bOR\b|\bUNION\b|\bSELECT\b|--)", re.IGNORECASE)

@app.middleware("http")
async def air_ds_waf_sensor_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    query_string = request.url.query
    
    if SQLI_PATTERNS.search(query_string):
        await send_alert_async({
            "source": "AIR-DS Autonomous WAF Sensor",
            "attack_type": "SQL_INJECTION",
            "severity": "HIGH",
            "source_ip": client_ip,
            "target_asset": request.url.path,
        })

        return JSONResponse(
            status_code=403,
            content={"detail": "WAF Block: Autonomous Threat Detected!"},
        )
        
    response = await call_next(request)
    return response

@app.get("/")
def home():
    return {"status": "Secure Gateway Active"}

@app.get("/login")
def login(user: str):
    return {"status": "success", "user": user}
