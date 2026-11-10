from fastapi import FastAPI, Request, HTTPException
import logging
import re

app = FastAPI(title="AIR-DS Integrated Enterprise Gateway")
LOGGER = logging.getLogger(__name__)

# Signature WAF yang tertanam langsung pada Gateway AIR-DS
THREAT_PATTERN = re.compile(r"('|\bOR\b|\bUNION\b|\bSELECT\b|--|%27|<script>|\.\./|etc/passwd|cat\b|exec\b)", re.IGNORECASE)

@app.middleware("http")
async def air_ds_built_in_sensor(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    query_params = str(request.url.query)
    path = request.url.path
    
    # Deteksi otonom berbasis signature security bawaan AIR-DS
    if THREAT_PATTERN.search(query_params) or THREAT_PATTERN.search(path):
        LOGGER.warning(
            "Blocked request matching a gateway signature (client_ip=%s path=%r). "
            "No IP block or session revocation is configured.",
            client_ip,
            path,
        )
        
        raise HTTPException(
            status_code=403, 
            detail="AIR-DS Defense Shield: Access Denied. Autonomous Attack Signature Detected."
        )
        
    response = await call_next(request)
    return response

@app.get("/")
def gateway_home():
    return {"status": "AIR-DS Gateway Online", "protected_endpoints": ["/api/v1/resource"]}

@app.get("/api/v1/resource")
def get_resource(user: str):
    return {"status": "success", "data": f"Confidential corporate data for {user}"}
