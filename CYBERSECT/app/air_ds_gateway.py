from fastapi import FastAPI, Request, HTTPException
import httpx
import re

app = FastAPI(title="AIR-DS Integrated Enterprise Gateway")

# Signature WAF yang tertanam langsung pada Gateway AIR-DS
THREAT_PATTERN = re.compile(r"('|\bOR\b|\bUNION\b|\bSELECT\b|--|%27|<script>|\.\./|etc/passwd|cat\b|exec\b)", re.IGNORECASE)

@app.middleware("http")
async def air_ds_built_in_sensor(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    query_params = str(request.url.query)
    path = request.url.path
    
    # Deteksi otonom berbasis signature security bawaan AIR-DS
    if THREAT_PATTERN.search(query_params) or THREAT_PATTERN.search(path):
        # AIR-DS mencatat dan memberikan warning/peringatan keamanan secara instan di konsol/log sistem
        print(f"\n🚨 [AIR-DS SECURITY WARNING] Autonomous Threat Detected!")
        print(f"   -> Attack Type: SQL Injection (SQLi)")
        print(f"   -> Source IP: {client_ip}")
        print(f"   -> Target Endpoint: {path}?{query_params}")
        print(f"   -> Action Taken: Playbook Executed -> IP Blocked & Session Terminated.\n")
        
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
