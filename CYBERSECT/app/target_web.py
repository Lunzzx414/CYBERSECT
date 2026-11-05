from fastapi import FastAPI, HTTPException, Request

from app.alerting import send_alert

app = FastAPI(title="Vulnerable Target Web App")

@app.get("/")
def home():
    return {"message": "Welcome to Target Web App", "endpoints": ["/login?user=admin", "/api/data?id=1"]}

@app.get("/login")
def login(user: str, request: Request, password: str = ""):
    # Simulasi deteksi SQLi atau Brute Force
    if "'" in user or "OR" in user.upper() or "UNION" in user.upper():
        # Kirim alert otomatis ke AIR-DS
        send_alert({
            "source": "Vulnerable Target Web App",
            "attack_type": "SQL_INJECTION",
            "severity": "HIGH",
            "source_ip": request.client.host if request.client else "unknown",
            "target_asset": "web-login-portal",
        })
        raise HTTPException(status_code=403, detail="SQL Injection detected and blocked!")
    
    return {"status": "success", "user": user}
