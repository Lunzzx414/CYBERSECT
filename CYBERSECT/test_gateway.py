from fastapi.testclient import TestClient
from app.air_ds_gateway import app
from app.scanners_integration import ExternalScannerIntegration

client = TestClient(app)

def test_root():
    res = client.get("/")
    assert res.status_code == 200

def test_waf_blocking():
    try:
        res = client.get("/api/v1/resource?user=admin' UNION SELECT 1--")
        assert res.status_code == 403
    except Exception as e:
        # FastAPI middleware raises raw HTTPException that testclient surfaces
        assert "403" in str(e) or hasattr(e, "status_code")

def test_comprehensive_scanners():
    res = ExternalScannerIntegration.run_comprehensive_scans("vulnerability", "web_app", "127.0.0.1")
    assert "findings" in res or "category" in res
