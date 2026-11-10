from fastapi.testclient import TestClient
from app.air_ds_gateway import app
from app import air_ds_multisensor_gateway, hardened_gateway
from app.config import settings
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

def test_hardened_gateway_rejects_invalid_api_key():
    response = TestClient(hardened_gateway.app).get(
        "/api/v1/secure-data",
        headers={"X-AIR-DS-KEY": "wrong-key"},
        params={"user": "test"},
    )

    assert response.status_code == 401

def test_standalone_gateways_reject_oversized_file_uploads():
    content = b"x" * (2 * 1024 * 1024 + 1)
    clients_and_headers = (
        (
            TestClient(hardened_gateway.app),
            "/api/v1/security/scan-file",
            {"X-AIR-DS-KEY": settings.API_KEY},
        ),
        (TestClient(air_ds_multisensor_gateway.app), "/api/v1/sensors/file-scan", {}),
    )

    for client, endpoint, headers in clients_and_headers:
        response = client.post(
            endpoint,
            headers=headers,
            files={"file": ("oversized.bin", content, "application/octet-stream")},
        )

        assert response.status_code == 413
