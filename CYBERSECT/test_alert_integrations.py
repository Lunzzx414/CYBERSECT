from fastapi.testclient import TestClient

from app import autonomous_waf, target_web


def test_target_web_logs_blocked_test_payload(monkeypatch):
    received_alerts = []
    monkeypatch.setattr(target_web, "send_alert", received_alerts.append)

    response = TestClient(target_web.app).get(
        "/login",
        params={"user": "' OR 1=1--"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "SQL Injection detected and blocked!"
    assert len(received_alerts) == 1
    assert received_alerts[0]["attack_type"] == "SQL_INJECTION"
    assert received_alerts[0]["target_asset"] == "web-login-portal"


def test_autonomous_waf_returns_valid_block_response_and_logs_alert(monkeypatch):
    received_alerts = []

    async def record_alert(payload):
        received_alerts.append(payload)

    monkeypatch.setattr(autonomous_waf, "send_alert_async", record_alert)
    response = TestClient(autonomous_waf.app).get(
        "/login",
        params={"user": "UNION SELECT"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "WAF Block: Autonomous Threat Detected!"
    assert len(received_alerts) == 1
    assert received_alerts[0]["attack_type"] == "SQL_INJECTION"
