import sqlite3
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.database_static_analyzer import analyze_sqlite_database
from app.main import app


client = TestClient(app)
AUTH_HEADERS = {"X-AIR-DS-KEY": settings.API_KEY}


def test_api_key_loads_from_documented_environment_file(tmp_path, monkeypatch):
    monkeypatch.delenv("AIR_DS_API_KEY", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    env_file = tmp_path / ".env"
    database_path = tmp_path / "application.sqlite"
    env_file.write_text(
        "AIR_DS_API_KEY=test-configured-key\n"
        "SECRET_KEY=test-configured-secret\n"
        f"SQLITE_DATABASE_PATH={database_path}\n",
        encoding="utf-8",
    )
    configured = Settings(_env_file=env_file)

    assert configured.API_KEY == "test-configured-key"
    assert configured.SQLITE_DATABASE_PATH == database_path


def test_dashboard_is_served():
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AIR SOC" in response.text
    assert "SAFE NETWORK DISCOVERY" in response.text
    assert "Credentialed patch / SMB / SSH audit" in response.text
    assert "GLOBAL ATTACK MAP" in response.text
    assert "LIVE + SIMULATION" in response.text
    assert "SIMULATION ONLY" in response.text
    assert "198.51.100.11" in response.text
    assert "North Korea" in response.text
    assert 'viewBox="0 0 1097 768"' in response.text
    assert 'href="/dashboard/worldmap.jpg"' in response.text
    assert "PROXY COUNTRIES BY CONTINENT" in response.text
    assert "configured geolocation provider" in response.text
    assert "local GeoLite2 coordinates" not in response.text


def test_dashboard_world_map_asset_is_served():
    response = client.get("/dashboard/worldmap.jpg")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.content.startswith(b"\xff\xd8\xff")


def test_dashboard_route_keeps_backend_available():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "online"


def test_cors_allows_any_origin_without_cookie_credentials():
    origin = "https://dashboard.example"
    preflight = client.options(
        "/api/v1/incidents",
        headers={
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "x-air-ds-key",
        },
    )
    response = client.get("/", headers={"Origin": origin})

    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "*"
    assert "x-air-ds-key" in preflight.headers["access-control-allow-headers"].lower()
    assert response.headers["access-control-allow-origin"] == "*"
    assert "access-control-allow-credentials" not in response.headers


def test_dashboard_does_not_remove_api_key_protection():
    response = client.post(
        "/api/v1/detect/dnn-anomaly",
        json={
            "cpu_usage": 89.4,
            "gpu_usage": 78.2,
            "ram_usage": 91.0,
            "network_pps": 320.5,
        },
    )

    assert response.status_code == 401


def test_new_dashboard_apis_require_authentication():
    incidents_response = client.get("/api/v1/incidents")
    file_response = client.post(
        "/api/v1/security/scan-file",
        files={"file": ("readme.txt", b"ordinary text file", "text/plain")},
    )
    config_response = client.post("/api/v1/security/audit-config", json={})

    assert incidents_response.status_code == 401
    assert file_response.status_code == 401
    assert config_response.status_code == 401


def test_authenticated_dnn_and_fim_endpoints():
    dnn_response = client.post(
        "/api/v1/detect/dnn-anomaly",
        headers=AUTH_HEADERS,
        json={
            "cpu_usage": 89.4,
            "gpu_usage": 78.2,
            "ram_usage": 91.0,
            "network_pps": 320.5,
        },
    )
    fim_response = client.post(
        "/api/v1/detect/fim-audit",
        headers=AUTH_HEADERS,
        json={
            "file_path": "/app/main.py",
            "current_hash": "8f4c29b1029481a7bcf89104bf7c8911",
            "trigger_mode": "hash_change",
        },
    )

    assert dnn_response.status_code == 200
    assert dnn_response.json()["status"] == "ANOMALY_DETECTED"
    assert fim_response.status_code == 200
    assert fim_response.json()["tamper_detected"] is False


def test_authenticated_security_tools():
    file_response = client.post(
        "/api/v1/security/scan-file",
        headers=AUTH_HEADERS,
        files={"file": ("readme.txt", b"ordinary text file", "text/plain")},
    )
    config_response = client.post(
        "/api/v1/security/audit-config",
        headers=AUTH_HEADERS,
        json={"debug": True, "allowed_hosts": "*", "secret_key": "short"},
    )
    hash_response = client.post(
        "/api/v1/threat-intel/malware-hash",
        headers=AUTH_HEADERS,
        json={"file_hash": "0" * 64},
    )

    assert file_response.status_code == 200
    assert file_response.json()["status"] == "clean"
    assert config_response.status_code == 200
    assert len(config_response.json()["issues"]) == 3
    assert hash_response.status_code == 200
    assert hash_response.json()["threat_intel"] == "Unknown"


def test_safe_network_scanner_is_bounded_and_never_claims_vulnerability_findings():
    response = client.post(
        "/api/v1/scanners/network",
        headers=AUTH_HEADERS,
        json={"target": "127.0.0.1", "profile": "discovery"},
    )

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "completed"
    assert result["target"] == "127.0.0.1"
    assert result["os_identification"]["status"] == "not_performed"
    assert "no vulnerability tests" in result["scope"]
    assert "findings" not in result


def test_safe_network_scanner_rejects_public_hosts_and_unapproved_ports():
    public_target = client.post(
        "/api/v1/scanners/network",
        headers=AUTH_HEADERS,
        json={"target": "8.8.8.8", "profile": "basic"},
    )
    disallowed_port = client.post(
        "/api/v1/scanners/network",
        headers=AUTH_HEADERS,
        json={"target": "127.0.0.1", "profile": "advanced", "ports": [4444]},
    )
    advanced_without_ports = client.post(
        "/api/v1/scanners/network",
        headers=AUTH_HEADERS,
        json={"target": "127.0.0.1", "profile": "advanced"},
    )

    assert public_target.status_code == 400
    assert disallowed_port.status_code == 400
    assert advanced_without_ports.status_code == 400


def test_legacy_active_vulnerability_scanners_are_disabled_not_simulated():
    sqlmap_response = client.post(
        "/api/v1/scanners/sqlmap",
        headers=AUTH_HEADERS,
        json={"target": "https://example.invalid"},
    )
    nikto_response = client.post(
        "/api/v1/scanners/nikto",
        headers=AUTH_HEADERS,
        json={"target": "https://example.invalid"},
    )

    assert sqlmap_response.status_code == 501
    assert nikto_response.status_code == 501
    assert "no scan was run" in sqlmap_response.json()["detail"]


def test_sqlite_static_analyzer_reports_schema_findings_without_row_data(tmp_path):
    database_path = tmp_path / "audit.sqlite"
    connection = sqlite3.connect(database_path)
    connection.executescript(
        """
        CREATE TABLE parent (id INTEGER PRIMARY KEY);
        CREATE TABLE child (
            parent_id INTEGER REFERENCES parent(id),
            secret_value TEXT
        );
        INSERT INTO child VALUES (1, 'private-row-content');
        """
    )
    connection.close()

    report = analyze_sqlite_database(database_path.read_bytes())
    upload_response = client.post(
        "/api/v1/security/analyze-sqlite",
        headers=AUTH_HEADERS,
        files={
            "file": (
                "audit.sqlite",
                database_path.read_bytes(),
                "application/vnd.sqlite3",
            )
        },
    )
    serialized_report = str(report)

    assert report["status"] == "analyzed"
    assert report["summary"] == {
        "table_count": 2,
        "view_count": 0,
        "column_count": 3,
        "finding_count": 2,
    }
    assert any("no declared primary key" in item["issue"] for item in report["findings"])
    assert any("supporting index" in item["issue"] for item in report["findings"])
    assert "private-row-content" not in serialized_report
    assert "schema metadata only" in report["analysis_scope"]
    assert upload_response.status_code == 200
    assert upload_response.json()["summary"] == report["summary"]


def test_sqlite_static_analyzer_rejects_non_database_file():
    response = client.post(
        "/api/v1/security/analyze-sqlite",
        headers=AUTH_HEADERS,
        files={"file": ("not-a-database.sqlite", b"not a database", "application/octet-stream")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "The uploaded file is not a SQLite database."


def test_sqlite_static_analyzer_requires_authentication():
    response = client.post(
        "/api/v1/security/analyze-sqlite",
        files={"file": ("database.sqlite", b"not a database", "application/octet-stream")},
    )

    assert response.status_code == 401


def test_configured_live_sqlite_audit_is_read_only(tmp_path, monkeypatch):
    database_path = tmp_path / "live.sqlite"
    connection = sqlite3.connect(database_path)
    connection.execute("CREATE TABLE events (id INTEGER PRIMARY KEY, message TEXT)")
    connection.execute("INSERT INTO events VALUES (1, 'private-row-content')")
    connection.commit()
    connection.close()
    original_contents = database_path.read_bytes()
    monkeypatch.setattr(settings, "SQLITE_DATABASE_PATH", database_path)

    response = client.get(
        "/api/v1/security/analyze-sqlite/live",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["summary"]["table_count"] == 1
    assert "private-row-content" not in response.text
    assert database_path.read_bytes() == original_contents


def test_live_sqlite_audit_requires_a_configured_database(monkeypatch):
    monkeypatch.setattr(settings, "SQLITE_DATABASE_PATH", None)

    response = client.get(
        "/api/v1/security/analyze-sqlite/live",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 503


def test_alert_is_available_in_authenticated_incident_feed():
    source = "dashboard integration regression test"
    alert_response = client.post(
        "/api/v1/alert",
        headers=AUTH_HEADERS,
        json={
            "source": source,
            "source_ip": "192.0.2.10",
            "attack_type": "SQL_INJECTION",
            "target_asset": "test-asset",
            "severity": "HIGH",
        },
    )
    incidents_response = client.get("/api/v1/incidents", headers=AUTH_HEADERS)

    assert alert_response.status_code == 201
    assert alert_response.json()["execution_status"] == "recommendation_only"
    assert incidents_response.status_code == 200
    assert any(
        incident["source"] == source
        for incident in incidents_response.json()["incidents"]
    )
