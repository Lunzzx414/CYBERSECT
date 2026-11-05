import csv
import hashlib
import io
import json
from types import SimpleNamespace

from fastapi.testclient import TestClient

from app.config import settings
from app.data_store import (
    attack_history_path,
    initialize_databases,
    recent_attacks,
    record_attack,
    threat_intel_path,
)
from app import geolocation
from app.import_threat_intel import (
    import_cisa_kev,
    import_exploitdb_csv,
    import_malwarebazaar_csv,
)
from app.main import app


client = TestClient(app)
AUTH_HEADERS = {"X-AIR-DS-KEY": settings.API_KEY}


def _use_data_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "DATA_DIR", tmp_path)
    initialize_databases()


def test_proxy_blocks_encoded_sql_injection_and_persists_fingerprint(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)

    response = client.get("/?search=%27%20OR%201%3D1--")

    assert response.status_code == 403
    assert response.json()["detail"]["category"] == "SQL_INJECTION"
    events = recent_attacks()
    assert len(events) == 1
    assert events[0]["category"] == "SQL_INJECTION"
    assert events[0]["request_sha256"] == hashlib.sha256(
        b"/?" + b"search=%27%20OR%201%3D1--"
    ).hexdigest()
    assert events[0]["path"] == "/"
    assert threat_intel_path() != attack_history_path()


def test_proxy_inspects_header_payloads_for_xss(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)

    response = client.get("/", headers={"X-Search": "<svg onload=alert(1)>"})

    assert response.status_code == 403
    assert response.json()["detail"]["category"] == "XSS"
    assert recent_attacks()[0]["category"] == "XSS"


def test_proxy_allows_normal_browser_wildcard_accept_header(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)

    response = client.get(
        "/favicon.ico",
        headers={
            "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8"
        },
    )

    assert response.status_code == 404
    assert recent_attacks() == []


def test_proxy_blocks_multipart_injection_but_replays_benign_upload(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)

    blocked = client.post(
        "/api/v1/security/scan-file",
        headers=AUTH_HEADERS,
        data={"description": "' OR 1=1--"},
        files={"file": ("note.txt", b"ordinary file contents", "text/plain")},
    )
    benign = client.post(
        "/api/v1/security/scan-file",
        headers=AUTH_HEADERS,
        files={"file": ("note.txt", b"ordinary file contents", "text/plain")},
    )

    assert blocked.status_code == 403
    assert blocked.json()["detail"]["category"] == "SQL_INJECTION"
    assert benign.status_code == 200
    assert benign.json()["status"] == "clean"
    assert len(recent_attacks()) == 1


def test_imported_cisa_catalog_is_searchable_from_protected_api(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)
    feed = {
        "dateReleased": "2026-01-01T00:00:00.000Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "shortDescription": "Remote code execution vulnerability.",
                "requiredAction": "Apply updates.",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            },
            None,
        ],
    }

    assert import_cisa_kev(json.dumps(feed).encode()) == 1
    response = client.post(
        "/api/v1/threat-intel/cve",
        headers=AUTH_HEADERS,
        json={"cve_id": "cve-2021-44228"},
    )

    assert response.status_code == 200
    assert response.json()["vendor_project"] == "Apache"
    assert response.json()["product"] == "Log4j"


def test_malwarebazaar_hash_blocks_upload_and_unknown_hash_is_not_clean(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)
    sample = b"known sample bytes"
    digest = hashlib.sha256(sample).hexdigest()
    csv_buffer = io.StringIO()
    writer = csv.DictWriter(csv_buffer, fieldnames=["sha256_hash", "signature"])
    writer.writeheader()
    writer.writerow({"sha256_hash": digest, "signature": "Example.Family"})
    assert import_malwarebazaar_csv(csv_buffer.getvalue().encode()) == 1

    upload_response = client.post(
        "/api/v1/security/scan-file",
        headers=AUTH_HEADERS,
        files={"file": ("sample.bin", sample, "application/octet-stream")},
    )
    known_hash_response = client.post(
        "/api/v1/threat-intel/malware-hash",
        headers=AUTH_HEADERS,
        json={"file_hash": digest},
    )
    unknown_hash_response = client.post(
        "/api/v1/threat-intel/malware-hash",
        headers=AUTH_HEADERS,
        json={"file_hash": "0" * 64},
    )

    assert upload_response.status_code == 403
    assert upload_response.json()["detail"]["category"] == "MALWARE_HASH"
    assert known_hash_response.json()["threat_intel"] == "Malicious"
    assert known_hash_response.json()["family"] == "Example.Family"
    assert unknown_hash_response.json()["threat_intel"] == "Unknown"
    assert "not a clean verdict" in unknown_hash_response.json()["source"]


def test_importers_reject_malformed_or_empty_feeds(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)

    try:
        import_cisa_kev(b"[]")
    except ValueError as error:
        assert "not a CISA KEV catalog" in str(error)
    else:
        raise AssertionError("Malformed CISA input must be rejected.")

    try:
        import_malwarebazaar_csv(b"sha256_hash,signature\ninvalid,Example\n")
    except ValueError as error:
        assert "No valid SHA-256" in str(error)
    else:
        raise AssertionError("CSV without valid indicators must be rejected.")


def test_exploitdb_import_stores_metadata_only(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)
    feed = (
        "id,file,description,date,author,type,platform,port,codes\n"
        '12345,exploits/12345.py,"Example vulnerability metadata",2025-01-02,Researcher,webapps,PHP,80,CVE-2025-1234\n'
    ).encode()

    assert import_exploitdb_csv(feed) == 1
    response = client.get(
        "/api/v1/threat-intel/summary",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["counts"]["exploitdb_metadata"] == 1


def test_threat_intel_and_attack_history_apis_require_authentication():
    summary_response = client.get("/api/v1/threat-intel/summary")
    history_response = client.get("/api/v1/security/attack-history")
    cve_response = client.post(
        "/api/v1/threat-intel/cve",
        json={"cve_id": "CVE-2021-44228"},
    )

    assert summary_response.status_code == 401
    assert history_response.status_code == 401
    assert cve_response.status_code == 401


def test_real_attack_history_is_enriched_from_local_geoip_database(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)
    database_path = tmp_path / "GeoLite2-City.mmdb"
    database_path.touch()
    monkeypatch.setattr(settings, "GEOLITE2_CITY_DB_PATH", database_path)

    city_record = SimpleNamespace(
        country=SimpleNamespace(names={"en": "United States"}, iso_code="US"),
        continent=SimpleNamespace(names={"en": "North America"}, code="NA"),
        city=SimpleNamespace(names={"en": "Mountain View"}),
        location=SimpleNamespace(latitude=37.4, longitude=-122.1),
    )
    monkeypatch.setattr(
        geolocation,
        "_reader",
        lambda _path: SimpleNamespace(
            metadata=lambda: SimpleNamespace(database_type="GeoLite2-City"),
            city=lambda _ip: city_record,
        ),
    )
    geolocation._lookup_cached.cache_clear()
    record_attack(
        client_ip="8.8.8.8",
        method="GET",
        path="/",
        category="SQL_INJECTION",
        rule="test",
        request_sha256="0" * 64,
    )

    response = client.get(
        "/api/v1/security/attack-history",
        headers=AUTH_HEADERS,
    )
    location = response.json()["attacks"][0]["location"]

    assert response.status_code == 200
    assert response.json()["geolocation"]["status"] == "ready"
    assert location == {
        "status": "located",
        "country": "United States",
        "country_code": "US",
        "continent": "North America",
        "continent_code": "NA",
        "city": "Mountain View",
        "latitude": 37.4,
        "longitude": -122.1,
    }


def test_private_addresses_are_never_geolocated():
    assert geolocation.locate_ip("127.0.0.1")["status"] == "non_public"
    assert geolocation.locate_ip("192.168.1.10")["status"] == "non_public"


def test_online_geolocation_resolves_public_ip_and_country_metadata(monkeypatch):
    monkeypatch.setattr(settings, "GEOLOCATION_PROVIDER", "ipwhois")
    geolocation._lookup_online_cached.cache_clear()
    monkeypatch.setattr(
        geolocation.httpx,
        "get",
        lambda url, **kwargs: SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {
                "success": True,
                "country": "United States",
                "country_code": "US",
                "continent": "North America",
                "continent_code": "NA",
                "city": "Mountain View",
                "latitude": 37.4,
                "longitude": -122.1,
            },
        ),
    )

    location = geolocation.locate_ip("8.8.8.8")

    assert location == {
        "status": "located",
        "country": "United States",
        "country_code": "US",
        "continent": "North America",
        "continent_code": "NA",
        "city": "Mountain View",
        "latitude": 37.4,
        "longitude": -122.1,
    }
    assert geolocation.geolocation_status()["status"] == "ready"
    geolocation._lookup_online_cached.cache_clear()


def test_online_geolocation_failure_is_reported_as_unavailable(monkeypatch):
    monkeypatch.setattr(settings, "GEOLOCATION_PROVIDER", "ipwhois")
    geolocation._lookup_online_cached.cache_clear()
    monkeypatch.setattr(
        geolocation.httpx,
        "get",
        lambda _url, **_kwargs: (_ for _ in ()).throw(geolocation.httpx.TimeoutException("timed out")),
    )

    assert geolocation.locate_ip("8.8.4.4")["status"] == "unavailable"
    geolocation._lookup_online_cached.cache_clear()


def test_attack_history_reports_geolocation_not_configured(tmp_path, monkeypatch):
    _use_data_directory(tmp_path, monkeypatch)
    monkeypatch.setattr(settings, "GEOLOCATION_PROVIDER", "maxmind")
    monkeypatch.setattr(settings, "GEOLITE2_CITY_DB_PATH", None)
    record_attack(
        client_ip="127.0.0.1",
        method="GET",
        path="/",
        category="XSS",
        rule="test",
        request_sha256="1" * 64,
    )

    response = client.get(
        "/api/v1/security/attack-history",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["geolocation"]["status"] == "not_configured"
    assert response.json()["attacks"][0]["location"]["status"] == "non_public"


def test_geolocation_rejects_non_city_maxmind_database(tmp_path, monkeypatch):
    database_path = tmp_path / "GeoLite2-Country.mmdb"
    database_path.touch()
    monkeypatch.setattr(settings, "GEOLITE2_CITY_DB_PATH", database_path)
    monkeypatch.setattr(
        geolocation,
        "_reader",
        lambda _path: SimpleNamespace(metadata=lambda: SimpleNamespace(database_type="GeoLite2-Country")),
    )

    status = geolocation.geolocation_status()

    assert status["status"] == "unavailable"
    assert "not a City database" in status["message"]
