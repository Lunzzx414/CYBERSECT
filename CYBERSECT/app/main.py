import asyncio
import hashlib
import hmac
import os
import re
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from fastapi import Depends, FastAPI, File, HTTPException, Security, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field, SecretStr
from app.config import settings
from app.data_store import (
    count_threat_intel_records,
    find_malware_indicator,
    initialize_databases,
    recent_attacks,
    search_cisa_kev,
)
from app.database_static_analyzer import (
    MAX_DATABASE_BYTES,
    analyze_sqlite_database,
    analyze_sqlite_path,
)
from app.enterprise_integrations import EnterpriseSecurityAggregator
from app.geolocation import enrich_attack_geolocation, geolocation_status
from app.hardened_security_engine import HardenedSecurityEngine
from app.proxy_sensor import ProxySecuritySensor
from app.scanners_integration import ExternalScannerIntegration
from app.credentialed_audits import audit_smb_shares, audit_ssh_patches

app = FastAPI(
    title="AIR-DS Enterprise Security Decision Engine",
    version="3.5.0",
    description="Automated Incident Response & Deep Learning Defense Shield - Enterprise Edition",
)

DASHBOARD_PATH = Path(__file__).parent / "dashboard" / "index.html"
DASHBOARD_MAP_PATH = Path(__file__).parent / "dashboard" / "worldmap.jpg"

initialize_databases()

app.add_middleware(ProxySecuritySensor)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Authentication & RBAC API Key Header
API_KEY_NAME = "X-AIR-DS-KEY"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def verify_api_key(api_key: Optional[str] = Security(api_key_header)):
    if not api_key or not hmac.compare_digest(
        api_key.encode("utf-8"), settings.API_KEY.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key"
        )
    return api_key

RAW_LOG_BUFFER: List[Dict[str, Any]] = []
INCIDENT_STORE: List[Dict[str, Any]] = []
FIM_BASELINES: Dict[str, str] = {
    "/app/main.py": "8f4c29b1029481a7bcf89104bf7c8911",
    "/etc/shadow": "e3b0c44298fc1c149afbf4c8996fb924",
}

class AlertPayload(BaseModel):
    source: str
    attack_type: str
    severity: str
    source_ip: str
    target_asset: str
    signature: Optional[str] = None  # HMAC validation for asset isolation

class RawTelemetryPayload(BaseModel):
    source_name: str
    log_data: str

class FIMCheckRequest(BaseModel):
    file_path: str
    current_hash: str
    trigger_mode: str

class DNNAnomalyRequest(BaseModel):
    cpu_usage: float = Field(..., ge=0.0, le=100.0)
    gpu_usage: float = Field(..., ge=0.0, le=100.0)
    ram_usage: float = Field(..., ge=0.0, le=100.0)
    network_pps: float = Field(..., ge=0.0)

class MalwareHashCheckRequest(BaseModel):
    file_hash: str

class CVELookupRequest(BaseModel):
    cve_id: str

class ScannerRequest(BaseModel):
    target: str

class SafeNetworkScanRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=64)
    profile: Literal["discovery", "basic", "advanced", "non_credentialed"] = "basic"
    ports: List[int] = Field(default_factory=list, max_length=8)

class SafeNmapAuditRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=64)
    ports: List[int] = Field(default_factory=list, max_length=8)

class SSHAuditRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=64)
    username: str = Field(..., min_length=1, max_length=128)
    identity_file: str = Field(..., min_length=1, max_length=512)

class SMBAuditRequest(BaseModel):
    target: str = Field(..., min_length=1, max_length=64)
    username: str = Field(..., min_length=1, max_length=128)
    password: SecretStr
    domain: str = Field(default="", max_length=128)

class EndpointFileEntry(BaseModel):
    path: str = Field(..., min_length=1, max_length=1024)
    sha256: str = Field(..., pattern=r"^[a-fA-F0-9]{64}$")
    size: int = Field(..., ge=0, le=50 * 1024 * 1024)

class EndpointReportRequest(BaseModel):
    platform: str = Field(..., min_length=1, max_length=64)
    scan_time: str = Field(..., min_length=1, max_length=64)
    file_count: int = Field(..., ge=0, le=10000)
    files: List[EndpointFileEntry] = Field(default_factory=list, max_length=10000)
    baseline: Optional[Dict[str, Any]] = None

@app.get("/")
def read_root():
    return {
        "status": "online",
        "engine": "AIR-DS Enterprise Decision Engine",
        "mode": "Active Defense & Threat Intel Integrated",
        "version": "3.5.0"
    }

@app.get("/dashboard", include_in_schema=False)
def read_dashboard():
    return FileResponse(DASHBOARD_PATH)

@app.get("/dashboard/worldmap.jpg", include_in_schema=False)
def read_dashboard_map():
    return FileResponse(DASHBOARD_MAP_PATH, media_type="image/jpeg")

@app.get("/api/v1/incidents", dependencies=[Depends(verify_api_key)])
async def get_incidents():
    return {"incidents": INCIDENT_STORE[:100]}

@app.get("/api/v1/scanners/capabilities", dependencies=[Depends(verify_api_key)])
async def scanner_capabilities():
    nmap_available = shutil.which("nmap") is not None
    raw_socket_privileges = hasattr(os, "geteuid") and os.geteuid() == 0
    return {
        "network_discovery": {"status": "available", "detail": "Built-in private network discovery; max 256 addresses."},
        "os_identification": {"status": "available" if nmap_available and raw_socket_privileges else "limited", "detail": "Nmap OS fingerprinting requires raw-socket privileges; otherwise only service hints are returned."},
        "safe_configuration_checks": {"status": "available", "detail": "Read-only SSH, HTTP header, and SMB signing/protocol observations."},
        "safe_nmap_audit": {"status": "available" if nmap_available else "needs_setup", "detail": "Nmap with a fixed safe script allowlist; no exploit, brute-force, or intrusive scripts."},
        "active_vulnerability_scans": {"status": "not_implemented", "detail": "Exploit and plugin vulnerability tests are not implemented."},
        "ssh_audit": {"status": "available" if shutil.which("ssh") else "needs_setup", "detail": "Requires OpenSSH client, a key under server ~/.ssh, and strict known_hosts enrollment."},
        "smb_audit": {"status": "available" if shutil.which("smbclient") else "needs_setup", "detail": "Requires smbclient and credentials for an authorized IPv4 host."},
        "named_vulnerability_probes": {"status": "not_implemented", "detail": "Badlock, Shellshock, DROWN, and Intel AMT are not actively probed."},
        "endpoint_agent": {"status": "available", "detail": "Windows/Linux Python agent; explicit roots and local baseline required."},
    }

@app.get("/api/v1/security/attack-history", dependencies=[Depends(verify_api_key)])
async def get_attack_history(limit: int = 100):
    try:
        attacks = await asyncio.to_thread(recent_attacks, limit)
        enriched_attacks = await asyncio.to_thread(enrich_attack_geolocation, attacks)
        location_status = await asyncio.to_thread(geolocation_status)
        return {"attacks": enriched_attacks, "geolocation": location_status}
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(
            status_code=503,
            detail="Attack-history database is unavailable.",
        ) from error

@app.get("/api/v1/threat-intel/summary", dependencies=[Depends(verify_api_key)])
async def get_threat_intelligence_summary():
    try:
        return await asyncio.to_thread(count_threat_intel_records)
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(
            status_code=503,
            detail="Threat-intelligence database is unavailable.",
        ) from error

@app.get("/api/v1/threat-intel/cve/{cve_id}", dependencies=[Depends(verify_api_key)])
async def get_known_exploited_cve(cve_id: str):
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id, flags=re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Invalid CVE identifier.")
    try:
        record = await asyncio.to_thread(search_cisa_kev, cve_id)
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(
            status_code=503,
            detail="Threat-intelligence database is unavailable.",
        ) from error
    if record is None:
        raise HTTPException(status_code=404, detail="CVE is not present in the local CISA KEV catalog.")
    return record

@app.post("/api/v1/threat-intel/cve", dependencies=[Depends(verify_api_key)])
async def lookup_known_exploited_cve(payload: CVELookupRequest):
    return await get_known_exploited_cve(payload.cve_id)

@app.post("/api/v1/telemetry/raw", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(verify_api_key)])
async def ingest_raw_telemetry(payload: RawTelemetryPayload):
    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": payload.source_name,
        "data": payload.log_data,
    }
    RAW_LOG_BUFFER.insert(0, log_entry)
    if len(RAW_LOG_BUFFER) > 100:
        RAW_LOG_BUFFER.pop()
    return {"status": "indexed", "total_buffered": len(RAW_LOG_BUFFER)}

@app.get("/api/v1/telemetry/raw", dependencies=[Depends(verify_api_key)])
async def get_raw_telemetry():
    return {"raw_logs": RAW_LOG_BUFFER}

@app.post("/api/v1/detect/dnn-anomaly", dependencies=[Depends(verify_api_key)])
async def evaluate_dnn_resource_anomaly(metrics: DNNAnomalyRequest):
    # Non-blocking async calculation
    def _compute_reconstruction(cpu, gpu, ram, net):
        return (cpu * 0.0004) + (gpu * 0.0003) + (ram * 0.0002) + (net * 0.001)

    reconstruction_error = await asyncio.to_thread(
        _compute_reconstruction,
        metrics.cpu_usage,
        metrics.gpu_usage,
        metrics.ram_usage,
        metrics.network_pps
    )
    is_anomaly = reconstruction_error > 0.05
    return {
        "model": "weighted-threshold-resource-scorer",
        "reconstruction_mse_loss": round(reconstruction_error, 5),
        "threshold": 0.05,
        "status": "ANOMALY_DETECTED" if is_anomaly else "NORMAL",
        "action_triggered": "Playbook: Isolate Resource Host & Deep Scan" if is_anomaly else None,
    }

@app.post("/api/v1/detect/fim-audit", dependencies=[Depends(verify_api_key)])
async def evaluate_file_integrity(audit: FIMCheckRequest):
    if audit.trigger_mode not in ["hash_change", "weekly", "monthly"]:
        raise HTTPException(status_code=400, detail="Invalid automation trigger mode.")

    expected_hash = FIM_BASELINES.get(audit.file_path, "UNKNOWN_BASELINE")
    tampered = (
        expected_hash != "UNKNOWN_BASELINE"
        and expected_hash != audit.current_hash
    )

    response_action = "None - File Intact"
    if tampered:
        if audit.trigger_mode == "hash_change":
            response_action = "Playbook: Immediate Container Quarantine & Golden Image Revert"
        else:
            response_action = f"Playbook: Scheduled [{audit.trigger_mode.upper()}] Audit Mismatch - Alert SOC Lead"

    return {
        "file_path": audit.file_path,
        "trigger_mode": audit.trigger_mode,
        "tamper_detected": tampered,
        "playbook_response": response_action,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/v1/security/scan-file", dependencies=[Depends(verify_api_key)])
async def scan_file(file: UploadFile = File(...)):
    content = await file.read(2 * 1024 * 1024 + 1)
    await file.close()
    if len(content) > 2 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds the 2 MiB scan limit.")

    result = HardenedSecurityEngine.inspect_file(file.filename or "upload", content)
    if result["malicious"]:
        raise HTTPException(
            status_code=403,
            detail={"status": "blocked", "details": result},
        )
    return {"status": "clean", "details": result}

@app.post("/api/v1/security/analyze-sqlite", dependencies=[Depends(verify_api_key)])
async def analyze_sqlite_file(file: UploadFile = File(...)):
    contents = await file.read(MAX_DATABASE_BYTES + 1)
    await file.close()
    try:
        return await asyncio.to_thread(analyze_sqlite_database, contents)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.get("/api/v1/security/analyze-sqlite/live", dependencies=[Depends(verify_api_key)])
async def analyze_configured_sqlite_database():
    if settings.SQLITE_DATABASE_PATH is None:
        raise HTTPException(
            status_code=503,
            detail="Set SQLITE_DATABASE_PATH to the SQLite database file before running a live audit.",
        )
    try:
        return await asyncio.to_thread(analyze_sqlite_path, settings.SQLITE_DATABASE_PATH)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/v1/security/audit-config", dependencies=[Depends(verify_api_key)])
async def audit_security_config(config: dict):
    return {
        "status": "audited",
        "issues": HardenedSecurityEngine.audit_config(config),
    }

@app.post("/api/v1/threat-intel/malware-hash", dependencies=[Depends(verify_api_key)])
async def check_malware_hash(payload: MalwareHashCheckRequest):
    if not re.fullmatch(r"[a-fA-F0-9]{64}", payload.file_hash):
        raise HTTPException(status_code=400, detail="Expected a 64-character SHA-256 hash.")
    try:
        indicator = await asyncio.to_thread(find_malware_indicator, payload.file_hash)
    except (sqlite3.Error, OSError) as error:
        raise HTTPException(
            status_code=503,
            detail="Threat-intelligence database is unavailable.",
        ) from error
    if indicator is None:
        return {
            "hash": payload.file_hash.lower(),
            "threat_intel": "Unknown",
            "source": "No matching local indicator; this is not a clean verdict.",
        }
    return {
        "hash": indicator["sha256"],
        "threat_intel": "Malicious",
        "family": indicator["family"] or "Unknown",
        "source": indicator["source"],
        "first_seen": indicator["first_seen"],
        "file_type": indicator["file_type"],
        "tags": indicator["tags"],
    }

@app.post("/api/v1/scanners/nmap", dependencies=[Depends(verify_api_key)])
async def trigger_nmap(payload: ScannerRequest):
    try:
        return await ExternalScannerIntegration.run_nmap_scan(payload.target)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/v1/scanners/network", dependencies=[Depends(verify_api_key)])
async def run_network_discovery(payload: SafeNetworkScanRequest):
    try:
        ports = payload.ports or None
        if payload.profile == "advanced" and ports is None:
            raise ValueError("Advanced profile requires explicit ports.")
        return await ExternalScannerIntegration.run_safe_network_scan(
            payload.target,
            ports,
            profile=payload.profile,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/v1/scanners/nmap-safe", dependencies=[Depends(verify_api_key)])
async def run_safe_nmap_audit(payload: SafeNmapAuditRequest):
    try:
        return await ExternalScannerIntegration.run_safe_nmap_audit(
            payload.target,
            payload.ports or None,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/v1/scanners/audit/ssh", dependencies=[Depends(verify_api_key)])
async def run_ssh_audit(payload: SSHAuditRequest):
    try:
        return await audit_ssh_patches(payload.target, payload.username, payload.identity_file)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/v1/scanners/audit/smb", dependencies=[Depends(verify_api_key)])
async def run_smb_audit(payload: SMBAuditRequest):
    try:
        return await audit_smb_shares(
            payload.target,
            payload.username,
            payload.password.get_secret_value(),
            payload.domain,
        )
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error

@app.post("/api/v1/security/analyze-endpoint-report", dependencies=[Depends(verify_api_key)])
async def analyze_endpoint_report(payload: EndpointReportRequest):
    if payload.file_count != len(payload.files):
        raise HTTPException(status_code=400, detail="Endpoint report file_count does not match files.")
    matches = []
    for file_hash in sorted({entry.sha256.lower() for entry in payload.files}):
        try:
            indicator = await asyncio.to_thread(find_malware_indicator, file_hash)
        except (sqlite3.Error, OSError) as error:
            raise HTTPException(status_code=503, detail="Threat-intelligence database is unavailable.") from error
        if indicator:
            matches.append({"sha256": file_hash, "threat_intel": "Malicious", "family": indicator.get("family") or "Unknown"})
    baseline = payload.baseline or {}
    baseline_status = baseline.get("status")
    if baseline_status not in {"changed", "initial", "unchanged"}:
        baseline_result = {"status": "not_provided"}
    else:
        baseline_result = {
            "status": baseline_status,
            "heuristic": True,
            "description": "Agent-reported baseline change is heuristic and is not a ransomware verdict.",
        }
    return {
        "platform": payload.platform,
        "scan_time": payload.scan_time,
        "files_analyzed": len(payload.files),
        "malware_hash_matches": matches,
        "agent_baseline_signal": baseline_result,
        "verdict": "Known malicious hash match" if matches else "No local hash match; unknown files are not proven clean",
        "analysis_limit": "File names and hashes only; no file content or network scanning is performed by this endpoint.",
    }

@app.post("/api/v1/scanners/sqlmap", dependencies=[Depends(verify_api_key)])
async def trigger_sqlmap(payload: ScannerRequest):
    raise HTTPException(
        status_code=501,
        detail="Active SQL injection testing is disabled; no scan was run.",
    )

@app.post("/api/v1/scanners/nikto", dependencies=[Depends(verify_api_key)])
async def trigger_nikto(payload: ScannerRequest):
    raise HTTPException(
        status_code=501,
        detail="Active web vulnerability testing is disabled; no scan was run.",
    )

@app.post("/api/v1/alert", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_api_key)])
async def receive_frontend_alert(alert: AlertPayload):
    # Bug 2 Fix: Verify HMAC signature when critical action is requested to prevent unauthorized asset isolation
    if alert.severity == "CRITICAL":
        expected_sig = hmac.new(
            settings.SECRET_KEY.encode(),
            f"{alert.target_asset}:{alert.severity}".encode(),
            hashlib.sha256
        ).hexdigest()
        if not alert.signature or not hmac.compare_digest(alert.signature, expected_sig):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security Violation: Invalid or missing HMAC signature for CRITICAL isolation action."
            )

    if alert.severity == "HIGH":
        action = "Recommendation: block source IP"
    elif alert.severity == "CRITICAL":
        action = "Recommendation: isolate target asset"
    else:
        action = "Recommendation: apply rate limiting"
    mitre = EnterpriseSecurityAggregator.get_mitre_tactics(alert.attack_type)

    incident = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": alert.source,
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "target_asset": alert.target_asset,
        "mitre_tactic": mitre['tactic'],
        "mitre_technique": mitre['technique'],
        "action_recommendation": action,
        "status": "Incident logged; no enforcement integration is configured"
    }
    INCIDENT_STORE.insert(0, incident)
    if len(INCIDENT_STORE) > 500:
        INCIDENT_STORE.pop()
    return {
        "status": "logged",
        "total_incidents": len(INCIDENT_STORE),
        "action_taken": action,
        "execution_status": "recommendation_only",
        "mitre_mapping": mitre
    }
