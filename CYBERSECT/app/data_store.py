import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from app.config import settings


THREAT_INTEL_DB_NAME = "threat_intel.sqlite3"
ATTACK_HISTORY_DB_NAME = "attack_history.sqlite3"


def threat_intel_path() -> Path:
    return settings.DATA_DIR / THREAT_INTEL_DB_NAME


def attack_history_path() -> Path:
    return settings.DATA_DIR / ATTACK_HISTORY_DB_NAME


def _connect(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_databases() -> None:
    settings.DATA_DIR.mkdir(parents=True, exist_ok=True)

    with _connect(threat_intel_path()) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS intel_sources (
                source TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                record_count INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS cisa_kev (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT NOT NULL DEFAULT '',
                product TEXT NOT NULL DEFAULT '',
                vulnerability_name TEXT NOT NULL DEFAULT '',
                date_added TEXT NOT NULL DEFAULT '',
                short_description TEXT NOT NULL DEFAULT '',
                required_action TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                known_ransomware_campaign_use TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'CISA KEV',
                imported_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_cisa_kev_vendor
                ON cisa_kev(vendor_project, product);
            CREATE TABLE IF NOT EXISTS exploitdb_records (
                exploit_id TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                published_date TEXT NOT NULL DEFAULT '',
                author TEXT NOT NULL DEFAULT '',
                exploit_type TEXT NOT NULL DEFAULT '',
                platform TEXT NOT NULL DEFAULT '',
                cve_codes TEXT NOT NULL DEFAULT '',
                source_url TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'Exploit-DB metadata',
                imported_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS malware_indicators (
                sha256 TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL DEFAULT '',
                family TEXT NOT NULL DEFAULT '',
                file_type TEXT NOT NULL DEFAULT '',
                tags TEXT NOT NULL DEFAULT '',
                imported_at TEXT NOT NULL,
                PRIMARY KEY (sha256, source)
            );
            CREATE INDEX IF NOT EXISTS idx_malware_indicators_sha256
                ON malware_indicators(sha256);
            """
        )

    with _connect(attack_history_path()) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS attack_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                category TEXT NOT NULL,
                rule TEXT NOT NULL,
                request_sha256 TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_attack_events_timestamp
                ON attack_events(timestamp DESC);
            """
        )


def record_attack(
    *,
    client_ip: str,
    method: str,
    path: str,
    category: str,
    rule: str,
    request_sha256: str,
) -> None:
    with _connect(attack_history_path()) as connection:
        connection.execute(
            """
            INSERT INTO attack_events
                (timestamp, client_ip, method, path, category, rule, request_sha256)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(timezone.utc).isoformat(),
                client_ip,
                method[:16],
                path[:512],
                category[:64],
                rule[:128],
                request_sha256,
            ),
        )
        connection.execute(
            """
            DELETE FROM attack_events
            WHERE id NOT IN (
                SELECT id FROM attack_events ORDER BY id DESC LIMIT 10000
            )
            """
        )


def recent_attacks(limit: int = 100) -> list[Dict[str, Any]]:
    bounded_limit = max(1, min(limit, 500))
    with _connect(attack_history_path()) as connection:
        rows = connection.execute(
            """
            SELECT id, timestamp, client_ip, method, path, category, rule, request_sha256
            FROM attack_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def count_threat_intel_records() -> Dict[str, Any]:
    with _connect(threat_intel_path()) as connection:
        counts = {
            "cisa_kev": connection.execute("SELECT COUNT(*) FROM cisa_kev").fetchone()[0],
            "exploitdb_metadata": connection.execute(
                "SELECT COUNT(*) FROM exploitdb_records"
            ).fetchone()[0],
            "malware_indicators": connection.execute(
                "SELECT COUNT(DISTINCT sha256) FROM malware_indicators"
            ).fetchone()[0],
        }
        sources = [
            dict(row)
            for row in connection.execute(
                "SELECT source, description, updated_at, record_count "
                "FROM intel_sources ORDER BY source"
            ).fetchall()
        ]
    return {"counts": counts, "sources": sources}


def find_malware_indicator(sha256: str) -> Optional[Dict[str, Any]]:
    with _connect(threat_intel_path()) as connection:
        row = connection.execute(
            """
            SELECT sha256, source, first_seen, family, file_type, tags
            FROM malware_indicators
            WHERE sha256 = ?
            ORDER BY source
            LIMIT 1
            """,
            (sha256.lower(),),
        ).fetchone()
    return dict(row) if row else None


def search_cisa_kev(cve_id: str) -> Optional[Dict[str, Any]]:
    with _connect(threat_intel_path()) as connection:
        row = connection.execute(
            """
            SELECT cve_id, vendor_project, product, vulnerability_name,
                   date_added, short_description, required_action, due_date,
                   known_ransomware_campaign_use, source
            FROM cisa_kev
            WHERE cve_id = ?
            """,
            (cve_id.upper(),),
        ).fetchone()
    return dict(row) if row else None


def import_records(
    *,
    source: str,
    description: str,
    table: str,
    records: Iterable[Dict[str, Any]],
    columns: tuple[str, ...],
    primary_key: tuple[str, ...],
) -> int:
    allowed_tables = {"cisa_kev", "exploitdb_records", "malware_indicators"}
    if table not in allowed_tables:
        raise ValueError(f"Unsupported threat-intelligence table: {table}")

    materialized_records = list(records)
    now = datetime.now(timezone.utc).isoformat()
    full_columns = columns + ("source", "imported_at")
    placeholders = ", ".join("?" for _ in full_columns)
    updates = ", ".join(
        f"{column}=excluded.{column}"
        for column in columns
        if column not in primary_key
    )
    conflict = ", ".join(primary_key)
    statement = (
        f"INSERT INTO {table} ({', '.join(full_columns)}) "
        f"VALUES ({placeholders}) ON CONFLICT ({conflict}) DO UPDATE SET "
        f"{updates}, source=excluded.source, imported_at=excluded.imported_at"
    )
    values = [
        tuple(record.get(column, "") for column in columns) + (source, now)
        for record in materialized_records
    ]

    with _connect(threat_intel_path()) as connection:
        connection.executemany(statement, values)
        if table == "malware_indicators":
            count = connection.execute(
                "SELECT COUNT(*) FROM malware_indicators WHERE source = ?", (source,)
            ).fetchone()[0]
        else:
            count = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        connection.execute(
            """
            INSERT INTO intel_sources (source, description, updated_at, record_count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(source) DO UPDATE SET
                description=excluded.description,
                updated_at=excluded.updated_at,
                record_count=excluded.record_count
            """,
            (source, description, now, count),
        )
    return len(materialized_records)

