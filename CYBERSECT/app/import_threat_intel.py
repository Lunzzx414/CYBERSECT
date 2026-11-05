import argparse
import csv
import io
import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Dict, Iterable
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.data_store import import_records, initialize_databases


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MAX_FEED_BYTES = 32 * 1024 * 1024
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def _read_feed_file(path: Path) -> bytes:
    if path.stat().st_size > MAX_FEED_BYTES:
        raise ValueError(f"Feed exceeds the {MAX_FEED_BYTES // (1024 * 1024)} MiB import limit.")
    return path.read_bytes()


def _fetch_cisa_kev() -> bytes:
    request = Request(
        CISA_KEV_URL,
        headers={"User-Agent": "AIR-DS-Defensive-Intel-Importer/1.0"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            data = response.read(MAX_FEED_BYTES + 1)
    except (OSError, URLError) as error:
        raise ValueError(f"Unable to download the official CISA KEV feed: {error}") from error
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("CISA KEV feed exceeds the 32 MiB import limit.")
    return data


def import_cisa_kev(data: bytes) -> int:
    try:
        payload = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("The CISA KEV file is not valid UTF-8 JSON.") from error
    if not isinstance(payload, dict):
        raise ValueError("The JSON file is not a CISA KEV catalog.")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise ValueError("The JSON file is not a CISA KEV catalog.")

    records = []
    for item in vulnerabilities:
        if not isinstance(item, dict):
            continue
        cve_id = str(item.get("cveID", "")).upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
            continue
        records.append(
            {
                "cve_id": cve_id,
                "vendor_project": str(item.get("vendorProject", "")),
                "product": str(item.get("product", "")),
                "vulnerability_name": str(item.get("vulnerabilityName", "")),
                "date_added": str(item.get("dateAdded", "")),
                "short_description": str(item.get("shortDescription", "")),
                "required_action": str(item.get("requiredAction", "")),
                "due_date": str(item.get("dueDate", "")),
                "known_ransomware_campaign_use": str(item.get("knownRansomwareCampaignUse", "")),
            }
        )
    if not records:
        raise ValueError("No valid CVE records were found in the CISA KEV feed.")

    return import_records(
        source="CISA Known Exploited Vulnerabilities",
        description=f"Official CISA KEV catalog; feed date {payload.get('dateReleased', 'unknown')}.",
        table="cisa_kev",
        records=records,
        columns=(
            "cve_id",
            "vendor_project",
            "product",
            "vulnerability_name",
            "date_added",
            "short_description",
            "required_action",
            "due_date",
            "known_ransomware_campaign_use",
        ),
        primary_key=("cve_id",),
    )


def _normalize_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")


def _read_csv_records(data: bytes) -> Iterable[Dict[str, str]]:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise ValueError("CSV feed must use UTF-8 encoding.") from error
    return csv.DictReader(io.StringIO(text))


def import_exploitdb_csv(data: bytes) -> int:
    reader = _read_csv_records(data)
    headers = {_normalize_header(header) for header in (reader.fieldnames or [])}
    if not {"id", "description"}.issubset(headers):
        raise ValueError("Expected an Exploit-DB metadata CSV with id and description columns.")

    records = []
    for raw_item in reader:
        item = {_normalize_header(key): (value or "").strip() for key, value in raw_item.items() if key}
        exploit_id = item.get("id", "").strip()
        if not exploit_id.isdigit():
            continue
        records.append(
            {
                "exploit_id": exploit_id,
                "description": item.get("description", "")[:1000],
                "published_date": item.get("date", "")[:32],
                "author": item.get("author", "")[:256],
                "exploit_type": item.get("type", "")[:64],
                "platform": item.get("platform", "")[:128],
                "cve_codes": item.get("codes", "")[:256],
                "source_url": f"https://www.exploit-db.com/exploits/{exploit_id}",
            }
        )
    if not records:
        raise ValueError("No Exploit-DB metadata records were found in the CSV.")

    return import_records(
        source="Exploit-DB metadata",
        description="Exploit-DB metadata only; exploit payloads and code are not imported.",
        table="exploitdb_records",
        records=records,
        columns=(
            "exploit_id",
            "description",
            "published_date",
            "author",
            "exploit_type",
            "platform",
            "cve_codes",
            "source_url",
        ),
        primary_key=("exploit_id",),
    )


def import_malwarebazaar_csv(data: bytes) -> int:
    reader = _read_csv_records(data)
    headers = {_normalize_header(header) for header in (reader.fieldnames or [])}
    if "sha256_hash" not in headers and "sha256" not in headers:
        raise ValueError("Expected a MalwareBazaar CSV with sha256_hash or sha256 column.")

    records = []
    for raw_item in reader:
        item = {_normalize_header(key): (value or "").strip() for key, value in raw_item.items() if key}
        sha256 = item.get("sha256_hash") or item.get("sha256", "")
        if not SHA256_PATTERN.fullmatch(sha256):
            continue
        records.append(
            {
                "sha256": sha256.lower(),
                "first_seen": item.get("first_seen_utc", item.get("first_seen", ""))[:64],
                "family": item.get("signature", item.get("family", ""))[:256],
                "file_type": item.get("file_type_guess", item.get("file_type", ""))[:128],
                "tags": item.get("tags", "")[:512],
            }
        )
    if not records:
        raise ValueError("No valid SHA-256 malware indicators were found in the CSV.")

    return import_records(
        source="abuse.ch MalwareBazaar",
        description="MalwareBazaar SHA-256 metadata only; malware samples are not imported.",
        table="malware_indicators",
        records=records,
        columns=("sha256", "first_seen", "family", "file_type", "tags"),
        primary_key=("sha256", "source"),
    )


def import_feed(source: str, data: bytes) -> int:
    if source == "cisa-kev":
        return import_cisa_kev(data)
    if source == "exploitdb":
        return import_exploitdb_csv(data)
    if source == "malwarebazaar":
        return import_malwarebazaar_csv(data)
    raise ValueError(f"Unsupported feed source: {source}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import public vulnerability/exploit/malware metadata into local SQLite."
    )
    parser.add_argument(
        "--source",
        choices=("cisa-kev", "exploitdb", "malwarebazaar"),
        required=True,
    )
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("--file", type=Path, help="Local JSON/CSV export to import.")
    input_group.add_argument(
        "--fetch",
        action="store_true",
        help="Fetch the official CISA KEV catalog. Supported only for cisa-kev.",
    )
    args = parser.parse_args(argv)

    if args.source == "cisa-kev" and args.file is None and not args.fetch:
        parser.error("Use --fetch or provide --file for cisa-kev.")
    if args.source != "cisa-kev" and args.fetch:
        parser.error("Only the official CISA KEV feed supports --fetch.")
    if args.source != "cisa-kev" and args.file is None:
        parser.error("Provide a local export with --file for this source.")

    try:
        data = _fetch_cisa_kev() if args.fetch else _read_feed_file(args.file)
        initialize_databases()
        count = import_feed(args.source, data)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"Import failed: {error}", file=sys.stderr)
        return 1

    print(f"Imported or updated {count} records from {args.source}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
