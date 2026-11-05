import asyncio
import hashlib
import html
import json
import logging
import re
import sqlite3
from email import policy
from email.parser import BytesParser
from typing import Any, Dict, Iterable, Optional, Tuple
from urllib.parse import unquote_plus

from app.data_store import find_malware_indicator, record_attack
from app.hardened_security_engine import HardenedSecurityEngine


LOGGER = logging.getLogger(__name__)
MAX_REQUEST_BYTES = 17 * 1024 * 1024
MAX_REQUEST_MESSAGES = 2048
SQL_INJECTION_SIGNATURES = (
    re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
    re.compile(
        r"\b(?:insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+(?:table|database)|alter\s+table)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:or|and)\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?", re.IGNORECASE),
    re.compile(r"(?:'|%27)\s*(?:or|and)\b", re.IGNORECASE),
    re.compile(r"(?:'|%27)\s*(?:--|#|/\*)|/\*[\s\S]{0,80}\*/", re.IGNORECASE),
    re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
)
XSS_SIGNATURE = re.compile(
    r"(?:<script\b|javascript\s*:|onerror\s*=|onload\s*=|<svg\b)",
    re.IGNORECASE,
)


def _multipart_parts(
    content_type: str,
    body: bytes,
) -> Tuple[list[str], list[Tuple[str, bytes]]]:
    try:
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: "
            + content_type.encode("latin-1", errors="replace")
            + b"\r\nMIME-Version: 1.0\r\n\r\n"
            + body
        )
    except (ValueError, TypeError):
        return [], []
    if not message.is_multipart():
        return [], []

    fields = []
    files = []
    for part in message.iter_parts():
        if part.get_content_disposition() != "form-data":
            continue
        content = part.get_payload(decode=True)
        if content is None:
            continue
        filename = part.get_filename()
        if filename:
            files.append((part.get_filename() or "upload", content))
            if filename.lower().endswith((".sql", ".txt", ".json", ".xml", ".csv")):
                fields.append(content.decode("utf-8", errors="ignore"))
        else:
            fields.append(content.decode("utf-8", errors="ignore"))
    return fields, files


def _inspect_file(
    filename: str,
    content: bytes,
) -> Optional[Dict[str, str]]:
    file_hash = hashlib.sha256(content).hexdigest()
    indicator = find_malware_indicator(file_hash)
    if indicator is not None:
        family = indicator["family"] or "known malware indicator"
        return {
            "category": "MALWARE_HASH",
            "rule": f"sha256:{file_hash}",
            "message": f"Upload matched malware indicator ({family}) from {indicator['source']}.",
        }

    heuristic = HardenedSecurityEngine.inspect_file(filename, content)
    if heuristic["malicious"]:
        return {
            "category": "SUSPICIOUS_FILE",
            "rule": f"sha256:{file_hash}",
            "message": "Upload matched a local static malware heuristic.",
        }
    return None


def _inspect(
    *,
    path: str,
    query: str,
    method: str,
    headers: Dict[bytes, bytes],
    body: bytes,
) -> Optional[Dict[str, str]]:
    content_type = headers.get(b"content-type", b"").decode("latin-1", errors="replace")
    scan_text = _decode_scan_text(f"{path}?{query}")
    inspectable_headers = (
        (name, value)
        for name, value in headers.items()
        if name in {b"user-agent", b"referer", b"cookie"}
        or name.startswith(b"x-")
    )
    scan_text += " " + " ".join(
        _decode_scan_text(
            name.decode("latin-1", errors="replace")
            + " "
            + value.decode("latin-1", errors="replace")
        )
        for name, value in inspectable_headers
    )

    uploads = []
    if content_type.lower().startswith("multipart/form-data"):
        form_fields, uploads = _multipart_parts(content_type, body)
        scan_text += " " + " ".join(_decode_scan_text(field) for field in form_fields)
    else:
        scan_text += " " + _decode_scan_text(body.decode("utf-8", errors="ignore"))

    for signature in SQL_INJECTION_SIGNATURES:
        if signature.search(scan_text):
            return {
                "category": "SQL_INJECTION",
                "rule": signature.pattern,
                "message": "Request matched a high-confidence SQL-injection signature.",
            }

    if XSS_SIGNATURE.search(scan_text):
        return {
            "category": "XSS",
            "rule": XSS_SIGNATURE.pattern,
            "message": "Request matched a high-confidence cross-site-scripting signature.",
        }

    content_type_lower = content_type.lower()
    if not uploads and (
        content_type_lower.startswith("application/octet-stream")
        or content_type_lower.startswith("application/x-executable")
    ):
        uploads.append(("binary upload", body))

    for filename, contents in uploads:
        result = _inspect_file(filename, contents)
        if result is not None:
            return result
    return None


def _decode_scan_text(value: str) -> str:
    return html.unescape(unquote_plus(value))


async def _send_json(send: Any, status_code: int, payload: Dict[str, Any]) -> None:
    encoded = json.dumps(payload).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(encoded)).encode("ascii")),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": encoded})


class ProxySecuritySensor:
    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {
            name.lower(): value
            for name, value in scope.get("headers", [])
        }
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                await _send_json(send, 400, {"detail": "Invalid Content-Length header."})
                return
            if declared_length < 0 or declared_length > MAX_REQUEST_BYTES:
                await _send_json(send, 413, {"detail": "Request body exceeds the 17 MiB proxy limit."})
                return

        messages = []
        body_chunks = []
        body_size = 0
        more_body = True
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            messages.append(message)
            body_chunk = message.get("body", b"")
            body_size += len(body_chunk)
            if body_size > MAX_REQUEST_BYTES:
                await _send_json(send, 413, {"detail": "Request body exceeds the 17 MiB proxy limit."})
                return
            body_chunks.append(body_chunk)
            more_body = message.get("more_body", False)
            if len(messages) > MAX_REQUEST_MESSAGES:
                await _send_json(send, 413, {"detail": "Request contains too many body chunks."})
                return

        target = scope.get("raw_path", scope.get("path", "").encode("utf-8"))
        path = scope.get("path", "/")
        query = scope.get("query_string", b"").decode("latin-1")
        method = scope.get("method", "GET")
        body = b"".join(body_chunks)

        try:
            result = await asyncio.to_thread(
                _inspect,
                path=path,
                query=query,
                method=method,
                headers=headers,
                body=body,
            )
        except sqlite3.Error:
            LOGGER.exception("Proxy sensor could not query local threat intelligence.")
            await _send_json(
                send,
                503,
                {"detail": "Proxy threat-intelligence database is unavailable; request was not forwarded."},
            )
            return

        if result is not None:
            digest = hashlib.sha256(target + b"?" + scope.get("query_string", b"") + body).hexdigest()
            client = scope.get("client")
            client_ip = client[0] if client else "unknown"
            try:
                await asyncio.to_thread(
                    record_attack,
                    client_ip=client_ip,
                    method=method,
                    path=path,
                    category=result["category"],
                    rule=result["rule"],
                    request_sha256=digest,
                )
            except sqlite3.Error:
                LOGGER.exception("Proxy sensor blocked a threat but could not persist attack history.")
                await _send_json(
                    send,
                    503,
                    {"detail": "Proxy detected a threat but could not persist its audit record."},
                )
                return

            await _send_json(
                send,
                403,
                {
                    "detail": {
                        "status": "blocked",
                        "engine": "AIR-DS Proxy Sensor",
                        "category": result["category"],
                        "message": result["message"],
                    }
                },
            )
            return

        message_index = 0

        async def replay_receive() -> Dict[str, Any]:
            nonlocal message_index
            if message_index < len(messages):
                message = messages[message_index]
                message_index += 1
                return message
            return await receive()

        await self.app(scope, replay_receive, send)
