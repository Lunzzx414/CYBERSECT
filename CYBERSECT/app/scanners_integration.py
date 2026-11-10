import asyncio
import hashlib
import ipaddress
import os
import shutil
import ssl
import struct
import time
from typing import Any
from xml.etree import ElementTree


SAFE_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8443)
MAX_SCAN_PORTS = 8
MAX_SCAN_HOSTS = 256
CONNECT_TIMEOUT_SECONDS = 0.6
PROBE_TIMEOUT_SECONDS = 1.2
MAX_CONCURRENT_PROBES = 32
NMAP_PROCESS_TIMEOUT_SECONDS = 120
NMAP_SAFE_SCRIPTS = (
    "ssh-hostkey,ssl-cert,ssl-enum-ciphers,ssl-dh-params,"
    "smb2-security-mode,smb-protocols,http-security-headers"
)
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    )
)
LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))
SERVICE_NAMES = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    445: "smb",
    3389: "rdp",
    8080: "http-alt",
    8443: "https-alt",
}


def _is_allowed_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return any(
        network.version == allowed.version and network.subnet_of(allowed)
        for allowed in (*ALLOWED_NETWORKS, *LOOPBACK_NETWORKS)
    )


def validate_private_targets(target: str) -> tuple[str, list[str]]:
    """Accept one private IP or a private subnet of at most 256 addresses."""
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
        else:
            address = ipaddress.ip_address(target)
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
    except ValueError as error:
        raise ValueError(
            "Use a private IP or private CIDR; hostnames and public addresses are not accepted."
        ) from error

    if not _is_allowed_network(network):
        raise ValueError("Only loopback, RFC1918, or IPv6 ULA targets can be scanned.")
    if network.num_addresses > MAX_SCAN_HOSTS:
        raise ValueError(f"Subnet exceeds the {MAX_SCAN_HOSTS}-address scan limit.")

    targets = [str(address) for address in network.hosts()]
    if not targets:
        raise ValueError("The target subnet contains no scannable host addresses.")
    return str(network) if "/" in target else targets[0], targets


async def _check_tcp_port(
    target: str,
    port: int,
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    async with semaphore:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=CONNECT_TIMEOUT_SECONDS,
            )
        except (OSError, asyncio.TimeoutError):
            return {"port": port, "service": SERVICE_NAMES[port], "state": "closed_or_filtered"}

        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return {"port": port, "service": SERVICE_NAMES[port], "state": "open"}


async def _read_limited(reader: asyncio.StreamReader, limit: int = 8192) -> bytes:
    chunks = bytearray()
    while len(chunks) < limit:
        chunk = await reader.read(min(1024, limit - len(chunks)))
        if not chunk:
            break
        chunks.extend(chunk)
        if b"\r\n\r\n" in chunks:
            break
    return bytes(chunks)


async def _probe_ssh(target: str, port: int) -> dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=PROBE_TIMEOUT_SECONDS
        )
        try:
            banner = await asyncio.wait_for(reader.readline(), timeout=PROBE_TIMEOUT_SECONDS)
        finally:
            writer.close()
            await writer.wait_closed()
    except (OSError, asyncio.TimeoutError, asyncio.LimitOverrunError, ValueError):
        return {"service": "ssh", "status": "no_banner"}

    text = banner[:256].decode("ascii", errors="replace").strip()
    findings = []
    if text.startswith("SSH-1."):
        findings.append(
            {
                "severity": "HIGH",
                "check": "ssh-legacy-protocol",
                "message": "The server advertises the obsolete SSH protocol version 1.",
                "recommendation": "Disable SSH protocol 1 and require SSH protocol 2.",
            }
        )
    os_hint = "Windows" if "OpenSSH_for_Windows" in text else None
    return {
        "service": "ssh",
        "status": "identified" if text else "no_banner",
        "banner": text,
        "os_hint": os_hint,
        "findings": findings,
    }


async def _probe_http(target: str, port: int, *, use_tls: bool) -> dict[str, Any]:
    context = None
    if use_tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                target,
                port,
                ssl=context,
                server_hostname=target if use_tls else None,
            ),
            timeout=PROBE_TIMEOUT_SECONDS,
        )
        request = (
            f"HEAD / HTTP/1.0\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        ).encode("ascii")
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT_SECONDS)
        response = await asyncio.wait_for(
            _read_limited(reader), timeout=PROBE_TIMEOUT_SECONDS
        )
        ssl_object = writer.get_extra_info("ssl_object")
        certificate = ssl_object.getpeercert(binary_form=True) if ssl_object else None
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    except (OSError, ssl.SSLError, asyncio.TimeoutError):
        return {"service": "https" if use_tls else "http", "status": "probe_failed"}

    lines = response.decode("latin-1", errors="replace").split("\r\n")
    status_line = lines[0][:256] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()[:512]

    required_headers = ["x-content-type-options", "content-security-policy", "x-frame-options"]
    if use_tls:
        required_headers.append("strict-transport-security")
    missing_headers = [header for header in required_headers if header not in headers]
    findings = []
    if missing_headers:
        findings.append(
            {
                "severity": "INFO",
                "check": "http-security-headers",
                "message": "The response did not include all commonly used browser security headers.",
                "evidence": missing_headers,
                "recommendation": "Review the headers against the application's intended browser policy.",
            }
        )

    result: dict[str, Any] = {
        "service": "https" if use_tls else "http",
        "status": "identified" if status_line.startswith("HTTP/") else "no_http_response",
        "status_line": status_line,
        "server_header": headers.get("server"),
        "missing_security_headers": missing_headers,
        "findings": findings,
    }
    if certificate:
        result["certificate_sha256"] = hashlib.sha256(certificate).hexdigest()
        result["certificate_validation"] = "not_performed; fingerprint only"
    return result


def _smb_negotiate_request() -> bytes:
    packet = bytearray(64)
    packet[:4] = b"\xfeSMB"
    struct.pack_into("<H", packet, 4, 64)  # SMB2 header size
    struct.pack_into("<H", packet, 12, 0)  # NEGOTIATE
    struct.pack_into("<H", packet, 14, 1)  # credit request
    struct.pack_into("<Q", packet, 24, 1)  # message id
    body = struct.pack(
        "<HHHHI16sIHH",
        36,
        5,
        1,
        0,
        0,
        b"AIR-DS-readonly".ljust(16, b"\x00"),
        0,
        0,
        0,
    )
    dialects = struct.pack("<5H", 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
    return bytes(packet) + body + dialects


async def _probe_smb(target: str, port: int = 445) -> dict[str, Any]:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=PROBE_TIMEOUT_SECONDS
        )
        request = _smb_negotiate_request()
        writer.write(b"\x00" + len(request).to_bytes(3, "big") + request)
        await asyncio.wait_for(writer.drain(), timeout=PROBE_TIMEOUT_SECONDS)
        length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=PROBE_TIMEOUT_SECONDS)
        length = int.from_bytes(length_bytes[1:], "big")
        if length < 68 or length > 65536:
            raise ValueError("Invalid SMB negotiate response length.")
        response = await asyncio.wait_for(reader.readexactly(length), timeout=PROBE_TIMEOUT_SECONDS)
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
    except (OSError, asyncio.TimeoutError, ValueError, asyncio.IncompleteReadError):
        return {"service": "smb", "status": "negotiate_failed"}

    if response[:4] != b"\xfeSMB":
        return {"service": "smb", "status": "unsupported_response"}
    security_mode = struct.unpack_from("<H", response, 66)[0]
    dialect = struct.unpack_from("<H", response, 68)[0]
    dialect_names = {
        0x0202: "SMB 2.0.2",
        0x0210: "SMB 2.1",
        0x0300: "SMB 3.0",
        0x0302: "SMB 3.0.2",
        0x0311: "SMB 3.1.1",
    }
    signing_enabled = bool(security_mode & 0x01)
    signing_required = bool(security_mode & 0x02)
    findings = []
    if not signing_enabled:
        findings.append(
            {
                "severity": "MEDIUM",
                "check": "smb-signing-disabled",
                "message": "The server did not advertise SMB message signing support.",
                "recommendation": "Review SMB signing policy for the server and its clients.",
            }
        )
    return {
        "service": "smb",
        "status": "negotiated",
        "dialect": dialect_names.get(dialect, f"unknown (0x{dialect:04x})"),
        "signing_enabled": signing_enabled,
        "signing_required": signing_required,
        "findings": findings,
    }


async def _probe_services(
    target: str,
    open_ports: list[int],
    semaphore: asyncio.Semaphore,
) -> list[dict[str, Any]]:
    probes = []
    for port in open_ports:
        if port == 22:
            probes.append(_probe_ssh(target, port))
        elif port in (80, 8080):
            probes.append(_probe_http(target, port, use_tls=False))
        elif port in (443, 8443):
            probes.append(_probe_http(target, port, use_tls=True))
        elif port == 445:
            probes.append(_probe_smb(target))
        else:
            probes.append(asyncio.sleep(0, result={"service": SERVICE_NAMES[port], "status": "port_only"}))

    async def limited_probe(probe):
        async with semaphore:
            return await probe

    return await asyncio.gather(*(limited_probe(probe) for probe in probes))


def _os_identification(services: list[dict[str, Any]]) -> dict[str, Any]:
    hints = sorted({service["os_hint"] for service in services if service.get("os_hint")})
    if hints:
        return {
            "status": "inferred",
            "hints": hints,
            "confidence": "low",
            "reason": "Service banners can suggest an operating system but do not verify it.",
        }
    return {
        "status": "not_performed",
        "reason": "TCP and service checks do not provide a reliable operating-system fingerprint.",
    }


async def _scan_host(
    target: str,
    selected_ports: list[int],
    semaphore: asyncio.Semaphore,
) -> dict[str, Any]:
    port_results = await asyncio.gather(
        *(_check_tcp_port(target, port, semaphore) for port in selected_ports)
    )
    open_ports = [result["port"] for result in port_results if result["state"] == "open"]
    services = await _probe_services(target, open_ports, semaphore)
    findings = [finding for service in services for finding in service.get("findings", [])]
    return {
        "target": target,
        "status": "responsive" if open_ports else "no_open_allowed_ports",
        "open_ports": open_ports,
        "ports": port_results,
        "services": services,
        "findings": findings,
        "os_identification": _os_identification(services),
    }


class ExternalScannerIntegration:
    @staticmethod
    async def run_safe_network_scan(
        target: str,
        ports: list[int] | None = None,
        *,
        profile: str = "basic",
    ) -> dict[str, Any]:
        normalized_target, targets = validate_private_targets(target)
        selected_ports = list(SAFE_PORTS if ports is None else ports)
        if not selected_ports or len(selected_ports) > MAX_SCAN_PORTS:
            raise ValueError(f"Select between 1 and {MAX_SCAN_PORTS} allowed TCP ports.")
        if len(set(selected_ports)) != len(selected_ports):
            raise ValueError("Duplicate ports are not allowed.")
        invalid_ports = sorted(set(selected_ports) - set(SAFE_PORTS))
        if invalid_ports:
            raise ValueError(
                f"Unsupported ports: {invalid_ports}. Allowed ports: {list(SAFE_PORTS)}."
            )

        started = time.monotonic()
        semaphore = asyncio.Semaphore(MAX_CONCURRENT_PROBES)
        hosts = await asyncio.gather(
            *(_scan_host(address, selected_ports, semaphore) for address in targets)
        )
        responsive_hosts = [host for host in hosts if host["open_ports"]]
        findings = [
            {"target": host["target"], **finding}
            for host in hosts
            for finding in host["findings"]
        ]
        result = {
            "tool": "AIR-DS bounded private-network discovery",
            "status": "completed",
            "profile": profile,
            "target": normalized_target,
            "host_count": len(targets),
            "responsive_host_count": len(responsive_hosts),
            "hosts": hosts,
            "findings": findings,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "checks": [
                "bounded TCP connection discovery",
                "read-only service banner and protocol negotiation",
                "safe HTTP response-header checks",
            ],
            "scope": (
                f"Private/loopback IP or subnet up to {MAX_SCAN_HOSTS} addresses; "
                "allowlisted TCP ports only; safe checks only, no exploit payloads, and no vulnerability tests."
            ),
        }
        if len(hosts) == 1:
            host = hosts[0]
            result.update(
                {
                    "open_ports": host["open_ports"],
                    "ports": host["ports"],
                    "services": host["services"],
                    "os_identification": host["os_identification"],
                }
            )
        return result

    @staticmethod
    async def run_safe_nmap_audit(target: str, ports: list[int] | None = None) -> dict[str, Any]:
        normalized_target, targets = validate_private_targets(target)
        selected_ports = list(SAFE_PORTS if ports is None else ports)
        if not selected_ports or len(selected_ports) > MAX_SCAN_PORTS:
            raise ValueError(f"Select between 1 and {MAX_SCAN_PORTS} allowed TCP ports.")
        if len(set(selected_ports)) != len(selected_ports):
            raise ValueError("Duplicate ports are not allowed.")
        invalid_ports = sorted(set(selected_ports) - set(SAFE_PORTS))
        if invalid_ports:
            raise ValueError(f"Unsupported ports: {invalid_ports}. Allowed ports: {list(SAFE_PORTS)}.")
        executable = shutil.which("nmap")
        if executable is None:
            raise ValueError("Nmap is not installed in the server environment.")

        arguments = [
            executable, "-n", "-Pn", "-sT", "-sV", "--version-light",
            "--script", NMAP_SAFE_SCRIPTS,
            "--script-timeout", "5s", "--host-timeout", "20s",
            "--max-retries", "1", "--max-hostgroup", "32", "-T3",
            "--open", "-p", ",".join(map(str, selected_ports)), "-oX", "-",
        ]
        os_fingerprint = hasattr(os, "geteuid") and os.geteuid() == 0
        if os_fingerprint:
            arguments[1:1] = ["-O", "--osscan-limit"]
        arguments.append(normalized_target)

        try:
            process = await asyncio.create_subprocess_exec(
                *arguments,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as error:
            raise ValueError("Nmap could not be started in the server environment.") from error
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=NMAP_PROCESS_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError as error:
            process.kill()
            await process.wait()
            raise ValueError("Safe Nmap audit timed out; no exploit script was run.") from error
        if process.returncode != 0:
            detail = stderr[:512].decode("utf-8", errors="replace").strip()
            raise ValueError(f"Safe Nmap audit failed: {detail or 'check server privileges and target scope'}")

        try:
            document = ElementTree.fromstring(stdout[:8 * 1024 * 1024])
        except ElementTree.ParseError as error:
            raise ValueError("Nmap returned an invalid or oversized XML report.") from error
        hosts = []
        for host_element in document.findall("host")[:MAX_SCAN_HOSTS]:
            address_element = host_element.find("address")
            address = address_element.get("addr") if address_element is not None else "unknown"
            status_element = host_element.find("status")
            host = {
                "target": address,
                "status": status_element.get("state", "unknown") if status_element is not None else "unknown",
                "os_matches": [
                    {"name": match.get("name", "unknown"), "accuracy": match.get("accuracy", "0")}
                    for match in host_element.findall("./os/osmatch")[:3]
                ],
                "ports": [],
            }
            for port_element in host_element.findall("./ports/port")[:MAX_SCAN_PORTS]:
                state_element = port_element.find("state")
                service_element = port_element.find("service")
                host["ports"].append({
                    "port": int(port_element.get("portid", "0")),
                    "protocol": port_element.get("protocol", "tcp"),
                    "state": state_element.get("state", "unknown") if state_element is not None else "unknown",
                    "service": service_element.get("name", "unknown") if service_element is not None else "unknown",
                    "product": service_element.get("product", "")[:128] if service_element is not None else "",
                    "version": service_element.get("version", "")[:64] if service_element is not None else "",
                    "safe_script_observations": [
                        {"script": script.get("id", "unknown"), "output": (script.get("output") or "")[:2048]}
                        for script in port_element.findall("script")[:16]
                    ],
                })
            hosts.append(host)
        return {
            "tool": "Nmap with fixed safe script allowlist",
            "status": "completed",
            "target": normalized_target,
            "host_count": len(targets),
            "hosts": hosts,
            "os_identification": "Nmap active OS fingerprinting performed" if os_fingerprint else "service version hints only; run with required raw-socket privileges for OS fingerprinting",
            "scripts": NMAP_SAFE_SCRIPTS.split(","),
            "scope": "Private/loopback/ULA targets up to 256 addresses; allowlisted TCP ports only; exploit, brute-force, intrusive, and arbitrary user-supplied scripts are excluded.",
        }

    @staticmethod
    async def run_nmap_scan(target: str) -> dict[str, Any]:
        return await ExternalScannerIntegration.run_safe_network_scan(target)

    @staticmethod
    async def run_sqlmap_scan(_url: str) -> dict[str, Any]:
        return {
            "tool": "sqlmap",
            "status": "disabled",
            "reason": "Active injection testing is not available in this safe scanner.",
        }

    @staticmethod
    async def run_nikto_scan(_target: str) -> dict[str, Any]:
        return {
            "tool": "nikto",
            "status": "disabled",
            "reason": "Active web vulnerability testing is not available in this safe scanner.",
        }

    @staticmethod
    def run_comprehensive_scans(
        scan_category: str,
        scan_type: str,
        target: str,
    ) -> dict[str, Any]:
        return {
            "category": scan_category,
            "type": scan_type,
            "target": target,
            "status": "unsupported",
            "message": "No scan was run. Use the bounded, non-invasive private-network discovery endpoint.",
        }
