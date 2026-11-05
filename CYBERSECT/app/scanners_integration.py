import asyncio
import ipaddress
from typing import Any


SAFE_PORTS = (22, 53, 80, 443, 445, 3389, 8080, 8443)
MAX_SCAN_PORTS = 8
CONNECT_TIMEOUT_SECONDS = 0.6
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


def validate_private_target(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise ValueError("Use a single private or loopback IP address; hostnames and CIDRs are not accepted.") from error
    if not (
        address.is_loopback
        or any(address.version == network.version and address in network for network in ALLOWED_NETWORKS)
    ):
        raise ValueError("Only private or loopback IP addresses can be scanned.")
    return str(address)


async def _check_tcp_port(target: str, port: int) -> dict[str, Any]:
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port),
            timeout=CONNECT_TIMEOUT_SECONDS,
        )
    except (OSError, asyncio.TimeoutError):
        return {"port": port, "state": "closed_or_filtered"}

    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass
    return {"port": port, "state": "open"}


class ExternalScannerIntegration:
    @staticmethod
    async def run_safe_network_scan(
        target: str,
        ports: list[int] | None = None,
        *,
        profile: str = "basic",
    ) -> dict[str, Any]:
        target_ip = validate_private_target(target)
        selected_ports = list(SAFE_PORTS if ports is None else ports)
        if not selected_ports or len(selected_ports) > MAX_SCAN_PORTS:
            raise ValueError(f"Select between 1 and {MAX_SCAN_PORTS} allowed TCP ports.")
        if len(set(selected_ports)) != len(selected_ports):
            raise ValueError("Duplicate ports are not allowed.")
        invalid_ports = sorted(set(selected_ports) - set(SAFE_PORTS))
        if invalid_ports:
            raise ValueError(f"Unsupported ports: {invalid_ports}. Allowed ports: {list(SAFE_PORTS)}.")

        results = await asyncio.gather(
            *(_check_tcp_port(target_ip, port) for port in selected_ports)
        )
        return {
            "tool": "AIR-DS safe TCP discovery",
            "status": "completed",
            "profile": profile,
            "target": target_ip,
            "open_ports": [item["port"] for item in results if item["state"] == "open"],
            "ports": results,
            "os_identification": {
                "status": "not_performed",
                "reason": "TCP connect checks do not provide reliable OS fingerprints.",
            },
            "scope": "Single private/loopback IP; TCP connect checks only; no vulnerability tests.",
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
            "message": "No scan was run. Use the bounded, non-invasive TCP discovery endpoint.",
        }
