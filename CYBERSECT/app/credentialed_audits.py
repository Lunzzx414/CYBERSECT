import asyncio
import ipaddress
import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from app.scanners_integration import validate_private_targets


PROCESS_TIMEOUT_SECONDS = 12
MAX_OUTPUT_BYTES = 64 * 1024
_SAFE_USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@\\-]{0,127}\Z")


def _validate_target(target: str) -> str:
    normalized, targets = validate_private_targets(target)
    if len(targets) != 1:
        raise ValueError("Credentialed audits accept one private IP at a time.")
    return targets[0]


def _validate_username(value: str) -> str:
    if not _SAFE_USERNAME.fullmatch(value):
        raise ValueError("Username contains unsupported characters.")
    return value


def _validate_identity_file(identity_file: str) -> Path:
    ssh_directory = (Path.home() / ".ssh").resolve()
    candidate = Path(identity_file).expanduser()
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(ssh_directory)
    except (OSError, ValueError) as error:
        raise ValueError("SSH identity file must be inside the server user's ~/.ssh directory.") from error
    if not resolved.is_file():
        raise ValueError("SSH identity path is not a regular file.")
    if os.name != "nt" and resolved.stat().st_mode & 0o077:
        raise ValueError("SSH identity file permissions must not allow group or other access.")
    return resolved


async def _run_process(*arguments: str) -> tuple[int, bytes, bytes]:
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=PROCESS_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError as error:
        process.kill()
        await process.wait()
        raise ValueError("Credentialed audit timed out; no result was recorded.") from error
    return process.returncode or 0, stdout[:MAX_OUTPUT_BYTES], stderr[:MAX_OUTPUT_BYTES]


def _ssh_base(target: str, username: str, identity_file: Path) -> list[str]:
    if shutil.which("ssh") is None:
        raise ValueError("OpenSSH client is not installed in the server environment.")
    return [
        "ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "LogLevel=ERROR",
        "-i",
        str(identity_file),
        "-l",
        username,
        target,
    ]


async def audit_ssh_patches(
    target: str,
    username: str,
    identity_file: str,
) -> dict[str, Any]:
    target_ip = _validate_target(target)
    username = _validate_username(username)
    identity_path = _validate_identity_file(identity_file)

    base = _ssh_base(target_ip, username, identity_path)
    return_code, system_bytes, _stderr = await _run_process(*base, "uname -srm")
    system_hint = system_bytes.decode("utf-8", errors="replace").strip()
    if return_code == 0 and system_hint.lower().startswith("linux"):
        linux_command = (
            "cat /etc/os-release 2>/dev/null | head -n 6; "
            "if command -v pacman >/dev/null 2>&1; then pacman -Qu 2>/dev/null | head -n 50; "
            "elif command -v apt >/dev/null 2>&1; then apt list --upgradable 2>/dev/null | head -n 50; fi"
        )
        return_code, stdout, _stderr = await _run_process(*base, linux_command)
        if return_code != 0:
            raise ValueError("Linux package inventory failed over SSH.")
        return {
            "target": target_ip,
            "protocol": "ssh",
            "status": "completed",
            "platform_hint": "Linux",
            "patch_audit": "read-only package inventory; update status depends on cached repository metadata",
            "inventory": f"{system_hint}\n{stdout.decode('utf-8', errors='replace').strip()}".strip(),
            "credential_storage": "not stored",
            "remote_actions": "fixed read-only inventory commands only",
        }

    windows_command = (
        "powershell.exe -NoProfile -NonInteractive -Command "
        "\"$os=Get-CimInstance Win32_OperatingSystem; "
        "$os | Select-Object Caption,Version,LastBootUpTime | ConvertTo-Json -Compress; "
        "Get-HotFix | Sort-Object InstalledOn -Descending | "
        "Select-Object -First 20 HotFixID,InstalledOn | ConvertTo-Json -Compress\""
    )
    return_code, stdout, _stderr = await _run_process(*base, windows_command)
    if return_code != 0:
        raise ValueError(
            "SSH authentication or read-only inventory failed. Check the key, known_hosts entry, "
            "remote SSH policy, and target reachability."
        )
    return {
        "target": target_ip,
        "protocol": "ssh",
        "status": "completed",
        "platform_hint": "Windows",
        "patch_audit": "installed hotfix inventory only; missing updates are not inferred",
        "inventory": stdout.decode("utf-8", errors="replace").strip(),
        "credential_storage": "not stored",
        "remote_actions": "fixed read-only inventory commands only",
    }


def _validate_smb_credentials(username: str, password: str, domain: str) -> tuple[str, str, str]:
    for name, value in (("username", username), ("domain", domain)):
        if len(value) > 128 or any(character in value for character in "\r\n=\x00"):
            raise ValueError(f"Invalid SMB {name}.")
    if not password or len(password) > 256 or any(character in password for character in "\r\n\x00"):
        raise ValueError("Invalid SMB password.")
    return username, password, domain


async def audit_smb_shares(
    target: str,
    username: str,
    password: str,
    domain: str = "",
) -> dict[str, Any]:
    target_ip = _validate_target(target)
    address = ipaddress.ip_address(target_ip)
    if address.version != 4:
        raise ValueError("SMB credentialed audits currently accept IPv4 targets only.")
    username, password, domain = _validate_smb_credentials(username, password, domain)
    smbclient = shutil.which("smbclient")
    if smbclient is None:
        raise ValueError("smbclient is not installed in the server environment.")

    with tempfile.TemporaryDirectory(prefix="airds-smb-auth-") as directory:
        os.chmod(directory, 0o700)
        auth_path = Path(directory) / "credentials"
        auth_path.write_text(
            f"username = {username}\npassword = {password}\ndomain = {domain}\n",
            encoding="utf-8",
        )
        os.chmod(auth_path, 0o600)
        return_code, stdout, _stderr = await _run_process(
            smbclient,
            "-g",
            "-L",
            f"//{target_ip}",
            "-A",
            str(auth_path),
            "-m",
            "SMB3",
            "--option=client min protocol=SMB3",
        )

    if return_code != 0:
        raise ValueError(
            "SMB3 authentication or share enumeration failed. Credentials were discarded; "
            "check the target, account, and SMB client availability."
        )
    shares = []
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        fields = line.split("|", 2)
        if len(fields) >= 2 and fields[0].lower() in {"disk", "print", "ipc"}:
            shares.append({"type": fields[0].lower(), "name": fields[1][:128]})
        if len(shares) >= 100:
            break
    return {
        "target": target_ip,
        "protocol": "smb3",
        "status": "completed",
        "shares": shares,
        "patch_audit": "not available over SMB share enumeration; install the endpoint agent for local patch inventory",
        "credential_storage": "temporary mode-600 file, removed after one connection",
        "remote_actions": "single authenticated share-list request; no file contents read or written",
    }
