"""Optional Windows/Linux endpoint inventory agent; hashes only explicitly selected roots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_FILE_SIZE = 50 * 1024 * 1024
MAX_FILES = 10000


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def collect_inventory(roots: list[Path]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for root in roots:
        resolved_root = root.expanduser().resolve(strict=True)
        if not resolved_root.is_dir():
            raise ValueError(f"Selected root is not a directory: {root}")
        root_label = hashlib.sha256(os.fsencode(str(resolved_root))).hexdigest()[:12]
        for directory, dirnames, filenames in os.walk(resolved_root, followlinks=False):
            dirnames[:] = sorted(
                name for name in dirnames
                if not (Path(directory) / name).is_symlink()
            )
            for name in sorted(filenames):
                path = Path(directory) / name
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    stat = path.stat(follow_symlinks=False)
                    if stat.st_size > MAX_FILE_SIZE:
                        continue
                    results.append({
                        "path": f"root-{root_label}/{path.relative_to(resolved_root)}",
                        "sha256": _hash_file(path),
                        "size": stat.st_size,
                        "modified_time": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    })
                except (OSError, PermissionError):
                    continue
                if len(results) >= MAX_FILES:
                    return results
    return results


def compare_baseline(files: list[dict[str, Any]], state_file: Path) -> dict[str, Any]:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(state_file)
    try:
        connection.execute("CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, sha256 TEXT NOT NULL)")
        previous = dict(connection.execute("SELECT path, sha256 FROM files"))
        current = {entry["path"]: entry["sha256"] for entry in files}
        if not previous:
            status = "initial"
        else:
            changed = sum(1 for path, digest in current.items() if previous.get(path) not in (None, digest))
            added = sum(path not in previous for path in current)
            removed = sum(path not in current for path in previous)
            changed_count = changed + added + removed
            changed_ratio = changed_count / max(len(previous), len(current), 1)
            status = "changed" if changed_count >= 10 and changed_ratio >= 0.2 else "unchanged"
        connection.execute("DELETE FROM files")
        connection.executemany("INSERT INTO files(path, sha256) VALUES(?, ?)", current.items())
        connection.commit()
        return {"status": status, "heuristic": True, "description": "Changed means at least 10 file additions, removals, or modifications and at least 20% of the previous/current inventory. This is not a ransomware verdict."}
    finally:
        connection.close()


def build_report(roots: list[Path], state_file: Path) -> dict[str, Any]:
    files = collect_inventory(roots)
    return {
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "file_count": len(files),
        "files": files,
        "baseline": compare_baseline(files, state_file),
        "limits": {"max_files": MAX_FILES, "max_file_size_bytes": MAX_FILE_SIZE, "content_uploaded": False},
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", action="append", required=True, help="Explicit directory to inventory; may be repeated")
    parser.add_argument("--output", required=True, help="JSON report path")
    parser.add_argument("--state-file", default=str(Path.home() / ".local" / "state" / "cybersect-agent.sqlite3"))
    args = parser.parse_args(argv)
    try:
        report = build_report([Path(root) for root in args.root], Path(args.state_file))
        output = Path(args.output).expanduser()
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent, delete=False) as temp:
            json.dump(report, temp, indent=2)
            temp.write("\n")
            temporary_path = Path(temp.name)
        temporary_path.replace(output)
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"endpoint agent: {error}", file=sys.stderr)
        return 2
    print(f"Wrote {report['file_count']} file hashes to {output}; contents were not uploaded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
