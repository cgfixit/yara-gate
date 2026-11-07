"""Scan captured bytes, then hand off those bytes or a private Read-tool snapshot.

The shell entry point keeps the existing environment variables. This module is stdlib-only;
YARA_GATE_BIN selects the installed scanner. Snapshot storage must be consumer-owned.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from sync_folder_gate import _readable

MAX_FILE_BYTES = 100 * 1024 * 1024


def _capture(path: Path) -> bytes:
    before = path.lstat()
    # Refuse cloud recalls as well as links, directories, devices, and pipes.
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or getattr(before, "st_file_attributes", 0) & (0x400 | 0x1000 | 0x400000)
    ):
        raise ValueError("not a local single-link regular file")
    if before.st_size > MAX_FILE_BYTES:
        raise ValueError("file exceeds 100MB")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not os.path.samestat(before, opened) or opened.st_nlink != 1:
            raise ValueError("entry changed during capture")
        payload = handle.read(MAX_FILE_BYTES + 1)
    if len(payload) > MAX_FILE_BYTES:
        raise ValueError("file exceeds 100MB")
    return payload


def main() -> int:
    args = sys.argv[1:]
    emit_bytes = bool(args and args[0] == "--bytes")
    if emit_bytes:
        args = args[1:]
    if args:
        if len(args) != 1:
            raise ValueError("expected one path")
        tool_input = {"file_path": args[0]}
    else:
        if emit_bytes:
            raise ValueError("--bytes requires a path")
        data = json.load(sys.stdin)
        if not isinstance(data, dict) or not isinstance(data.get("tool_input"), dict):
            raise ValueError("missing tool_input")
        tool_input = data["tool_input"]
        if data.get("tool_name", "Read") != "Read":
            return 0
    target = tool_input.get("file_path")
    if not isinstance(target, str) or not target:
        raise ValueError("missing file_path")
    policy = os.environ.get("YARA_GATE_POLICY", "agent-document")
    if policy not in ("agent-document", "agent-ingest"):
        raise ValueError("policy must be agent-document or agent-ingest")
    timeout = int(os.environ.get("YARA_GATE_SCAN_TIMEOUT", "30"))
    if timeout <= 0:
        raise ValueError("scan timeout must be positive")
    path = Path(target)
    payload = _capture(path)
    digest = hashlib.sha256(payload).hexdigest()
    home = Path(os.environ.get("YARA_GATE_HOME", str(Path.home() / "YaraGate-agent")))
    command = [
        os.environ.get("YARA_GATE_BIN", "yara-gate"),
        "scan",
        "-",
        "--name",
        path.name,
        "--json",
        "--policy",
        policy,
        "--home",
        str(home),
        "--timeout",
        str(timeout),
    ]
    rules = os.environ.get("YARA_GATE_RULES_ROOT")
    if rules:
        command += ["--rules", rules]
    completed = subprocess.run(  # noqa: S603 - configured executable, fixed argv, no shell
        command, input=payload, capture_output=True, check=False, timeout=timeout + 5
    )
    lines = completed.stdout.splitlines()
    if completed.returncode != 0 or len(lines) != 1:
        raise ValueError(f"scanner exit {completed.returncode}, records {len(lines)}")
    record = json.loads(lines[0])
    if not isinstance(record, dict) or not _readable(record, policy, digest):
        raise ValueError("record does not authorize these bytes")
    if emit_bytes:
        sys.stdout.buffer.write(payload)
        return 0
    # A fresh private directory per read prevents a later scan from replacing an earlier copy.
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    folder = Path(tempfile.mkdtemp(prefix="read-", dir=home)).resolve()
    try:
        snapshot = folder / path.name
        snapshot.write_bytes(payload)
        snapshot.chmod(0o400)
        output = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "updatedInput": {**tool_input, "file_path": str(snapshot)},
            }
        }
        print(json.dumps(output))
    except BaseException:
        shutil.rmtree(folder)
        raise
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # Only fixed failure descriptions; parser exceptions can contain submitted content.
        reason = (
            str(exc)
            if isinstance(exc, ValueError) and not isinstance(exc, json.JSONDecodeError)
            else type(exc).__name__
        )
        print(f"yara-gate hook: {reason}; blocking", file=sys.stderr)
        sys.exit(2)
