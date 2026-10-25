#!/usr/bin/env python3
"""Zero-dependency stdio MCP server that wraps `yara-gate scan --json`.

Tested against upstream 80b3319.

Env:
  YARA_GATE_BIN    yara-gate executable (default: `yara-gate` on PATH)
  YARA_GATE_HOME   gate root (default: $PLUGIN_DATA/gate or ~/.cache/yara-gate-plugin/gate)
  YARA_GATE_RULES  rules root (passed through; yara-gate has its own default)
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys

PROTOCOL = "2025-06-18"
POLICIES = ["agent-ingest", "default"]


def _schema(desc):
    return {
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": desc},
            "policy": {
                "type": "string",
                "enum": POLICIES,
                "default": "agent-ingest",
                "description": "agent-ingest treats advisory findings as block (exit 1).",
            },
            "timeout_s": {"type": "integer", "minimum": 1, "default": 30},
        },
        "required": ["path"],
        "additionalProperties": False,
    }


TOOLS = [
    {
        "name": "scan_file",
        "description": (
            "Scan ONE untrusted file with yara-gate before opening, reading, or executing it. "
            "Returns yara-gate's own JSON report. allowed=true only for a complete clean verdict."
        ),
        "inputSchema": _schema("Absolute path to the file."),
    },
    {
        "name": "scan_dir",
        "description": (
            "Scan every file under a folder (symlinks not followed). One report per file; "
            "exit_code is the worst. allowed=true only if every file is complete and clean."
        ),
        "inputSchema": _schema("Absolute path to the folder."),
    },
    {
        "name": "scan_content",
        "description": (
            "Scan in-memory text (fetched page, message, tool output) via `yara-gate scan -` "
            "before putting it in context. Nothing is written to disk except the gate report. "
            "allowed=true only for one complete clean record whose sha256 matches the UTF-8 bytes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "content": {"type": "string", "description": "Text to scan (sent as UTF-8)."},
                "name": {
                    "type": "string",
                    "default": "content.txt",
                    "description": "Logical name; its suffix drives type checks (e.g. page.html).",
                },
                "policy": {"type": "string", "enum": POLICIES, "default": "agent-ingest"},
                "timeout_s": {"type": "integer", "minimum": 1, "default": 30},
            },
            "required": ["content"],
            "additionalProperties": False,
        },
    },
]


def _gate_home():
    if os.environ.get("YARA_GATE_HOME"):
        return os.environ["YARA_GATE_HOME"]
    base = os.environ.get("PLUGIN_DATA") or os.path.expanduser("~/.cache/yara-gate-plugin")
    return os.path.join(base, "gate")


def _run(target, args, data=None):
    policy = args.get("policy", "agent-ingest")
    if policy not in POLICIES:
        raise ValueError(f"policy must be one of {POLICIES}")
    exe = os.environ.get("YARA_GATE_BIN") or shutil.which("yara-gate")
    if not exe:
        raise RuntimeError("yara-gate not found: install it or set YARA_GATE_BIN")
    cmd = [
        exe,
        "scan",
        target,
        "--json",
        "--policy",
        policy,
        "--home",
        _gate_home(),
        "--timeout",
        str(int(args.get("timeout_s", 30))),
    ]
    if data is not None:
        cmd += ["--name", os.path.basename(str(args.get("name") or "content.txt")) or "content.txt"]
    if os.environ.get("YARA_GATE_RULES"):
        cmd += ["--rules", os.environ["YARA_GATE_RULES"]]
    proc = subprocess.run(  # noqa: S603 - yara-gate argv list, no shell
        cmd,
        input=data,
        capture_output=True,
        check=False,
        timeout=600,
    )
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace").strip() or None
    try:
        records = [json.loads(line) for line in stdout.splitlines() if line.strip()]
    except json.JSONDecodeError:
        return {
            "allowed": False,
            "exit_code": proc.returncode,
            "records": [],
            "stderr": (stderr or "") + " [malformed yara-gate output]",
        }
    # Fail closed, per yara-gate docs/integrations.md.
    ok = (
        proc.returncode == 0
        and bool(records)
        and all(
            r.get("verdict") == "clean"
            and r.get("exit_code") == 0
            and r.get("incomplete_reason") is None
            and r.get("policy") == policy
            for r in records
        )
    )
    return {"allowed": ok, "exit_code": proc.returncode, "records": records, "stderr": stderr}


def scan(name, args):
    if name == "scan_content":
        if not isinstance(args.get("content"), str):
            raise ValueError("content must be a string")
        data = args["content"].encode("utf-8")
        out = _run("-", args, data)
        out["allowed"] = (
            out["allowed"]
            and len(out["records"]) == 1
            and out["records"][0].get("sha256") == hashlib.sha256(data).hexdigest()
        )
        return out
    want_dir = name == "scan_dir"
    path = os.path.abspath(os.path.expanduser(str(args["path"])))
    if os.path.exists(path) and want_dir != os.path.isdir(path):
        kind = "scan_dir needs a folder" if want_dir else "scan_file needs a file"
        raise ValueError(f"{kind}: {path}")
    out = _run(path, args)
    if not want_dir:
        out["allowed"] = out["allowed"] and len(out["records"]) == 1
    return out


def handle(msg):
    method, mid = msg.get("method"), msg.get("id")
    if method == "initialize":
        return {
            "protocolVersion": msg.get("params", {}).get("protocolVersion", PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "yara-gate", "version": "0.2.0"},
        }
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        p = msg.get("params", {})
        name = p.get("name")
        if name not in ("scan_file", "scan_dir", "scan_content"):
            raise LookupError(f"unknown tool: {name}")
        try:
            out = scan(name, p.get("arguments") or {})
        except Exception as exc:  # report as tool error, never as clean
            return {
                "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
                "isError": True,
            }
        return {
            "content": [{"type": "text", "text": json.dumps(out)}],
            "structuredContent": out,
            "isError": False,
        }
    if method == "ping":
        return {}
    if mid is None:
        return None
    raise LookupError(f"method not found: {method}")


def main():
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            reply = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "parse error"},
            }
        else:
            if "id" not in msg:  # notification
                continue
            try:
                reply = {"jsonrpc": "2.0", "id": msg["id"], "result": handle(msg)}
            except LookupError as exc:
                reply = {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32601, "message": str(exc)},
                }
            except Exception as exc:
                reply = {
                    "jsonrpc": "2.0",
                    "id": msg["id"],
                    "error": {"code": -32603, "message": str(exc)},
                }
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
