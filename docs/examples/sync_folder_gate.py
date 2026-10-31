"""Gate files that arrive in a sync client's folder (Dropbox, OneDrive, iCloud Drive).

The sync folder is never the gate's inbox: inbox intake removes its input, and a sync client
would propagate that deletion to every other device. This script copies each new, settled,
regular file into a gate-owned staging directory under a temporary name, renames it into
place, scans the staged copy with ``yara-gate scan --json --policy agent-document`` (synced
files are documents; ``--policy agent-ingest`` makes it clean-only), and moves it to
``allowed/<sha256>/`` only when the one record's SHA-256 matches the staged bytes and the
record passes the document read rule: complete and ``clean``, or the exact notes-only
``agent-document`` record from docs/integrations.md and nothing broader. Anything else
goes to ``held/<sha256>/`` with the record beside it. A consumer reads ``allowed/`` only,
never the sync folder, so a later change to the source cannot reach it.

Skipped, and logged once: dotfiles and client metadata (``.dropbox``, ``.DS_Store``,
``desktop.ini``, ``Icon\\r``, ``~$`` Office locks, ``.tmp``, ``.part``, ``.crdownload``),
symlinks and other non-regular entries, Windows reparse points (junctions and cloud-file
placeholders, which a read would hydrate), zero-length files (a placeholder or a write in
progress), and files whose size or mtime changed between two looks. ``conflicted copy`` files
are scanned like any other and named in the log so the operator can decide a policy.

Stdlib only. Nothing here executes a target or fetches a URL. The ledger holds paths, sizes,
times, and hashes, never content. Works on Windows, macOS, and Linux because it uses in-place
scans; on a POSIX host the staging directory may instead be the gate's own ``inbox/``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

SKIP_NAMES = {"desktop.ini", "Icon\r", "thumbs.db"}
SKIP_SUFFIXES = {".tmp", ".part", ".crdownload", ".partial", ".download"}
SKIP_PREFIXES = (".", "~$")
# Windows: FILE_ATTRIBUTE_REPARSE_POINT covers symlinks, junctions, and cloud-file placeholders.
_REPARSE = 0x400
_SETTLE_SECONDS = 1.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("sync_folder", type=Path, help="The sync client's folder (read only)")
    parser.add_argument("gate_home", type=Path, help="A directory this gate owns")
    parser.add_argument("--rules", type=Path, help="Rules root passed to yara-gate")
    parser.add_argument("--yara-gate", default=os.environ.get("YARA_GATE_BIN", "yara-gate"))
    parser.add_argument("--timeout", type=int, default=60, help="Seconds for one scan")
    parser.add_argument(
        "--policy",
        choices=("agent-document", "agent-ingest"),
        default="agent-document",
        help="agent-document for documents (the default); agent-ingest reads clean records only",
    )
    args = parser.parse_args()

    home = args.gate_home.resolve()
    for name in ("staging", "allowed", "held", "reports"):
        (home / name).mkdir(parents=True, exist_ok=True)
    ledger_path = home / "ledger.json"
    ledger = _load_ledger(ledger_path)
    sync_root = args.sync_folder.resolve()
    if home == sync_root or home.is_relative_to(sync_root):
        print("gate home must be outside the sync folder", file=sys.stderr)
        return 2

    worst = 0
    for path in sorted(_entries(sync_root)):
        relative = path.relative_to(sync_root).as_posix()
        reason = _skip_reason(path)
        if reason is not None:
            _log("skip", relative, reason)
            continue
        info = path.stat()
        key = f"{info.st_size}:{info.st_mtime_ns}"
        if ledger.get(relative, {}).get("key") == key:
            continue
        if not _settled(path, info):
            _log("skip", relative, "changing")
            continue
        if "conflicted copy" in path.name:
            _log("note", relative, "conflicted copy; scanned like any file")
        staged = _stage(path, home / "staging")
        if staged is None:
            _log("skip", relative, "changed during copy")
            continue
        digest = _sha256(staged)
        code, record = _scan(args, home, staged)
        allowed = code == 0 and record is not None and _readable(record, args.policy, digest)
        destination = home / ("allowed" if allowed else "held") / digest
        destination.mkdir(parents=True, exist_ok=True)
        os.replace(staged, destination / path.name)
        (destination / "record.json").write_text(
            json.dumps(record or {"exit_code": code}, indent=2) + "\n", encoding="utf-8"
        )
        ledger[relative] = {"key": key, "sha256": digest, "allowed": allowed}
        _save_ledger(ledger_path, ledger)
        _log("allowed" if allowed else "held", relative, digest)
        worst = max(worst, code if record is not None else 2)
    return worst


NOTES_ONLY = "agent-document records note findings"


def _readable(record: dict, policy: str, digest: str) -> bool:
    """One complete clean record, or the exact notes-only agent-document record; nothing else."""
    complete = (
        record.get("policy") == policy
        and record.get("exit_code") == 0
        and record.get("incomplete_reason") is None
        and record.get("sha256") == digest
    )
    if not complete:
        return False
    if record.get("verdict") == "clean":
        return True
    findings = record.get("findings") or []
    return (
        policy == "agent-document"
        and record.get("verdict") == "advisory"
        and record.get("policy_reason") == NOTES_ONLY
        and record.get("note") is True
        and record.get("advisory") is False
        and len(findings) > 0
        and all(finding.get("severity") == "note" for finding in findings)
    )


def _entries(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        dirnames[:] = [d for d in dirnames if not d.startswith(".") and not (base / d).is_symlink()]
        found.extend(base / name for name in filenames)
    return found


def _skip_reason(path: Path) -> str | None:
    name = path.name
    if name.startswith(SKIP_PREFIXES) or name in SKIP_NAMES or name.lower() in SKIP_NAMES:
        return "client metadata or temporary name"
    if path.suffix.lower() in SKIP_SUFFIXES:
        return "temporary suffix"
    try:
        info = path.lstat()
    except OSError:
        return "vanished"
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        return "not a regular file"
    attributes = getattr(info, "st_file_attributes", 0)
    if attributes & _REPARSE or getattr(info, "st_reparse_tag", 0):
        return "reparse point (link or online-only placeholder); not read"
    if info.st_size == 0:
        return "zero length (placeholder or write in progress)"
    return None


def _settled(path: Path, info: os.stat_result) -> bool:
    """Two looks at least a second apart must agree on size and mtime."""
    if time.time() - info.st_mtime >= _SETTLE_SECONDS:
        return True
    time.sleep(_SETTLE_SECONDS)
    try:
        again = path.stat()
    except OSError:
        return False
    return (again.st_size, again.st_mtime_ns) == (info.st_size, info.st_mtime_ns)


def _stage(source: Path, staging: Path) -> Path | None:
    """Copy through a temporary name, then rename, so a watcher never sees a partial file."""
    before = source.stat()
    partial = staging / f".partial-{secrets.token_hex(4)}"
    with source.open("rb") as handle, partial.open("wb") as out:
        shutil.copyfileobj(handle, out, 1024 * 1024)
    after = source.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        partial.unlink(missing_ok=True)
        return None
    final = staging / f"{secrets.token_hex(4)}-{source.name}"
    os.replace(partial, final)
    return final


def _sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _scan(args: argparse.Namespace, home: Path, staged: Path) -> tuple[int, dict | None]:
    command = [
        args.yara_gate,
        "scan",
        str(staged),
        "--json",
        "--policy",
        args.policy,
        "--home",
        str(home / "reports"),
        "--timeout",
        str(args.timeout),
    ]
    if args.rules is not None:
        command += ["--rules", str(args.rules)]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv built above, no shell
            command, capture_output=True, text=True, check=False
        )
    except OSError as exc:
        _log("error", staged.name, f"yara-gate did not start: {exc.__class__.__name__}")
        return 2, None
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if completed.returncode not in (0, 1) or len(lines) != 1:
        return 2, None
    try:
        record = json.loads(lines[0])
    except json.JSONDecodeError:
        return 2, None
    return completed.returncode, record if isinstance(record, dict) else None


def _load_ledger(path: Path) -> dict[str, dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _save_ledger(path: Path, ledger: dict[str, dict]) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _log(kind: str, relative: str, detail: str) -> None:
    print(f"{kind}\t{relative!r}\t{detail}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
