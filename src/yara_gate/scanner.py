"""Compile a rule set once and scan bytes. This module does not move files."""

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path
from typing import Any

from yara_gate.filetype import mismatch, sniff
from yara_gate.heuristics import heuristic_findings
from yara_gate.models import Finding, FindingSource, ScanResult, Severity, result_from_findings
from yara_gate.rules import compile_sources, default_rules_dir

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_EXTRACT_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3


class ScanTimeout(Exception):
    pass


def hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def scan_file(
    path: Path | str,
    *,
    timeout_s: int = 30,
    rules_dir: Path | None = None,
) -> ScanResult:
    file_path = Path(path)
    try:
        return _scan_file(file_path, timeout_s=timeout_s, rules_dir=rules_dir)
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        digest = ""
        try:
            if file_path.is_file():
                digest = hash_file(file_path)
        except OSError:
            digest = "0" * 64
        return result_from_findings(
            sha256=digest or "0" * 64,
            path=str(file_path),
            findings=[],
            incomplete_reason="scan failed",
        )


def _scan_file(file_path: Path, *, timeout_s: int, rules_dir: Path | None) -> ScanResult:
    if not file_path.is_file():
        return result_from_findings(
            sha256="0" * 64,
            path=str(file_path),
            findings=[],
            incomplete_reason="unreadable file",
        )
    try:
        size = file_path.stat().st_size
        digest = hash_file(file_path)
    except OSError:
        return result_from_findings(
            sha256="0" * 64,
            path=str(file_path),
            findings=[],
            incomplete_reason="unreadable file",
        )
    if size > MAX_FILE_BYTES:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=[],
            incomplete_reason="file exceeds 100MB",
        )
    try:
        data = file_path.read_bytes()
    except OSError:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=[],
            incomplete_reason="unreadable file",
        )

    findings: list[Finding] = []
    kind = sniff(data)
    if mismatch(file_path, kind):
        findings.append(
            Finding(
                rule_id=f"filetype_mismatch_{kind}",
                severity=Severity.block if kind in {"pe", "elf", "macho"} else Severity.advisory,
                source=FindingSource.filetype,
            )
        )
    limit = archive_limit(data)
    if limit:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=findings,
            incomplete_reason=limit,
        )

    rules, _skipped, error, _compiled, _skip_count = compile_sources(
        rules_dir or default_rules_dir()
    )
    if error or rules is None:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=findings,
            incomplete_reason=error or "yara-x missing",
        )
    try:
        for member, ext in _scan_units(file_path, data):
            findings.extend(_yara_findings(rules, member, ext, timeout_s))
    except ScanTimeout:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=findings,
            incomplete_reason="timeout",
        )
    except Exception:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=findings,
            incomplete_reason="yara scan failed",
        )

    extra, office_error = heuristic_findings(file_path, data)
    if office_error:
        return result_from_findings(
            sha256=digest,
            path=str(file_path),
            findings=findings,
            incomplete_reason=office_error,
        )
    findings.extend(extra)
    return result_from_findings(sha256=digest, path=str(file_path), findings=findings)


def archive_limit(data: bytes, *, depth: int = 0, budget: list[int] | None = None) -> str | None:
    """Return a reason when nested archives exceed the depth or byte budget."""
    spent = budget if budget is not None else [0]
    if not _is_archive(data):
        return None
    if depth >= MAX_ARCHIVE_DEPTH:
        return "archive depth exceeds 3"
    for size, member in _members(data):
        spent[0] += size
        if spent[0] > MAX_EXTRACT_BYTES:
            return "extracted size exceeds 500MB"
        reason = archive_limit(member, depth=depth + 1, budget=spent)
        if reason:
            return reason
    return None


def _yara_findings(rules: object, data: bytes, ext: str, timeout_s: int) -> list[Finding]:
    result = _invoke_scan(rules, data, timeout_s, ext)
    findings: list[Finding] = []
    for rule in getattr(result, "matching_rules", ()):
        meta = {str(key): value for key, value in getattr(rule, "metadata", ())}
        mode = meta.get("verdict_on_match", "block")
        if mode not in ("advisory", "block"):
            mode = "block"
        offset: int | None = None
        length: int | None = None
        for pattern in getattr(rule, "patterns", ()):
            matches = getattr(pattern, "matches", ())
            if not matches:
                continue
            offset = int(matches[0].offset)
            length = int(matches[0].length)
            break
        findings.append(
            Finding(
                rule_id=str(getattr(rule, "identifier", "rule")),
                offset=offset,
                length=length,
                severity=Severity(str(mode)),
                source=FindingSource.yara,
            )
        )
    return findings


def _invoke_scan(rules: Any, data: bytes, timeout_s: int, ext: str) -> object:
    import yara_x

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout_s)
    try:
        scanner.set_global("yara_gate_ext", ext)
    except (TypeError, ValueError):
        pass
    try:
        return scanner.scan(data)
    except yara_x.TimeoutError as exc:
        raise ScanTimeout from exc


def _scan_units(path: Path, data: bytes) -> list[tuple[bytes, str]]:
    ext = path.suffix.lower().removeprefix(".")
    units = [(data, ext)]
    units.extend(_nested_units(data, depth=0))
    return units


def _nested_units(data: bytes, depth: int) -> list[tuple[bytes, str]]:
    if depth >= MAX_ARCHIVE_DEPTH or not _is_archive(data):
        return []
    units: list[tuple[bytes, str]] = []
    for _size, member in _members(data):
        units.append((member, ""))
        units.extend(_nested_units(member, depth + 1))
    return units


def _is_archive(data: bytes) -> bool:
    return data.startswith(b"PK\x03\x04") or data.startswith(b"\x1f\x8b") or _is_tar(data)


def _is_tar(data: bytes) -> bool:
    if len(data) < 262:
        return False
    return data[257:262] == b"ustar"


def _members(data: bytes) -> list[tuple[int, bytes]]:
    if data.startswith(b"PK\x03\x04"):
        return _zip_members(data)
    if _is_tar(data):
        return _tar_members(data)
    return []


def _zip_members(data: bytes) -> list[tuple[int, bytes]]:
    # ponytail: trust the declared uncompressed size, then cap the read.
    # A lying zip header still stops at the remaining budget inside read().
    found: list[tuple[int, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.file_size > MAX_EXTRACT_BYTES:
                found.append((info.file_size, b""))
                continue
            with archive.open(info) as handle:
                blob = handle.read(MAX_EXTRACT_BYTES + 1)
            found.append((len(blob), blob))
    return found


def _tar_members(data: bytes) -> list[tuple[int, bytes]]:
    found: list[tuple[int, bytes]] = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            if member.size > MAX_EXTRACT_BYTES:
                found.append((member.size, b""))
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            blob = extracted.read(MAX_EXTRACT_BYTES + 1)
            found.append((len(blob), blob))
    return found
