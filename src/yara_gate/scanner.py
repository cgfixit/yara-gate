"""Scan raw bytes, archive members and derived text without moving files."""

import hashlib
import importlib.metadata
import math
import time
from pathlib import Path
from typing import Any

from yara_gate.content import (
    MAX_ARCHIVE_DEPTH as MAX_ARCHIVE_DEPTH,
)
from yara_gate.content import (
    MAX_EXTRACT_BYTES as MAX_EXTRACT_BYTES,
)
from yara_gate.content import (
    MAX_FILE_BYTES as MAX_FILE_BYTES,
)
from yara_gate.content import (
    Budget,
    ContentLimit,
    ContentUnit,
    content_units,
    text_views,
)
from yara_gate.filetype import mismatch, sniff, utf16_encoding
from yara_gate.heuristics import heuristic_findings, joiner_findings
from yara_gate.models import (
    Finding,
    FindingSource,
    ScanPolicy,
    ScanResult,
    Severity,
    Verdict,
    result_from_findings,
)
from yara_gate.rules import compile_sources, default_rules_dir, ruleset_digest


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
    policy: ScanPolicy | str = ScanPolicy.default,
) -> ScanResult:
    file_path = Path(path)
    try:
        return _scan_file(
            file_path, timeout_s=timeout_s, rules_dir=rules_dir, policy=ScanPolicy(policy)
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        digest = "0" * 64
        try:
            if file_path.is_file():
                digest = hash_file(file_path)
        except OSError:
            pass
        return result_from_findings(
            sha256=digest, path=str(file_path), findings=[], incomplete_reason="scan failed"
        )


def _scan_file(
    file_path: Path,
    *,
    timeout_s: int,
    rules_dir: Path | None,
    policy: ScanPolicy,
) -> ScanResult:
    budget = Budget(time.monotonic() + timeout_s)
    digest = "0" * 64
    findings: list[Finding] = []
    fingerprint: str | None = None
    engine_version: str | None = None
    skip_count = 0

    def finish(reason: str | None = None) -> ScanResult:
        result = result_from_findings(
            sha256=digest, path=str(file_path), findings=findings, incomplete_reason=reason
        )
        result.ruleset_sha256 = fingerprint
        result.engine_version = engine_version
        result.skipped_rule_files = skip_count
        result.policy = policy
        if policy is ScanPolicy.agent_ingest and result.verdict is Verdict.advisory:
            result.verdict = Verdict.block
            result.policy_reason = "agent-ingest holds advisory findings"
        return result

    if not file_path.is_file():
        return finish("unreadable file")
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            digest = hash_file(file_path)
            return finish("file exceeds 100MB")
        with file_path.open("rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except OSError:
        return finish("unreadable file")
    digest = hashlib.sha256(data).hexdigest()
    if len(data) > MAX_FILE_BYTES:
        return finish("file exceeds 100MB")
    root = rules_dir or default_rules_dir()
    rules, _skipped, error, _compiled, skip_count = compile_sources(root)
    if error or rules is None:
        return finish(error or "yara-x missing")
    fingerprint = ruleset_digest(root)
    engine_version = importlib.metadata.version("yara-x")
    try:
        for unit in content_units(ContentUnit(file_path.name, data), budget):
            budget.check()
            path = Path(unit.name)
            kind = sniff(unit.data)
            extra: list[Finding] = []
            if mismatch(path, kind):
                extra.append(
                    Finding(
                        rule_id=f"filetype_mismatch_{kind}",
                        severity=Severity.block
                        if kind in {"pe", "elf", "macho"}
                        else Severity.advisory,
                        source=FindingSource.filetype,
                    )
                )
            seconds = max(1, math.ceil(budget.deadline - time.monotonic()))
            ext = path.suffix.lower().removeprefix(".")
            extra.extend(_yara_findings(rules, unit.data, ext, seconds))
            heuristic, office_error = heuristic_findings(path, unit.data)
            extra.extend(heuristic)
            decoded = _decoded_text(unit.data)
            if decoded is not None:
                text, view = decoded
                for finding in joiner_findings(text):
                    finding.view = view
                    extra.append(finding)
            for finding in extra:
                finding.member_path = list(unit.member_path)
            findings.extend(extra)
            if office_error:
                return finish(office_error)
            for view, derived in text_views(unit.data, budget):
                budget.check()
                seconds = max(1, math.ceil(budget.deadline - time.monotonic()))
                for finding in _yara_findings(rules, derived, ext, seconds):
                    finding.member_path = list(unit.member_path)
                    finding.view = view
                    findings.append(finding)
            budget.check()
    except ContentLimit as exc:
        return finish(str(exc))
    except ScanTimeout:
        return finish("timeout")
    except Exception:
        return finish("content scan failed")
    return finish()


def _decoded_text(data: bytes) -> tuple[str, str] | None:
    if sniff(data) != "text":
        return None
    encoding = utf16_encoding(data)
    if encoding is not None:
        try:
            return data.decode(encoding), "decoded-utf16"
        except UnicodeError:
            return None
    try:
        return data.decode("utf-8"), "raw"
    except UnicodeError:
        # U+FFFD is three bytes, so offsets no longer match the file: not a raw view.
        return data.decode("utf-8", errors="replace"), "utf8-replaced"


def archive_limit(data: bytes, *, depth: int = 0, budget: list[int] | None = None) -> str | None:
    """Inspect archive coverage with the same bounded reader used by scans."""
    limits = Budget(float("inf"), expanded=budget[0] if budget else 0)
    try:
        for _unit in content_units(ContentUnit("archive", data), limits, depth):
            pass
    except ContentLimit as exc:
        return str(exc)
    finally:
        if budget is not None:
            budget[0] = limits.expanded
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
                namespace=str(getattr(rule, "namespace", "")) or None,
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
