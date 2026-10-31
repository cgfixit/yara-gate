"""Scan raw bytes, archive members and derived text without moving files."""

import hashlib
import math
import time
from collections.abc import Sequence
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
    PdfObjects,
    content_units,
    ooxml_text_views,
    pdf_views,
    text_views,
)
from yara_gate.filetype import (
    double_extension,
    is_document_name,
    is_executable_kind,
    mismatch,
    name_has_controls,
    sniff,
    utf16_encoding,
)
from yara_gate.heuristics import (
    base64_run_signals,
    heuristic_findings,
    joiner_findings,
    pdf_token_findings,
)
from yara_gate.models import (
    Finding,
    FindingSource,
    ScanPolicy,
    ScanResult,
    Severity,
    Verdict,
    result_from_findings,
)
from yara_gate.rules import compile_ruleset, default_rules_dir, yara_x_version


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


def scan_bytes(
    data: bytes,
    *,
    name: str = "input",
    timeout_s: int = 30,
    rules_dir: Path | None = None,
    policy: ScanPolicy | str = ScanPolicy.default,
) -> ScanResult:
    """Scan bytes the caller already holds, such as a chat or SMS message body.

    Nothing is written to disk and nothing is moved. ``name`` supplies the suffix that the
    extension-sensitive checks read (the YARA ``yara_gate_ext`` global, type mismatch, double
    extension, MCP JSON and model headers); only its final component is kept, and it becomes
    the report ``path``. The verdict describes these bytes: consume the same buffer, not a
    later reread.
    """
    label = Path(name).name or "input"
    # bytes(5) would build five NUL bytes; anything not bytes-like is a failed scan.
    payload = bytes(data) if isinstance(data, bytes | bytearray | memoryview) else None
    try:
        if payload is None:
            raise TypeError("scan_bytes needs bytes")
        return _scan_file(
            Path(label),
            timeout_s=timeout_s,
            rules_dir=rules_dir,
            policy=ScanPolicy(policy),
            data=payload,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        digest = hashlib.sha256(payload).hexdigest() if payload is not None else "0" * 64
        return result_from_findings(
            sha256=digest, path=label, findings=[], incomplete_reason="scan failed"
        )


def _scan_file(
    file_path: Path,
    *,
    timeout_s: int,
    rules_dir: Path | None,
    policy: ScanPolicy,
    data: bytes | None = None,
) -> ScanResult:
    started = time.monotonic()
    budget = Budget(started + timeout_s)
    digest = "0" * 64
    findings: list[Finding] = []
    fingerprint: str | None = None
    engine_version: str | None = None
    skip_count = 0
    compiled = 0
    units = 0
    views: dict[str, int] = {}
    scanned_bytes = 0
    yara_time = 0.0

    def yara(rules: object, payload: bytes, ext: str, view: str | None) -> list[Finding]:
        nonlocal scanned_bytes, yara_time
        if view is not None:
            views[view] = views.get(view, 0) + 1
        seconds = max(1, math.ceil(budget.deadline - time.monotonic()))
        begun = time.monotonic()
        try:
            return _yara_findings(rules, payload, ext, seconds)
        finally:
            scanned_bytes += len(payload)
            yara_time += time.monotonic() - begun

    def finish(reason: str | None = None) -> ScanResult:
        from yara_gate import __version__

        result = result_from_findings(
            sha256=digest, path=str(file_path), findings=findings, incomplete_reason=reason
        )
        result.ruleset_sha256 = fingerprint
        result.engine_version = engine_version
        result.skipped_rule_files = skip_count
        result.compiled_rules = compiled
        result.tool_version = __version__
        result.scan_seconds = round(time.monotonic() - started, 3)
        result.units_scanned = units
        result.views_scanned = dict(sorted(views.items()))
        result.bytes_scanned = scanned_bytes
        result.yara_seconds = round(yara_time, 3) if units else None
        result.policy = policy
        if result.verdict is Verdict.advisory:
            if policy is ScanPolicy.agent_ingest:
                result.verdict = Verdict.block
                result.policy_reason = "agent-ingest holds advisory and note findings"
            elif policy is ScanPolicy.agent_document and result.advisory:
                result.verdict = Verdict.block
                result.policy_reason = "agent-document holds advisory findings"
            elif policy is ScanPolicy.agent_document:
                result.policy_reason = "agent-document records note findings"
        return result

    if data is None:
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
    rules, _skipped, error, compiled, skip_count, ruleset = compile_ruleset(root)
    if error or rules is None:
        return finish(error or "yara-x missing")
    fingerprint = ruleset
    engine_version = yara_x_version()
    # Only the submitted name: the directories above it belong to the operator.
    findings.extend(_name_findings([file_path.name]))
    try:
        for unit in content_units(ContentUnit(file_path.name, data), budget):
            budget.check()
            units += 1
            path = Path(unit.name)
            kind = sniff(unit.data)
            extra: list[Finding] = []
            if unit.member_path:
                # Every component: an Invoice.pdf.app bundle hides behind its inner file names.
                extra.extend(_name_findings(path.parts))
            if is_executable_kind(kind) and unit.member_path and is_document_name(file_path):
                extra.append(
                    Finding(
                        rule_id="heuristic_document_executable",
                        severity=Severity.block,
                        source=FindingSource.heuristic,
                    )
                )
            if is_executable_kind(kind) and len(unit.member_path) >= 2:
                extra.append(
                    Finding(
                        rule_id="heuristic_nested_executable",
                        severity=Severity.block,
                        source=FindingSource.heuristic,
                    )
                )
            if mismatch(path, kind):
                if unit.data:
                    extra.append(
                        Finding(
                            rule_id=f"filetype_mismatch_{kind}",
                            severity=Severity.block
                            if kind in {"pe", "elf", "macho"}
                            else Severity.advisory,
                            source=FindingSource.filetype,
                        )
                    )
                else:
                    # Zero bytes sniff as text; a cloud placeholder is not a disguised type.
                    extra.append(
                        Finding(
                            rule_id="heuristic_empty_file",
                            severity=Severity.advisory,
                            source=FindingSource.heuristic,
                        )
                    )
            ext = path.suffix.lower().removeprefix(".")
            extra.extend(yara(rules, unit.data, ext, None))
            # Object streams are indexed on first use, for an /OpenAction reference only.
            pdf_objects = PdfObjects(unit.data, budget)
            heuristic, office_error = heuristic_findings(path, unit.data, pdf_objects)
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
                view_findings = yara(rules, derived, ext, view)
                if view == "text-folded":
                    # Folding rewrites digits inside base64 (0 to o), which breaks the media
                    # exemptions; the raw bytes already carry the base64 verdict, and folding
                    # cannot create a real encoded payload that the raw view missed.
                    view_findings = [f for f in view_findings if f.rule_id not in _RAW_ONLY_RULES]
                if view == "html-unescaped":
                    # An entity such as &zwnj; hides a joiner that the raw check cannot see.
                    view_findings.extend(joiner_findings(derived.decode("utf-8")))
                for finding in view_findings:
                    finding.member_path = list(unit.member_path)
                    finding.view = view
                    findings.append(finding)
            for view, derived in pdf_views(unit.data, budget):
                budget.check()
                view_findings = yara(rules, derived, ext, view)
                # An action dictionary inside an object stream is invisible to the raw check.
                view_findings.extend(pdf_token_findings(derived, pdf_objects))
                for finding in view_findings:
                    finding.member_path = list(unit.member_path)
                    finding.view = view
                    findings.append(finding)
            for view, derived in ooxml_text_views(unit.name, unit.data, budget):
                budget.check()
                # A sentence split across Word runs is one sentence to the reader.
                for finding in yara(rules, derived, ext, view):
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


_RAW_ONLY_RULES = frozenset({"agent_base64_blob", "agent_base64_executable"})


def _name_findings(parts: Sequence[str]) -> list[Finding]:
    found: list[Finding] = []
    if any(double_extension(Path(part)) for part in parts):
        found.append(
            Finding(
                rule_id="heuristic_double_extension",
                severity=Severity.block,
                source=FindingSource.heuristic,
            )
        )
    if any(name_has_controls(part) for part in parts):
        found.append(
            Finding(
                rule_id="heuristic_filename_control",
                severity=Severity.block,
                source=FindingSource.heuristic,
            )
        )
    return found


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
        if mode not in ("note", "advisory", "block"):
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
    blob, exe = base64_run_signals(data)
    for name, value in (
        ("yara_gate_ext", ext),
        ("yara_gate_b64_blob", blob),
        ("yara_gate_b64_exe", exe),
    ):
        try:
            scanner.set_global(name, value)
        except (TypeError, ValueError):
            pass
    try:
        return scanner.scan(data)
    except yara_x.TimeoutError as exc:
        raise ScanTimeout from exc
