"""A read-only index of present holds, using metadata and stored reports only."""

import json
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from yara_gate.models import UNKNOWN_SHA256, Finding, ScanResult, Verdict
from yara_gate.quarantine import (
    _UNREAD_ATTRIBUTES,
    GatePaths,
    IntakeRejected,
    _open_regular,
    _reject_reason,
)
from yara_gate.release import release_refusal
from yara_gate.report import redact

_MAX_REPORT_BYTES = 8 * 1024 * 1024
_DIGEST = re.compile(r"[0-9a-f]{64}")


def since_seconds(value: str) -> int:
    match = re.fullmatch(r"([0-9]{1,9})([smhdw])", value)
    if match is None:
        raise ValueError("--since must be an integer followed by s, m, h, d, or w (for example 7d)")
    return int(match[1]) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[match[2]]


def _entries(path: Path) -> list[Path]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return []
    if (
        not stat.S_ISDIR(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _UNREAD_ATTRIBUTES
    ):
        raise ValueError("hold index requires local directories, without links")
    return sorted(path.iterdir())


def _read_report(path: Path) -> tuple[ScanResult, float]:
    # Check before opening as well: a report must never be a link to a held copy.
    if _reject_reason(path.lstat()) is not None:
        raise ValueError("report is not a regular file with one link")
    fd = _open_regular(path)
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if info.st_size > _MAX_REPORT_BYTES:
            raise ValueError("report exceeds size limit")
        data = handle.read(_MAX_REPORT_BYTES + 1)
    if len(data) > _MAX_REPORT_BYTES:
        raise ValueError("report exceeds size limit")
    record = json.loads(data)
    if not isinstance(record, dict):
        raise ValueError("invalid report")
    for key in ("sha256", "path", "verdict", "policy"):
        if not isinstance(record.get(key), str):
            raise ValueError("invalid report field")
    if _DIGEST.fullmatch(record["sha256"]) is None:
        raise ValueError("invalid report digest")
    for key in ("incomplete_reason", "policy_reason", "ruleset_sha256"):
        if record.get(key) is not None and not isinstance(record[key], str):
            raise ValueError("invalid report field")
    ruleset = record.get("ruleset_sha256")
    if ruleset is not None and _DIGEST.fullmatch(ruleset) is None:
        raise ValueError("invalid ruleset digest")
    if not isinstance(record.get("findings"), list):
        raise ValueError("invalid findings")
    findings = []
    for item in record["findings"]:
        if not isinstance(item, dict) or not isinstance(item.get("rule_id"), str):
            raise ValueError("invalid finding")
        findings.append(
            Finding(rule_id=item["rule_id"], severity=item["severity"], source=item["source"])
        )
    return ScanResult(
        sha256=record["sha256"],
        path=record["path"],
        verdict=record["verdict"],
        policy=record["policy"],
        policy_reason=record.get("policy_reason"),
        incomplete_reason=record.get("incomplete_reason"),
        ruleset_sha256=ruleset,
        findings=findings,
    ), info.st_mtime


_REPORT_ERRORS = (OSError, ValueError, TypeError, KeyError, RecursionError, IntakeRejected)


def held_items(home: GatePaths, *, since: int | None = None) -> list[dict[str, Any]]:
    """List current entries, not historical reports. Never authorize a release or a read."""
    if not home.root.exists():
        raise ValueError("gate home does not exist")
    _entries(home.root)
    report_paths = _entries(home.reports)
    rejected: dict[str, list[tuple[ScanResult, float]]] = {}
    for path in report_paths:
        if path.name.startswith("rejected-") and path.suffix == ".json":
            try:
                result, modified = _read_report(path)
                if path.stem == f"rejected-{result.sha256}":
                    rejected.setdefault(result.path, []).append((result, modified))
            except _REPORT_ERRORS:
                continue  # The physical entry is still listed with an unreadable report.
    now = datetime.now(UTC).timestamp()
    try:
        unknown = _read_report(home.reports / f"{'0' * 64}.json")
    except _REPORT_ERRORS:
        unknown = None
    rows: list[dict[str, Any]] = []
    for folder, disposition in ((home.blocked, "blocked"), (home.quarantine, "incomplete")):
        for slot in _entries(folder):
            if slot == home.quarantine / "_rejected":
                for entry in _entries(slot):
                    matches = rejected.get(redact(str(entry)), [])
                    report = matches[0] if len(matches) == 1 else None
                    rows.append(_row(entry, "rejected", None, report, now))
                continue
            identifier = slot.name if _DIGEST.fullmatch(slot.name) else None
            try:
                copies = _entries(slot)
            except (OSError, ValueError):
                copies = []
            if not copies:
                copies = [slot]
            for entry in copies:
                report = None
                if identifier is not None and entry != slot:
                    paths = {
                        redact(str(parent / identifier / entry.name))
                        for parent in (home.blocked, home.quarantine, home.clean)
                    }
                    if (
                        unknown is not None
                        and unknown[0].path in paths
                        and unknown[0].sha256 == UNKNOWN_SHA256
                        and unknown[0].verdict is Verdict.incomplete
                    ):
                        report = unknown
                    try:
                        candidate, modified = _read_report(home.reports / f"{identifier}.json")
                        if (
                            candidate.path in paths
                            and (
                                candidate.sha256 == identifier
                                or candidate.sha256 == UNKNOWN_SHA256
                                and candidate.verdict is Verdict.incomplete
                            )
                            and (report is None or modified > report[1])
                        ):
                            report = candidate, modified
                    except _REPORT_ERRORS:
                        pass
                row = _row(entry, disposition, identifier, report, now)
                if len(copies) != 1 or entry == slot:
                    row["release_eligible"] = False
                    row["release_refusal"] = "slot must contain exactly one file"
                rows.append(row)
    # Unknown ages remain visible even with a filter; absence of evidence must not hide a hold.
    return [
        row
        for row in rows
        if since is None or row["age_seconds"] is None or row["age_seconds"] <= since
    ]


def _row(
    entry: Path,
    disposition: str,
    identifier: str | None,
    report: tuple[ScanResult, float] | None,
    now: float,
) -> dict[str, Any]:
    refusal: str | None = "report missing, unreadable, or unassociated"
    modified: float | None = None
    try:
        info = entry.lstat()
        entry_refusal = _reject_reason(info)
    except OSError:
        entry_refusal = "entry unavailable"
    row: dict[str, Any] = {
        "disposition": disposition,
        "identifier": identifier,
        "sha256": None,
        "path": redact(str(entry)),
        "age_seconds": None,
        "policy": None,
        "policy_reason": None,
        "incomplete_reason": None,
        "findings": [],
        "report_status": "unreadable",
        "release_eligible": False,
        "release_refusal": refusal,
    }
    if report is not None:
        result, modified = report
        row.update(
            identifier=identifier or result.sha256,
            sha256=result.sha256
            if disposition != "rejected" and result.sha256 != UNKNOWN_SHA256
            else None,
            policy=result.policy.value,
            policy_reason=result.policy_reason,
            incomplete_reason=result.incomplete_reason,
            findings=[
                {"rule_id": f.rule_id, "severity": f.severity.value} for f in result.findings
            ],
            report_status="readable",
        )
        refusal = (
            "only a blocked copy can be released"
            if disposition != "blocked"
            else entry_refusal or release_refusal(result)
        )
        row.update(release_eligible=refusal is None, release_refusal=refusal)
    if modified is not None:
        row["age_seconds"] = max(0, int(now - modified))
    return row
