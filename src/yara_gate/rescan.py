"""Revalidate admitted copies without releasing anything already held."""

import hashlib
import json
import os
import stat
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

from yara_gate.models import ScanPolicy, ScanResult, Verdict
from yara_gate.quarantine import (
    _UNREAD_ATTRIBUTES,
    GatePaths,
    IntakeRejected,
    _acquire_lock,
    _bounded_chunks,
    _gate_lock,
    _open_regular,
    _reject_reason,
    _source_stamp,
)
from yara_gate.report import redact, write_reports
from yara_gate.scanner import scan_bytes


def rescan_clean(
    home: GatePaths,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
    dry_run: bool = False,
) -> Iterator[ScanResult | None]:
    """Yield a fresh result per changed admission, or None for a current clean copy.

    Reports precede withdrawal. Any error aborts with the remaining copies unvalidated;
    consumers must stop reading this home until a successful pass completes.
    """
    if timeout_s <= 0:
        raise ValueError("scan timeout must be positive")
    if not home.clean.is_dir() or home.clean.is_symlink() or home.clean.is_junction():
        raise ValueError("gate home must have a real clean directory")
    lock_fd = _acquire_lock(home)
    try:
        with _gate_lock(home):
            if home.pending_intake.exists():
                raise ValueError("pending intake must be recovered before rescan")
            identity = scan_bytes(b"", rules_dir=rules_dir, timeout_s=timeout_s, policy=policy)
            for slot in sorted(home.clean.iterdir()):
                yield _rescan_slot(home, slot, identity, rules_dir, timeout_s, policy, dry_run)
    finally:
        os.close(lock_fd)


def _rescan_slot(
    home: GatePaths,
    slot: Path,
    identity: ScanResult,
    rules_dir: Path | None,
    timeout_s: int,
    policy: ScanPolicy,
    dry_run: bool,
) -> ScanResult | None:
    digest = slot.name
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("invalid clean slot name; manual recovery required")
    info = slot.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or getattr(info, "st_file_attributes", 0) & _UNREAD_ATTRIBUTES
    ):
        raise ValueError("clean slot is not a local directory; manual recovery required")
    copies = list(slot.iterdir())
    if len(copies) != 1:
        raise ValueError("clean slot must contain exactly one file; manual recovery required")
    target = copies[0]
    result: ScanResult
    try:
        fd = _open_regular(target)
        try:
            opened = os.fstat(fd)
            payload = b"".join(_bounded_chunks(fd))
            if hashlib.sha256(payload).hexdigest() != digest:
                raise IntakeRejected("admitted copy no longer matches its digest")
            current = _current_report(home, target, identity, policy)
            result = (
                identity
                if current
                else scan_bytes(
                    payload,
                    name=target.name,
                    rules_dir=rules_dir,
                    timeout_s=timeout_s,
                    policy=policy,
                )
            )
            entry = target.lstat()
            if (
                _reject_reason(entry) is not None
                or _source_stamp(entry) != _source_stamp(opened)
                or _source_stamp(os.fstat(fd)) != _source_stamp(opened)
            ):
                raise IntakeRejected("admitted copy changed during rescan")
            if current:
                return None
            if result.path != target.name:
                raise IntakeRejected("admitted name could not be preserved during rescan")
        finally:
            os.close(fd)
    except (IntakeRejected, OSError) as exc:
        result = ScanResult(
            sha256="0" * 64,
            verdict=Verdict.incomplete,
            incomplete_reason=exc.reason
            if isinstance(exc, IntakeRejected)
            else "admitted copy unreadable",
            policy=policy,
        )
    result = replace(result, path=str(target), policy=policy)
    destination = (
        home.quarantine / digest
        if result.verdict is Verdict.incomplete
        else home.blocked / digest
        if result.verdict is Verdict.block
        else slot
    )
    if destination != slot and os.path.lexists(destination):
        raise ValueError("held slot already exists; manual recovery required")
    if not dry_run:
        write_reports(home.reports, result, stem=digest)
        if destination != slot:
            os.replace(slot, destination)
    return result


def _current_report(
    home: GatePaths, target: Path, identity: ScanResult, policy: ScanPolicy
) -> bool:
    if (
        identity.verdict is Verdict.incomplete
        or not identity.ruleset_sha256
        or not identity.detector_sha256
    ):
        return False
    try:
        prior = json.loads((home.reports / f"{target.parent.name}.json").read_bytes())
    except (OSError, ValueError):
        return False
    return (
        isinstance(prior, dict)
        and prior.get("sha256") == target.parent.name
        and prior.get("verdict") == Verdict.clean.value
        and prior.get("incomplete_reason") is None
        and prior.get("policy") == policy.value
        and prior.get("ruleset_sha256") == identity.ruleset_sha256
        and prior.get("detector_sha256") == identity.detector_sha256
        and prior.get("path")
        in {redact(str(target)), redact(str(home.quarantine / target.parent.name / target.name))}
    )
