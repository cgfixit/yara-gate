"""Eligibility and a gate-home audit log for reviewed agent-document holds."""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from yara_gate.models import (
    DOCUMENT_HOLD,
    DOCUMENT_RELEASE,
    ScanPolicy,
    ScanResult,
    Severity,
    Verdict,
)

# Owner decision 2: only an agent-document hold is releasable. A message held under
# agent-ingest stays held. Policy selection is the caller's, so this holds only while
# callers scan messages under agent-ingest.
RELEASABLE_POLICY = ScanPolicy.agent_document
_GENESIS = "0" * 64
MAX_REASON = 500
_FIELDS = ("time", "uid", "user", "reason", "sha256", "ruleset_sha256", "policy", "rule_ids")


@dataclass(frozen=True)
class ReleaseKey:
    """What a release is bound to. Any change (bytes, rules, policy, findings) re-holds."""

    sha256: str
    ruleset_sha256: str
    policy: str
    rule_ids: tuple[str, ...]


def release_refusal(result: ScanResult) -> str | None:
    """Return why ``result`` may not be released, or None when it is a releasable hold.

    ``result`` must come from a scan run now with the current rules: a stored report can
    predate a rule change.
    """
    if result.verdict is Verdict.incomplete or result.incomplete_reason:
        return "incomplete scan"
    if result.policy is not RELEASABLE_POLICY:
        return "only an agent-document hold is releasable"
    if result.verdict is not Verdict.block:
        return "not held"
    if result.policy_reason != DOCUMENT_HOLD:
        return "not a policy hold"
    if any(finding.severity is Severity.block for finding in result.findings):
        return "block-severity finding"
    if not result.findings:
        return "no findings"
    if not result.ruleset_sha256:
        return "no ruleset digest"
    return None


def release_key(result: ScanResult) -> ReleaseKey:
    ruleset = result.ruleset_sha256
    if release_refusal(result) is not None or not ruleset:
        raise ValueError("result is not a releasable hold")
    return ReleaseKey(
        sha256=result.sha256,
        ruleset_sha256=ruleset,
        policy=result.policy.value,
        rule_ids=tuple(sorted({finding.rule_id for finding in result.findings})),
    )


def release_log(home: Path) -> AuditLog:
    return AuditLog(home / "releases.jsonl")


def reviewed_result(result: ScanResult) -> ScanResult:
    return replace(result, verdict=Verdict.advisory, policy_reason=DOCUMENT_RELEASE)


def apply_release(result: ScanResult, home: Path) -> ScanResult:
    if release_refusal(result) is not None:
        return result
    log = release_log(home)
    try:
        if (log.path.exists() or log.head_path.exists()) and log.contains(release_key(result)):
            return reviewed_result(result)
    except (AuditLogError, OSError, ValueError):
        # Broken audit evidence cannot authorize a read.
        pass
    return result


def current_reviewer() -> tuple[int | None, str]:
    """(uid, user name) of the OS account running the command; a reviewer is never a flag.

    The uid is the identity anchor and the name is display text. Windows has no uid, so the
    name is the only identity there. Either records who ran the command, not how well they
    reviewed.
    """
    uid = os.getuid() if hasattr(os, "getuid") else None
    return uid, getpass.getuser()


class AuditLogError(Exception):
    pass


def _check_reason(reason: str) -> str:
    reason = reason.strip()
    if not reason:
        raise ValueError("reason is empty")
    if len(reason) > MAX_REASON:
        raise ValueError(f"reason exceeds {MAX_REASON} characters")
    if any(unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") for char in reason):
        raise ValueError("reason contains a control or format character")
    return reason


@contextmanager
def _exclusive(path: Path) -> Iterator[None]:
    """Hold an exclusive lock on ``path`` (created if missing) for the duration."""
    path.parent.mkdir(parents=True, exist_ok=True)
    handle: IO[bytes] = open(path, "a+b")  # closed in finally
    try:
        if sys.platform == "win32":
            import msvcrt

            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        handle.close()  # closing releases the lock on both platforms


def _replace_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="ascii")
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


class AuditLog:
    """Append-only, hash-chained JSON Lines with a sidecar head.

    Each line's ``prev`` is the SHA-256 of the line before it, so editing or deleting an
    earlier line breaks the chain. ``<log>.head`` holds the SHA-256 of the newest line, so an
    edit to the newest line, a deleted suffix, or a deleted log is caught too. Someone who can
    rewrite both files in the gate home can still forge a consistent pair: the chain is tamper
    evidence, not authentication, and the gate home's permissions are the boundary. Pass the
    head printed after a release, kept outside the gate home, as ``expected_head`` to close
    that gap. Appends are serialized with an exclusive lock on ``<log>.lock``.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.head_path = path.with_name(path.name + ".head")
        self.lock_path = path.with_name(path.name + ".lock")

    def append(
        self,
        key: ReleaseKey,
        *,
        reason: str,
        reviewer: tuple[int | None, str] | None = None,
        now: datetime | None = None,
    ) -> str:
        """Append one release and return the new head hash."""
        uid, user = reviewer or current_reviewer()
        checked = _check_reason(reason)
        with _exclusive(self.lock_path):
            previous = self._verified_head()
            entry: dict[str, Any] = {
                "time": (now or datetime.now(UTC)).isoformat(),
                "uid": uid,
                "user": user,
                "reason": checked,
                "sha256": key.sha256,
                "ruleset_sha256": key.ruleset_sha256,
                "policy": key.policy,
                "rule_ids": list(key.rule_ids),
                "prev": previous,
            }
            line = (json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
            fd = os.open(self.path, flags, 0o600)
            try:
                if os.write(fd, line) != len(line):
                    raise AuditLogError("audit append was incomplete")
                os.fsync(fd)
            finally:
                os.close(fd)
            head = hashlib.sha256(line).hexdigest()
            _replace_text(self.head_path, head + "\n")
        return head

    def verify(self, *, expected_head: str | None = None) -> int:
        """Check the chain and the head; return the number of entries or raise AuditLogError."""
        return len(self.entries(expected_head=expected_head))

    def entries(self, *, expected_head: str | None = None) -> list[dict[str, Any]]:
        """Read the same snapshot that was verified, under the append lock."""
        with _exclusive(self.lock_path):
            entries: list[dict[str, Any]] = []
            self._verified_head(expected_head=expected_head, entries=entries)
            return entries

    def contains(self, key: ReleaseKey) -> bool:
        return any(
            entry["sha256"] == key.sha256
            and entry["ruleset_sha256"] == key.ruleset_sha256
            and entry["policy"] == key.policy
            and entry["rule_ids"] == list(key.rule_ids)
            for entry in self.entries()
        )

    def head(self) -> str:
        """The verified head hash, or 64 zeros when no release was ever logged."""
        with _exclusive(self.lock_path):
            return self._verified_head()

    def _verified_head(
        self, *, expected_head: str | None = None, entries: list[dict[str, Any]] | None = None
    ) -> str:
        log_exists, head_exists = self.path.exists(), self.head_path.exists()
        if not log_exists and not head_exists:
            computed = _GENESIS
        elif not log_exists:
            raise AuditLogError("log is missing but its head record exists")
        elif not head_exists:
            raise AuditLogError("head record is missing")
        else:
            computed = self._chain(entries)
            recorded = self.head_path.read_text(encoding="ascii").strip()
            if recorded != computed:
                raise AuditLogError("head does not match the newest line")
        if expected_head is not None and expected_head != computed:
            raise AuditLogError("head does not match the expected head")
        return computed

    def _chain(self, entries: list[dict[str, Any]] | None) -> str:
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise AuditLogError("last line is truncated")
        previous = _GENESIS
        for number, line in enumerate(data.splitlines(keepends=True), start=1):
            try:
                entry = json.loads(line)
            except ValueError:
                raise AuditLogError(f"line {number} is not JSON") from None
            if not isinstance(entry, dict) or any(field not in entry for field in _FIELDS):
                raise AuditLogError(f"line {number} is missing a field")
            if entry.get("prev") != previous:
                raise AuditLogError(f"line {number} does not follow line {number - 1}")
            if entries is not None:
                entries.append(entry)
            previous = hashlib.sha256(line).hexdigest()
        return previous
