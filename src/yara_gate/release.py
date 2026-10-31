"""Building blocks for a reviewed release of a policy hold (#39).

Nothing here is reachable from the CLI yet, and nothing moves a file. Two pieces are needed
whatever the open #39 decisions turn out to be:

- ``release_refusal`` decides, from a fresh ``ScanResult``, whether a hold may be released.
  The answer comes from the result's findings and policy reason, never from the folder the
  bytes sit in, so a real block or an incomplete scan cannot be released.
- ``AuditLog`` is an append-only JSON Lines log whose lines are hash-chained, so an edited or
  deleted line is detected. It records no file content, names, or paths.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import unicodedata
from collections.abc import Collection
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from yara_gate.models import DOCUMENT_HOLD, INGEST_HOLD, ScanPolicy, ScanResult, Severity, Verdict

# A block that exists only because a policy promoted advisory or note findings.
_PROMOTION_REASONS = {
    ScanPolicy.agent_ingest: INGEST_HOLD,
    ScanPolicy.agent_document: DOCUMENT_HOLD,
}
_GENESIS = "0" * 64
MAX_REASON = 500
_FIELDS = ("time", "reviewer", "uid", "reason", "sha256", "ruleset_sha256", "policy", "rule_ids")


@dataclass(frozen=True)
class ReleaseKey:
    """What a release is bound to. Any change (bytes, rules, policy, findings) re-holds."""

    sha256: str
    ruleset_sha256: str
    policy: str
    rule_ids: tuple[str, ...]


def release_refusal(
    result: ScanResult,
    *,
    policies: Collection[ScanPolicy] = (ScanPolicy.agent_ingest, ScanPolicy.agent_document),
) -> str | None:
    """Return why ``result`` may not be released, or None when it is a releasable hold.

    ``policies`` limits which policy holds are releasable; restricting it to agent-document
    keeps a message (agent-ingest) unreleasable. ``result`` must come from a scan run now with
    the current rules: a stored report can predate a rule change.
    """
    if result.verdict is Verdict.incomplete or result.incomplete_reason:
        return "incomplete scan"
    if result.verdict is not Verdict.block:
        return "not held"
    if result.policy not in policies:
        return "policy is not releasable"
    if result.policy_reason != _PROMOTION_REASONS.get(result.policy):
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
    if release_refusal(result, policies=tuple(_PROMOTION_REASONS)) is not None or not ruleset:
        raise ValueError("result is not a releasable hold")
    return ReleaseKey(
        sha256=result.sha256,
        ruleset_sha256=ruleset,
        policy=result.policy.value,
        rule_ids=tuple(sorted({finding.rule_id for finding in result.findings})),
    )


def current_reviewer() -> tuple[str, int | None]:
    """The operating-system user running the command: a reviewer name is not taken from a flag."""
    uid = os.getuid() if hasattr(os, "getuid") else None
    return getpass.getuser(), uid


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


class AuditLog:
    """Append-only, hash-chained JSON Lines.

    Each line's ``prev`` is the SHA-256 of the line before it, so an edit or a deletion breaks
    the chain. The newest line has no successor, so an edit to it alone is not detected by
    ``verify``; ``head`` returns the hash to record elsewhere (the release command's output,
    for example), and a later ``head`` that differs shows the tail changed. Appends are not
    locked: one operator at a time is assumed.
    """

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(
        self,
        key: ReleaseKey,
        *,
        reason: str,
        reviewer: tuple[str, int | None] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        name, uid = reviewer or current_reviewer()
        entry: dict[str, Any] = {
            "time": (now or datetime.now(UTC)).isoformat(),
            "reviewer": name,
            "uid": uid,
            "reason": _check_reason(reason),
            "sha256": key.sha256,
            "ruleset_sha256": key.ruleset_sha256,
            "policy": key.policy,
            "rule_ids": list(key.rule_ids),
            "prev": self._last_hash(),
        }
        line = (json.dumps(entry, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return entry

    def verify(self) -> int:
        """Check every line and the chain; return the number of entries or raise AuditLogError."""
        if not self.path.exists():
            return 0
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise AuditLogError("last line is truncated")
        previous = _GENESIS
        count = 0
        for number, line in enumerate(data.splitlines(keepends=True), start=1):
            try:
                entry = json.loads(line)
            except ValueError:
                raise AuditLogError(f"line {number} is not JSON") from None
            if not isinstance(entry, dict) or any(field not in entry for field in _FIELDS):
                raise AuditLogError(f"line {number} is missing a field")
            if entry.get("prev") != previous:
                raise AuditLogError(f"line {number} does not follow line {number - 1}")
            previous = hashlib.sha256(line).hexdigest()
            count += 1
        return count

    def head(self) -> str:
        """The SHA-256 of the newest line after a full ``verify``, or 64 zeros for no log."""
        return self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS
        self.verify()
        lines = self.path.read_bytes().splitlines(keepends=True)
        return hashlib.sha256(lines[-1]).hexdigest() if lines else _GENESIS
