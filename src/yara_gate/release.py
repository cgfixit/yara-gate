"""Building blocks for a reviewed release of an agent-document hold (#39).

Nothing here is reachable from the CLI yet, and nothing moves a file: owner decision 3 on #39
puts rule-precision work first and release activation second. A release is a person's
acceptance of one exact file with its exact findings under one ruleset and policy. It never
makes content safe to execute or obey.

- ``release_refusal`` decides, from a fresh ``ScanResult``, whether a hold may be released.
  The answer comes from the result's findings and policy reason, never from the folder the
  bytes sit in, so a real block or an incomplete scan cannot be released. Only agent-document
  holds qualify (owner decision 2); every agent-ingest result is refused.
- ``AuditLog`` is an append-only JSON Lines log. Lines are hash-chained, appends hold an
  exclusive lock, and the newest line's hash is kept in a sidecar head file, so an edited
  line, a deleted line or suffix, and a removed head are all detected. It records no file
  content, names, or paths.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import sys
import unicodedata
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from yara_gate.models import DOCUMENT_HOLD, ScanPolicy, ScanResult, Severity, Verdict

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
    handle: IO[bytes] = open(path, "a+b")  # noqa: SIM115 - closed in finally
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
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            head = hashlib.sha256(line).hexdigest()
            _replace_text(self.head_path, head + "\n")
        return head

    def verify(self, *, expected_head: str | None = None) -> int:
        """Check the chain and the head; return the number of entries or raise AuditLogError."""
        self._verified_head(expected_head=expected_head)
        if not self.path.exists():
            return 0
        return len(self.path.read_bytes().splitlines())

    def entries(self, *, expected_head: str | None = None) -> list[dict[str, Any]]:
        """Every entry, after a full ``verify``."""
        self.verify(expected_head=expected_head)
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_bytes().splitlines()]

    def head(self) -> str:
        """The verified head hash, or 64 zeros when no release was ever logged."""
        return self._verified_head()

    def _verified_head(self, *, expected_head: str | None = None) -> str:
        log_exists, head_exists = self.path.exists(), self.head_path.exists()
        if not log_exists and not head_exists:
            computed = _GENESIS
        elif not log_exists:
            raise AuditLogError("log is missing but its head record exists")
        elif not head_exists:
            raise AuditLogError("head record is missing")
        else:
            computed = self._chain()
            recorded = self.head_path.read_text(encoding="ascii").strip()
            if recorded != computed:
                raise AuditLogError("head does not match the newest line")
        if expected_head is not None and expected_head != computed:
            raise AuditLogError("head does not match the expected head")
        return computed

    def _chain(self) -> str:
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
            previous = hashlib.sha256(line).hexdigest()
        return previous
