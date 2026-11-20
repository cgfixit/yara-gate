"""Replay captured model input through the scanner and record what the gate would decide.

A consumer captures what it was about to hand a model (a search snippet, the text of a fetched
page, text its own extractor took from a PDF, a cached passage) beside what it did with it.
This module scans exactly those bytes and builds one envelope per item: the gate's record, the
decision that record's read rule gives, and the consumer's own decision. It is a measurement.
It admits nothing, holds nothing, writes no report, and touches no gate home.

Each scan runs in a child process that the parent kills at a hard deadline, because the
scanner's own deadline cannot preempt every parser. A killed or crashed child, output that is
not one valid record, and a record for other bytes are ``failed``: there is no gate record, and
the proposed decision is a hold. An envelope carries hashes, identifiers, and the compact
report. It never carries the text.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import re
import statistics
import subprocess
import sys
import time
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

from yara_gate.models import DOCUMENT_NOTES, ScanPolicy, Severity

SCHEMA_VERSION = 1
# One capture line. Text a model reads is far smaller; a longer line is a malformed capture.
MAX_LINE_BYTES = 16 * 1024 * 1024
# The child is killed this long after the scanner's own deadline should have ended the scan.
KILL_GRACE = 30

COMPLETE = "complete"
TRUNCATED = "truncated"
FAILED = "failed"
ADMIT = "admit"
HOLD = "hold"

_ZERO = "0" * 64
_DIGEST = re.compile(r"[0-9a-f]{64}")
_CHANNEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_CLASSIFIER_KEY = re.compile(r"[a-z0-9_]{1,64}")
# C0 and C1 controls, and lone surrogates, which cannot be written as UTF-8 or passed in argv.
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\ud800-\udfff]")
_EXIT = {"clean": 0, "advisory": 0, "block": 1, "incomplete": 2}
_SEVERITIES = frozenset(item.value for item in Severity)
_LABELS = ("attack", "benign")
_ACTUAL = {"admitted": ADMIT, "held": HOLD}
_KEYS = frozenset(
    {
        "schema_version",
        "source_id",
        "channel",
        "text",
        "text_base64",
        "text_sha256",
        "name",
        "policy",
        "label",
        "actual_decision",
        "original_sha256",
        "extractor",
        "extractor_version",
        "classifier",
    }
)
# What ran, as the compact report names it. More than one set in a replay is a mixed baseline.
_IDENTITY = (
    "ruleset_sha256",
    "detector_sha256",
    "engine_version",
    "tool_version",
    "compiled_rules",
    "skipped_rule_files",
)


class CaptureError(ValueError):
    """A capture line that cannot be replayed. The message names a key, never a value."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CaptureItem:
    """One captured input: the exact bytes the consumer handed on, and what it says about them."""

    source_id: str
    channel: str
    data: bytes
    name: str = "item.txt"
    policy: ScanPolicy = ScanPolicy.agent_ingest
    label: str | None = None
    actual_decision: str | None = None
    original_sha256: str | None = None
    extractor: str | None = None
    extractor_version: str | None = None
    claimed_sha256: str | None = None
    classifier: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class ShadowScan:
    """One isolated scan. ``record`` is the gate's compact report only when it covers ``sha256``."""

    status: str
    status_reason: str | None
    sha256: str
    record: dict[str, Any] | None
    wall_seconds: float


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for key, value in pairs:
        if key in found:
            raise CaptureError("a key is repeated")
        found[key] = value
    return found


def _label(record: Mapping[str, Any], key: str, limit: int) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > limit or _CONTROL.search(value):
        raise CaptureError(f"{key} must be 1 to {limit} characters without control characters")
    return value


def _digest(record: Mapping[str, Any], key: str) -> str | None:
    value = record.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise CaptureError(f"{key} must be 64 lowercase hex digits")
    return value


def _classifier(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or not 0 < len(value) <= 32:
        raise CaptureError("classifier must be an object of 1 to 32 keys")
    for key, item in value.items():
        if _CLASSIFIER_KEY.fullmatch(key) is None:
            raise CaptureError("classifier keys are lowercase letters, digits, and underscores")
        if isinstance(item, float) and not math.isfinite(item):
            raise CaptureError("classifier numbers must be finite")
        if isinstance(item, str) and (len(item) > 256 or _CONTROL.search(item)):
            raise CaptureError("classifier strings are at most 256 characters, without controls")
        if item is not None and not isinstance(item, str | int | float | bool):
            raise CaptureError("classifier values are strings, numbers, booleans, or null")
    return dict(value)


def parse_item(line: bytes, *, policy: ScanPolicy = ScanPolicy.agent_ingest) -> CaptureItem:
    """Read one JSON capture line. ``policy`` applies to an item that names none."""
    try:
        record = json.loads(line, object_pairs_hook=_unique)
    except CaptureError:
        raise
    except (ValueError, RecursionError) as exc:
        raise CaptureError("not one JSON object") from exc
    if not isinstance(record, dict):
        raise CaptureError("not one JSON object")
    if not record.keys() <= _KEYS:
        raise CaptureError("an unknown key is present")
    version = record.get("schema_version", SCHEMA_VERSION)
    if type(version) is not int or version != SCHEMA_VERSION:
        raise CaptureError(f"schema_version must be {SCHEMA_VERSION}")
    source_id = _label(record, "source_id", 256)
    if source_id is None:
        raise CaptureError("source_id is required")
    channel = record.get("channel")
    if not isinstance(channel, str) or _CHANNEL.fullmatch(channel) is None:
        raise CaptureError("channel must be a lowercase label such as fetched-html")
    text, encoded = record.get("text"), record.get("text_base64")
    if (text is None) == (encoded is None):
        raise CaptureError("give text or text_base64, not both")
    if text is not None:
        if not isinstance(text, str):
            raise CaptureError("text must be a string")
        try:
            data = text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CaptureError("text is not valid Unicode; send text_base64") from exc
    else:
        if not isinstance(encoded, str):
            raise CaptureError("text_base64 must be a string")
        try:
            data = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CaptureError("text_base64 is not base64") from exc
    name = _label(record, "name", 255) or "item.txt"
    chosen = record.get("policy")
    try:
        item_policy = policy if chosen is None else ScanPolicy(chosen)
    except ValueError as exc:
        raise CaptureError("policy is not one the scanner has") from exc
    label = record.get("label")
    if label is not None and label not in _LABELS:
        raise CaptureError("label must be attack or benign")
    actual = record.get("actual_decision")
    if actual is not None and (not isinstance(actual, str) or actual not in _ACTUAL):
        raise CaptureError("actual_decision must be admitted or held")
    return CaptureItem(
        source_id=source_id,
        channel=channel,
        data=data,
        name=name,
        policy=item_policy,
        label=label,
        actual_decision=actual,
        original_sha256=_digest(record, "original_sha256"),
        extractor=_label(record, "extractor", 64),
        extractor_version=_label(record, "extractor_version", 64),
        claimed_sha256=_digest(record, "text_sha256"),
        classifier=_classifier(record.get("classifier")),
    )


def _checked(
    stdout: bytes, returncode: int, digest: str, policy: ScanPolicy
) -> tuple[dict[str, Any] | None, str | None]:
    """The child's record when it is one valid record for these bytes and policy; else why not."""
    if returncode not in (0, 1, 2):
        return None, f"worker exit {returncode}"
    try:
        lines = stdout.decode("utf-8").splitlines()
        record = json.loads(lines[0]) if len(lines) == 1 else None
    except (ValueError, RecursionError):
        record = None
    if not isinstance(record, dict):
        return None, "malformed output"
    verdict, reason = record.get("verdict"), record.get("incomplete_reason")
    findings = record.get("findings")
    code = record.get("exit_code")
    if (
        not isinstance(verdict, str)
        or verdict not in _EXIT
        or type(code) is not int
        or code != _EXIT[verdict]
        or returncode != _EXIT[verdict]
        or (verdict == "incomplete") != isinstance(reason, str)
        or (reason is not None and not isinstance(reason, str))
        or not isinstance(findings, list)
        or (verdict == "clean" and findings)
        or not all(
            isinstance(item, dict)
            and isinstance(item.get("rule_id"), str)
            and isinstance(item.get("severity"), str)
            and item["severity"] in _SEVERITIES
            for item in findings
        )
    ):
        return None, "malformed output"
    if reason == "scan failed":
        # The scanner raised. Its record names no policy and no rules, so it is not kept.
        return None, "scan failed"
    if record.get("policy") != policy.value:
        return None, "record is for another policy"
    # An input over the scanner's size limit is incomplete with the unknown (zero) digest.
    covered = record.get("sha256")
    if covered != digest and not (covered == _ZERO and verdict == "incomplete"):
        return None, "record is for other bytes"
    return record, None


def _run(command: Sequence[str], data: bytes, seconds: float) -> subprocess.CompletedProcess[bytes]:
    # Fixed argv built by shadow_scan from this interpreter and validated values; no shell.
    # Stderr is dropped: a traceback from a parser could quote the input.
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        command,
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=seconds,
    )


def shadow_scan(
    data: bytes,
    *,
    name: str = "item.txt",
    policy: ScanPolicy | str = ScanPolicy.agent_ingest,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    kill_after_s: float | None = None,
) -> ShadowScan:
    """Scan ``data`` in a child process and return its record, or why there is none.

    The child is killed ``kill_after_s`` seconds after it starts (``timeout_s`` plus
    ``KILL_GRACE`` when not given). The digest is taken here, before the child runs, so a
    record is accepted only for the bytes this caller holds.
    """
    # bytes(5) would build five NUL bytes, and bytes([73]) one byte nobody handed over.
    if not isinstance(data, bytes | bytearray | memoryview):
        raise TypeError("shadow_scan needs bytes")
    payload = bytes(data)
    digest = hashlib.sha256(payload).hexdigest()
    chosen = ScanPolicy(policy)
    label = PurePosixPath(str(name).replace("\\", "/")).name or "item.txt"
    # -P keeps the working directory off the child's import path.
    command = [sys.executable, "-P", "-m", "yara_gate.replay", "--worker"]
    command += [f"--name={label}", f"--policy={chosen.value}", f"--timeout={timeout_s}"]
    if rules_dir is not None:
        command.append(f"--rules={Path(rules_dir).absolute()}")
    deadline = timeout_s + KILL_GRACE if kill_after_s is None else kill_after_s
    started = time.monotonic()
    record: dict[str, Any] | None = None
    try:
        if not sys.executable:
            raise OSError("no interpreter")
        completed = _run(command, payload, deadline)
    except subprocess.TimeoutExpired:
        reason: str | None = "hard deadline"
    except (OSError, ValueError, OverflowError):
        # OverflowError: a deadline too large for the platform's clock.
        reason = "worker did not start"
    else:
        record, reason = _checked(completed.stdout, completed.returncode, digest, chosen)
    wall = round(time.monotonic() - started, 3)
    if record is None:
        status = FAILED
    elif record["verdict"] == "incomplete":
        reason = record["incomplete_reason"]
        status = TRUNCATED
    else:
        status = COMPLETE
    return ShadowScan(
        status=status, status_reason=reason, sha256=digest, record=record, wall_seconds=wall
    )


def proposed_decision(scan: ShadowScan, policy: ScanPolicy | str) -> str:
    """What the policy's read rule gives for this scan: ``admit`` or ``hold``.

    A message (``agent-ingest``) needs a complete clean record. A document
    (``agent-document``) needs that or the exact notes-only record. ``default`` admits a
    complete record that exits 0. Anything without a complete record for these bytes is a hold.
    """
    record = scan.record
    if scan.status != COMPLETE or record is None or record.get("sha256") != scan.sha256:
        return HOLD
    if record.get("exit_code") != 0 or record.get("incomplete_reason") is not None:
        return HOLD
    chosen = ScanPolicy(policy)
    if record.get("policy") != chosen.value:
        return HOLD
    if record.get("verdict") == "clean":
        return ADMIT
    if chosen is ScanPolicy.default:
        return ADMIT
    if chosen is ScanPolicy.agent_ingest:
        return HOLD
    findings = record.get("findings") or []
    notes_only = (
        record.get("verdict") == "advisory"
        and record.get("policy_reason") == DOCUMENT_NOTES
        and record.get("note") is True
        and record.get("advisory") is False
        and len(findings) > 0
        and all(item.get("severity") == "note" for item in findings)
    )
    return ADMIT if notes_only else HOLD


def _envelope(line: int, item: CaptureItem | None, **fields: Any) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "record": "item",
        "schema_version": SCHEMA_VERSION,
        "line": line,
        "source_id": item.source_id if item else None,
        "channel": item.channel if item else None,
        "label": item.label if item else None,
        "policy": item.policy.value if item else None,
        "text_sha256": None,
        "text_bytes": None,
        "original_sha256": item.original_sha256 if item else None,
        "extractor": item.extractor if item else None,
        "extractor_version": item.extractor_version if item else None,
        "status": FAILED,
        "status_reason": None,
        "proposed_decision": HOLD,
        "actual_decision": item.actual_decision if item else None,
        "agreement": None,
        "wall_seconds": None,
        "classifier": item.classifier if item else None,
        "gate": None,
    }
    envelope.update(fields)
    actual = envelope["actual_decision"]
    # Without a gate record there is nothing of the gate's to compare.
    if actual is not None and envelope["status"] != FAILED:
        proposed = envelope["proposed_decision"]
        envelope["agreement"] = "agree" if _ACTUAL[actual] == proposed else f"gate-would-{proposed}"
    return envelope


def replay_item(
    item: CaptureItem,
    *,
    line: int = 0,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    kill_after_s: float | None = None,
    timings: bool = True,
) -> dict[str, Any]:
    """Scan one captured item and return its envelope. ``timings=False`` leaves seconds out."""
    digest = hashlib.sha256(item.data).hexdigest()
    sizes = {"text_sha256": digest, "text_bytes": len(item.data)}
    if item.claimed_sha256 is not None and item.claimed_sha256 != digest:
        # The capture's own receipt names other bytes, so nothing here describes its text.
        return _envelope(line, item, status_reason="receipt mismatch", **sizes)
    scan = shadow_scan(
        item.data,
        name=item.name,
        policy=item.policy,
        rules_dir=rules_dir,
        timeout_s=timeout_s,
        kill_after_s=kill_after_s,
    )
    gate = scan.record
    if gate is not None and not timings:
        gate = {**gate, "scan_seconds": None, "yara_seconds": None}
    return _envelope(
        line,
        item,
        status=scan.status,
        status_reason=scan.status_reason,
        proposed_decision=proposed_decision(scan, item.policy),
        wall_seconds=scan.wall_seconds if timings else None,
        gate=gate,
        **sizes,
    )


def read_lines(handle: BinaryIO) -> Iterator[bytes | None]:
    """Each capture line, or ``None`` for one over ``MAX_LINE_BYTES`` (its rest is skipped)."""
    while True:
        line = handle.readline(MAX_LINE_BYTES + 1)
        if not line:
            return
        if len(line) > MAX_LINE_BYTES and not line.endswith(b"\n"):
            while True:
                rest = handle.readline(MAX_LINE_BYTES)
                if not rest or rest.endswith(b"\n"):
                    break
            yield None
        else:
            yield line


def replay_capture(
    handle: BinaryIO,
    *,
    policy: ScanPolicy = ScanPolicy.agent_ingest,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    kill_after_s: float | None = None,
    timings: bool = True,
) -> Iterator[dict[str, Any]]:
    """One envelope per non-blank capture line, in order. A bad line is a ``failed`` envelope."""
    for number, line in enumerate(read_lines(handle), start=1):
        if line is None:
            yield _envelope(number, None, status_reason="malformed capture: line too long")
            continue
        if not line.strip():
            continue
        try:
            item = parse_item(line, policy=policy)
        except CaptureError as exc:
            yield _envelope(number, None, status_reason=f"malformed capture: {exc}")
            continue
        yield replay_item(
            item,
            line=number,
            rules_dir=rules_dir,
            timeout_s=timeout_s,
            kill_after_s=kill_after_s,
            timings=timings,
        )


def _spread(values: list[float]) -> dict[str, float] | None:
    if not values:
        return None
    return {"median": round(statistics.median(values), 3), "max": round(max(values), 3)}


class Tally:
    """Counts over envelopes. A ``failed`` or ``truncated`` item is never counted as an admit."""

    def __init__(self) -> None:
        self.items = 0
        self.status = {COMPLETE: 0, TRUNCATED: 0, FAILED: 0}
        self.proposed = {ADMIT: 0, HOLD: 0}
        self.agreement = {"agree": 0, "gate-would-hold": 0, "gate-would-admit": 0, "unknown": 0}
        self.labels = {
            label: {ADMIT: 0, HOLD: 0, TRUNCATED: 0, FAILED: 0} for label in (*_LABELS, "unlabeled")
        }
        self.with_findings = 0
        self.rules: dict[str, int] = {}
        self.identities: list[dict[str, Any]] = []
        self.wall: list[float] = []
        self.scan: list[float] = []

    def add(self, envelope: Mapping[str, Any]) -> None:
        self.items += 1
        status = envelope["status"]
        self.status[status] += 1
        self.proposed[envelope["proposed_decision"]] += 1
        self.agreement[envelope["agreement"] or "unknown"] += 1
        outcome = envelope["proposed_decision"] if status == COMPLETE else status
        self.labels[envelope["label"] or "unlabeled"][outcome] += 1
        if isinstance(envelope["wall_seconds"], int | float):
            self.wall.append(envelope["wall_seconds"])
        gate = envelope["gate"]
        if gate is None:
            return
        rule_ids = {item["rule_id"] for item in gate["findings"]}
        self.with_findings += bool(rule_ids)
        for rule_id in rule_ids:
            self.rules[rule_id] = self.rules.get(rule_id, 0) + 1
        identity = {key: gate.get(key) for key in _IDENTITY}
        if identity not in self.identities:
            self.identities.append(identity)
        if isinstance(gate.get("scan_seconds"), int | float):
            self.scan.append(gate["scan_seconds"])

    def result(self) -> dict[str, Any]:
        return {
            "record": "summary",
            "schema_version": SCHEMA_VERSION,
            "items": self.items,
            "status": self.status,
            "proposed_decision": self.proposed,
            "agreement": self.agreement,
            "labels": self.labels,
            "items_with_findings": self.with_findings,
            "items_by_rule": dict(sorted(self.rules.items())),
            "identities": self.identities,
            "mixed_identities": len(self.identities) > 1,
            "wall_seconds": _spread(self.wall),
            "scan_seconds": _spread(self.scan),
        }


def summarize(envelopes: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """The summary record for a set of item envelopes."""
    tally = Tally()
    for envelope in envelopes:
        tally.add(envelope)
    return tally.result()


def _worker(argv: Sequence[str]) -> int:
    """The child: scan stdin in memory, print the compact report, exit as ``scan`` would."""
    parser = argparse.ArgumentParser(prog="python -m yara_gate.replay")
    parser.add_argument("--worker", action="store_true", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--timeout", type=int, required=True)
    parser.add_argument("--rules", type=Path)
    args = parser.parse_args(argv)

    from yara_gate.models import exit_code
    from yara_gate.report import compact_report
    from yara_gate.scanner import MAX_FILE_BYTES, scan_bytes

    data = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
    result = scan_bytes(
        data, name=args.name, timeout_s=args.timeout, rules_dir=args.rules, policy=args.policy
    )
    sys.stdout.write(json.dumps(compact_report(result), separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return exit_code(result)


if __name__ == "__main__":
    raise SystemExit(_worker(sys.argv[1:]))
