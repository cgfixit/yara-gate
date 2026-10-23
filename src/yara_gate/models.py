"""Verdicts for one scan. Exit codes are derived from the verdict.

Plain dataclasses, not pydantic models: every ``yara-gate scan`` that a caller starts per file
is a fresh process, and building pydantic's schemas cost more than scanning a small file.
``model_dump`` and ``model_dump_json`` keep the output shape library callers already use.
"""

import json
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Verdict(StrEnum):
    clean = "clean"
    advisory = "advisory"
    block = "block"
    incomplete = "incomplete"


class Severity(StrEnum):
    advisory = "advisory"
    block = "block"


class ScanPolicy(StrEnum):
    default = "default"
    agent_ingest = "agent-ingest"


class FindingSource(StrEnum):
    yara = "yara"
    heuristic = "heuristic"
    filetype = "filetype"


class _Dumpable:
    __slots__ = ()

    def model_dump(self, *, exclude: set[str] | None = None) -> dict[str, Any]:
        data: dict[str, Any] = asdict(self)  # type: ignore[call-overload]
        for name in exclude or ():
            data.pop(name, None)
        return data

    def model_dump_json(self) -> str:
        return json.dumps(self.model_dump(), separators=(",", ":"), ensure_ascii=False)


@dataclass(kw_only=True, slots=True)
class Finding(_Dumpable):
    rule_id: str
    offset: int | None = None
    length: int | None = None
    severity: Severity
    source: FindingSource
    member_path: list[str] = field(default_factory=list)
    view: str = "raw"
    namespace: str | None = None

    def __post_init__(self) -> None:
        # A bad value must fail here, as it did when this was validated on construction.
        self.severity = Severity(self.severity)
        self.source = FindingSource(self.source)


@dataclass(kw_only=True, slots=True)
class ScanResult(_Dumpable):
    sha256: str
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)
    advisory: bool = False
    incomplete_reason: str | None = None
    path: str = ""
    ruleset_sha256: str | None = None
    engine_version: str | None = None
    skipped_rule_files: int = 0
    policy: ScanPolicy = ScanPolicy.default
    policy_reason: str | None = None

    def __post_init__(self) -> None:
        self.verdict = Verdict(self.verdict)
        self.policy = ScanPolicy(self.policy)


def exit_code(result: ScanResult) -> int:
    if result.verdict is Verdict.incomplete:
        return 2
    if result.verdict is Verdict.block:
        return 1
    return 0


def result_from_findings(
    *,
    sha256: str,
    path: str,
    findings: list[Finding],
    incomplete_reason: str | None = None,
) -> ScanResult:
    if incomplete_reason:
        return ScanResult(
            sha256=sha256,
            path=path,
            verdict=Verdict.incomplete,
            findings=findings,
            advisory=False,
            incomplete_reason=incomplete_reason,
        )
    has_block = any(item.severity is Severity.block for item in findings)
    has_advisory = any(item.severity is Severity.advisory for item in findings)
    if has_block:
        verdict = Verdict.block
    elif has_advisory:
        verdict = Verdict.advisory
    else:
        verdict = Verdict.clean
    return ScanResult(
        sha256=sha256,
        path=path,
        verdict=verdict,
        findings=findings,
        advisory=has_advisory,
        incomplete_reason=None,
    )
