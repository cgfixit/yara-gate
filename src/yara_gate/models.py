"""Verdicts for one scan. Exit codes are derived from the verdict."""

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


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


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    offset: int | None = None
    length: int | None = None
    severity: Severity
    source: FindingSource
    member_path: list[str] = Field(default_factory=list)
    view: str = "raw"
    namespace: str | None = None


class ScanResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sha256: str
    verdict: Verdict
    findings: list[Finding] = Field(default_factory=list)
    advisory: bool = False
    incomplete_reason: str | None = None
    path: str = ""
    ruleset_sha256: str | None = None
    engine_version: str | None = None
    skipped_rule_files: int = 0
    policy: ScanPolicy = ScanPolicy.default
    policy_reason: str | None = None


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
