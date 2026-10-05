from yara_gate.models import (
    Finding,
    FindingSource,
    ScanResult,
    Severity,
    Verdict,
    exit_code,
    result_from_findings,
)


def test_exit_codes() -> None:
    incomplete = ScanResult(
        sha256="a" * 64, verdict=Verdict.incomplete, incomplete_reason="timeout"
    )
    blocked = ScanResult(sha256="b" * 64, verdict=Verdict.block)
    advisory = ScanResult(sha256="c" * 64, verdict=Verdict.advisory, advisory=True)
    clean = ScanResult(sha256="d" * 64, verdict=Verdict.clean)
    assert exit_code(incomplete) == 2
    assert exit_code(blocked) == 1
    assert exit_code(advisory) == 0
    assert exit_code(clean) == 0


def test_block_beats_advisory() -> None:
    findings = [
        Finding(rule_id="note", severity=Severity.advisory, source=FindingSource.yara),
        Finding(rule_id="bad", severity=Severity.block, source=FindingSource.yara),
    ]
    result = result_from_findings(sha256="e" * 64, path="x", findings=findings)
    assert result.verdict is Verdict.block
    assert result.advisory is True


def test_incomplete_wins() -> None:
    findings = [Finding(rule_id="bad", severity=Severity.block, source=FindingSource.yara)]
    result = result_from_findings(
        sha256="f" * 64,
        path="x",
        findings=findings,
        incomplete_reason="timeout",
    )
    assert result.verdict is Verdict.incomplete
    assert exit_code(result) == 2
