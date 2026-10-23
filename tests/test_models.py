import json

import pytest

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


def test_finding_rejects_bad_input() -> None:
    for kwargs in (
        {"rule_id": "x", "severity": "nope", "source": FindingSource.yara},
        {"rule_id": "x", "severity": Severity.block, "source": FindingSource.yara, "bogus": 1},
        {"severity": Severity.block, "source": FindingSource.yara},
    ):
        with pytest.raises((TypeError, ValueError)):
            Finding(**kwargs)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ScanResult(sha256="a" * 64, verdict="maybe")  # type: ignore[arg-type]
    assert Finding(rule_id="x", severity="block", source="yara").severity is Severity.block  # type: ignore[arg-type]


def test_dump_keeps_the_library_shape() -> None:
    finding = Finding(rule_id="é", severity=Severity.block, source=FindingSource.yara, offset=1)
    result = ScanResult(sha256="a" * 64, verdict=Verdict.block, findings=[finding], path="p")
    assert list(result.model_dump()) == list(ScanResult.__dataclass_fields__)
    assert result.model_dump(exclude={"path", "findings"})["verdict"] is Verdict.block
    assert "path" not in result.model_dump(exclude={"path"})
    text = result.model_dump_json()
    assert ", " not in text
    assert '": ' not in text
    decoded = json.loads(text)
    assert decoded["findings"][0] == {
        "rule_id": "é",
        "offset": 1,
        "length": None,
        "severity": "block",
        "source": "yara",
        "member_path": [],
        "view": "raw",
        "namespace": None,
    }
    assert decoded["policy"] == "default"
