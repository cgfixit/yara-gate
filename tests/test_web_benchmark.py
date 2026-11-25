"""An unfinished or mixed-identity benchmark cannot support a hold rate."""

import runpy
from pathlib import Path

import pytest

from yara_gate import report
from yara_gate.models import ScanResult

SCRIPT = Path(__file__).resolve().parents[1] / "docs/research/probe_web_benchmark.py"


def test_withhold_rates_for_unfinished_scans(rules_copy: Path) -> None:
    probe = runpy.run_path(str(SCRIPT))
    probe["_start"](str(rules_copy))
    benign = probe["scan_page"](("<p>Ordinary page</p>", "no"))
    unfinished = probe["scan_page"](("PK\x03\x04", "yes"))
    assert probe["summarize"]([benign])["read_rules"]["agent-document"]["benign_held"] == 0
    summary = probe["summarize"]([benign, unfinished])
    assert summary["incomplete"] == 2
    assert "read_rules" not in summary
    assert all(record["decision"] == "hold" for record in unfinished["policies"].values())


@pytest.mark.parametrize(("digest", "distinct", "unidentified"), [("a" * 64, 2, 0), (None, 1, 2)])
def test_policy_identity_required(
    rules_copy: Path,
    monkeypatch: pytest.MonkeyPatch,
    digest: str | None,
    distinct: int,
    unidentified: int,
) -> None:
    probe = runpy.run_path(str(SCRIPT))
    probe["_start"](str(rules_copy))
    compact_report = report.compact_report

    def with_other_identity(result: ScanResult) -> dict[str, object]:
        record = compact_report(result)
        if digest is None or record["policy"] == "agent-ingest":
            record["detector_sha256"] = digest
        return record

    monkeypatch.setattr(report, "compact_report", with_other_identity)
    row = probe["scan_page"](("<p>Ordinary page</p>", "no"))
    if distinct > 1:
        assert row["identity"] is None
    summary = probe["summarize"]([row])
    assert len(summary["identities"]) == distinct
    assert summary["unidentified"] == unidentified
    assert "read_rules" not in summary
