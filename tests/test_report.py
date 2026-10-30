import json
from pathlib import Path

import pytest

from yara_gate.models import Verdict
from yara_gate.quarantine import GatePaths, process_inbox_file
from yara_gate.report import redact, write_reports
from yara_gate.samples import EICAR, clean_text, eicar_bytes, injection_markdown
from yara_gate.scanner import scan_file


def test_redact_home_prefix() -> None:
    home = str(Path.home())
    assert redact(home + "/YaraGate/clean/abc") == "~/YaraGate/clean/abc"
    assert redact("/tmp/other") == "/tmp/other"


def test_reports_omit_matched_text(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    eicar = home.inbox / "eicar.com"
    eicar.write_bytes(eicar_bytes())
    blocked = process_inbox_file(home, eicar, rules_dir=rules_copy)
    note = home.inbox / "note.md"
    note.write_bytes(injection_markdown())
    noted = process_inbox_file(home, note, rules_dir=rules_copy)
    phrase = "ignore previous instructions"
    for digest in (blocked.sha256, noted.sha256):
        for suffix in (".sarif", ".json"):
            text = (home.reports / f"{digest}{suffix}").read_text(encoding="utf-8")
            assert EICAR.decode() not in text
            assert phrase not in text
    sarif = json.loads((home.reports / f"{blocked.sha256}.sarif").read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "agent_eicar"
    assert "byteOffset" in result["locations"][0]["physicalLocation"]["region"]
    compact = json.loads((home.reports / f"{noted.sha256}.json").read_text(encoding="utf-8"))
    assert compact["verdict"] == "advisory"
    assert compact["advisory"] is False
    assert compact["note"] is True
    assert compact["exit_code"] == 0


def test_clean_still_writes_both_reports(tmp_path: Path, rules_copy: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_bytes(clean_text())
    result = scan_file(path, rules_dir=rules_copy)
    assert result.verdict is Verdict.clean
    sarif, js = write_reports(tmp_path / "reports", result)
    assert sarif.is_file() and js.is_file()
    body = js.read_text(encoding="utf-8")
    assert '"verdict": "clean"' in body
    assert result.findings == []


def test_failed_report_write_keeps_previous_reports(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "notes.txt"
    path.write_bytes(clean_text())
    result = scan_file(path, rules_dir=rules_copy)
    reports = tmp_path / "reports"
    before = {report: report.read_bytes() for report in write_reports(reports, result)}
    real_write = Path.write_text

    def torn_write(self: Path, data: str, *args: object, **kwargs: object) -> int:
        real_write(self, data[: len(data) // 2], *args, **kwargs)  # type: ignore[arg-type]
        raise OSError("disk full")

    monkeypatch.setattr(Path, "write_text", torn_write)
    with pytest.raises(OSError, match="disk full"):
        write_reports(reports, result)
    monkeypatch.undo()
    assert {report: report.read_bytes() for report in before} == before
    assert sorted(reports.iterdir()) == sorted(before)


def test_redact_needs_a_path_separator(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", "/x/u")
    assert redact("/x/u") == "~"
    assert redact("/x/u/notes.txt") == "~/notes.txt"
    assert redact("/x/u2/secret-project.txt") == "/x/u2/secret-project.txt"


def test_reports_record_what_ran(tmp_path: Path, rules_copy: Path) -> None:
    from yara_gate import __version__
    from yara_gate.rules import compile_sources

    path = tmp_path / "notes.txt"
    path.write_bytes(clean_text())
    result = scan_file(path, rules_dir=rules_copy)
    _rules, _skipped, _error, compiled, _skips = compile_sources(rules_copy)
    assert result.compiled_rules == compiled > 0
    assert result.tool_version == __version__
    assert result.scan_seconds is not None and 0 <= result.scan_seconds < 30
    _sarif_path, js = write_reports(tmp_path / "reports", result)
    compact = json.loads(js.read_text(encoding="utf-8"))
    assert compact["compiled_rules"] == compiled
    assert compact["tool_version"] == __version__
    assert compact["scan_seconds"] == result.scan_seconds
    sarif = json.loads(_sarif_path.read_text(encoding="utf-8"))
    assert sarif["runs"][0]["properties"]["compiled_rules"] == compiled
    assert compact["units_scanned"] == 1
    assert compact["bytes_scanned"] == len(clean_text())
    assert compact["yara_seconds"] is not None
    assert sarif["runs"][0]["properties"]["views_scanned"] == compact["views_scanned"]


def test_coverage_counts_members_and_views(rules_copy: Path) -> None:
    import io
    import zipfile

    from yara_gate.scanner import scan_bytes

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("a.html", "caf&eacute;\n")
        archive.writestr("b.txt", "plain\n")
    result = scan_bytes(buf.getvalue(), name="bundle.zip", rules_dir=rules_copy)
    assert result.units_scanned == 3
    assert result.views_scanned == {"html-unescaped": 1}
    broken = scan_bytes(b"PK\x03\x04broken", name="bad.zip", rules_dir=rules_copy)
    assert broken.incomplete_reason is not None
    assert broken.units_scanned == 0 and broken.yara_seconds is None
