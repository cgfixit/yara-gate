"""The classic-YARA probe: its recorded cases still hold, and a folder check names what fails."""

import runpy
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "docs/research/probe_yara_compat.py"


@pytest.fixture(scope="module")
def probe() -> dict[str, Any]:
    return runpy.run_path(str(SCRIPT))


def test_every_recorded_case_answers_as_recorded(
    probe: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    # A YARA-X upgrade that moves one of these changes what a ported rule does.
    assert probe["run_cases"](False) == 0
    out = capsys.readouterr().out
    assert "no longer answer as recorded" not in out
    answers = {case.name: probe["gate_answer"](case) for case in probe["CASES"]}
    assert answers["xor-fullword"] == "no match"
    assert answers["regex-unknown-escape"] == "match"
    assert answers["include"] == "E044"


def test_folder_check_names_the_file_the_line_and_the_cause(
    probe: dict[str, Any], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "tagged.yara").write_text(
        "rule Tagged : SuppressMalwareDetectionNotification "
        '{ strings: $a = "abc" condition: $a }\n',
        encoding="utf-8",
    )
    (tmp_path / "external.yar").write_text(
        'rule NeedsName\n{\n  strings:\n    $a = "abc"\n  condition:\n'
        "    $a and filename matches /x/\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "base.yar").write_text("rule is_elf { condition: uint32(0) == 0x464c457f }\n")
    (tmp_path / "uses.yar").write_text("rule elf_thing { condition: is_elf and filesize < 10 }\n")
    assert probe["run_folder"](tmp_path, False) == 1
    out = capsys.readouterr().out
    assert "ok    tagged.yara: 1 rule(s); no verdict_on_match: a match blocks" in out
    assert "tags are not read by the gate" in out
    assert "FAIL  external.yar line 6: E009 unknown identifier `filename`" in out
    assert "yara_gate_name" in out
    assert "FAIL  uses.yar line 1: E009 unknown identifier `is_elf`" in out
    assert "`is_elf` is a rule in base.yar" in out
    assert "4 file(s): 2 compile, 2 fail" in out


def test_folder_check_passes_the_shipped_rules(
    probe: dict[str, Any], rules_copy: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert probe["run_folder"](rules_copy / "local", True) == 0
    assert '"fail": 0' in capsys.readouterr().out
