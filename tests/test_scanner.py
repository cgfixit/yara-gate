import io
import zipfile
from pathlib import Path

import pytest

from yara_gate.models import Verdict, exit_code
from yara_gate.samples import (
    EICAR,
    base64_text,
    bidi_markdown,
    clean_text,
    docm_with_autoopen,
    eicar_bytes,
    hidden_html,
    injection_markdown,
    nested_zip,
    risky_pdf,
    zip_named_pdf,
)
from yara_gate.scanner import ScanTimeout, archive_limit, scan_file


def _scan(tmp_path: Path, rules_copy: Path, name: str, payload: bytes):
    path = tmp_path / name
    path.write_bytes(payload)
    return scan_file(path, rules_dir=rules_copy)


def test_eicar_blocks(tmp_path: Path, rules_copy: Path) -> None:
    result = _scan(tmp_path, rules_copy, "eicar.com", eicar_bytes())
    assert result.verdict is Verdict.block
    assert exit_code(result) == 1
    assert any(item.rule_id == "agent_eicar" for item in result.findings)
    assert EICAR.decode() not in result.model_dump_json()


def test_docm_and_pdf_block(tmp_path: Path, rules_copy: Path) -> None:
    docm = _scan(tmp_path, rules_copy, "macro.docm", docm_with_autoopen())
    pdf = _scan(tmp_path, rules_copy, "open.pdf", risky_pdf())
    assert docm.verdict is Verdict.block
    assert pdf.verdict is Verdict.block


def test_zip_named_pdf_is_advisory(tmp_path: Path, rules_copy: Path) -> None:
    result = _scan(tmp_path, rules_copy, "not-a.pdf", zip_named_pdf())
    assert result.verdict is Verdict.advisory
    assert exit_code(result) == 0
    assert any(item.rule_id == "filetype_mismatch_zip" for item in result.findings)


def test_pe_named_pdf_blocks(tmp_path: Path, rules_copy: Path) -> None:
    from yara_gate.samples import mini_pe

    result = _scan(tmp_path, rules_copy, "report.pdf", mini_pe())
    assert result.verdict is Verdict.block
    assert any(item.rule_id == "filetype_mismatch_pe" for item in result.findings)


def test_bidi_blocks_and_injection_is_advisory(tmp_path: Path, rules_copy: Path) -> None:
    blocked = _scan(tmp_path, rules_copy, "hidden.md", bidi_markdown())
    noted = _scan(tmp_path, rules_copy, "note.md", injection_markdown())
    assert blocked.verdict is Verdict.block
    assert noted.verdict is Verdict.advisory
    assert noted.advisory is True
    assert "ignore previous instructions" not in noted.model_dump_json()


def test_base64_and_hidden_html_are_advisory(tmp_path: Path, rules_copy: Path) -> None:
    blob = _scan(tmp_path, rules_copy, "blob.txt", base64_text())
    html = _scan(tmp_path, rules_copy, "hide.html", hidden_html())
    renamed = _scan(tmp_path, rules_copy, "blob.bin", base64_text())
    assert blob.verdict is Verdict.advisory
    assert any(item.rule_id == "agent_hidden_html" for item in html.findings)
    assert renamed.verdict is Verdict.clean


def test_clean_text(tmp_path: Path, rules_copy: Path) -> None:
    result = _scan(tmp_path, rules_copy, "notes.txt", clean_text())
    assert result.verdict is Verdict.clean
    assert exit_code(result) == 0
    assert result.findings == []


def test_zip_of_eicar_blocks(tmp_path: Path, rules_copy: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("inner.txt", eicar_bytes())
    result = _scan(tmp_path, rules_copy, "bundle.zip", buf.getvalue())
    assert result.verdict is Verdict.block
    assert any(item.rule_id == "agent_eicar" for item in result.findings)


def test_archive_depth() -> None:
    assert archive_limit(nested_zip(3)) is None
    assert archive_limit(nested_zip(4)) == "archive depth exceeds 3"


def test_over_size_is_incomplete(tmp_path: Path, rules_copy: Path) -> None:
    path = tmp_path / "big.bin"
    path.touch()
    with path.open("wb") as handle:
        handle.truncate(100 * 1024 * 1024 + 1)
    result = scan_file(path, rules_dir=rules_copy)
    assert result.verdict is Verdict.incomplete
    assert exit_code(result) == 2
    assert result.incomplete_reason == "file exceeds 100MB"


def test_broken_rule_is_incomplete(tmp_path: Path) -> None:
    rules = tmp_path / "broken"
    rules.mkdir()
    (rules / "bad.yar").write_text(
        "rule nope { condition: not_a_real_identifier }\n",
        encoding="utf-8",
    )
    target = tmp_path / "plain.txt"
    target.write_text("hello\n", encoding="utf-8")
    result = scan_file(target, rules_dir=rules)
    assert result.verdict is Verdict.incomplete
    assert result.incomplete_reason == "no rules compiled"


def test_timeout_is_incomplete(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yara_gate import scanner

    def boom(rules: object, data: bytes, timeout_s: int, ext: str) -> object:
        raise ScanTimeout

    monkeypatch.setattr(scanner, "_invoke_scan", boom)
    result = _scan(tmp_path, rules_copy, "slow.txt", clean_text())
    assert result.verdict is Verdict.incomplete
    assert result.incomplete_reason == "timeout"


def test_scan_does_not_move_the_file(tmp_path: Path, rules_copy: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_bytes(clean_text())
    scan_file(path, rules_dir=rules_copy)
    assert path.is_file()
    assert path.read_bytes() == clean_text()
