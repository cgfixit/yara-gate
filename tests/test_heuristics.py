from pathlib import Path

from yara_gate.heuristics import heuristic_findings
from yara_gate.samples import docm_with_autoopen, risky_pdf, text_with_embedded_pe


def test_pdf_javascript_does_not_also_count_as_js_prefix(tmp_path: Path) -> None:
    data = b"%PDF-1.4\n1 0 obj\n<< /JavaScript (app.alert) >>\nendobj\n%%EOF\n"
    path = tmp_path / "only.pdf"
    path.write_bytes(data)
    findings, error = heuristic_findings(path, data)
    assert error is None
    ids = {item.rule_id for item in findings}
    assert "heuristic_pdf_JavaScript" in ids
    assert "heuristic_pdf_JS" not in ids


def test_openaction_pdf_blocks(tmp_path: Path) -> None:
    path = tmp_path / "open.pdf"
    data = risky_pdf()
    path.write_bytes(data)
    findings, error = heuristic_findings(path, data)
    assert error is None
    ids = {item.rule_id for item in findings}
    assert "heuristic_pdf_OpenAction" in ids
    assert "heuristic_pdf_JavaScript" in ids


def test_harmless_autoopen_docm_blocks(tmp_path: Path) -> None:
    path = tmp_path / "macro.docm"
    data = docm_with_autoopen()
    path.write_bytes(data)
    findings, error = heuristic_findings(path, data)
    assert error is None
    assert any(item.rule_id == "heuristic_office_autoexec" for item in findings)


def test_embedded_pe_blocks(tmp_path: Path) -> None:
    path = tmp_path / "notes.bin"
    data = text_with_embedded_pe()
    path.write_bytes(data)
    findings, error = heuristic_findings(path, data)
    assert error is None
    assert any(item.rule_id == "heuristic_embedded_pe" for item in findings)
