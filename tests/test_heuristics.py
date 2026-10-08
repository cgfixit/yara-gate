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


def test_pdf_hex_escaped_names_block(tmp_path: Path) -> None:
    encoded = b"%PDF-1.4\n<< /OpenAct#69on /J#61vaScript >>\n%%EOF\n"
    plain = b"%PDF-1.4\n<< /OpenAction /JavaScript >>\n%%EOF\n"
    encoded_findings, encoded_error = heuristic_findings(tmp_path / "encoded.pdf", encoded)
    plain_findings, plain_error = heuristic_findings(tmp_path / "plain.pdf", plain)
    assert encoded_error is None
    assert plain_error is None
    encoded_ids = {item.rule_id for item in encoded_findings}
    plain_ids = {item.rule_id for item in plain_findings}
    assert "heuristic_pdf_OpenAction" in encoded_ids
    assert "heuristic_pdf_JavaScript" in encoded_ids
    assert encoded_ids == plain_ids
    javascript = next(
        item for item in encoded_findings if item.rule_id == "heuristic_pdf_JavaScript"
    )
    assert javascript.offset is not None
    assert encoded[javascript.offset : javascript.offset + 2] == b"/J"


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
