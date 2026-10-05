from pathlib import Path

from yara_gate.filetype import embedded_exec_offset, mismatch, sniff
from yara_gate.samples import mini_pe, risky_pdf, zip_named_pdf


def test_sniff_pdf_zip_and_pe() -> None:
    assert sniff(risky_pdf()) == "pdf"
    assert sniff(zip_named_pdf()) == "zip"
    assert sniff(mini_pe()) == "pe"


def test_pdf_extension_on_a_zip_mismatches(tmp_path: Path) -> None:
    path = tmp_path / "not-a.pdf"
    path.write_bytes(zip_named_pdf())
    assert mismatch(path, sniff(path.read_bytes())) is True


def test_embedded_pe_is_not_the_first_byte() -> None:
    blob = b"notes " + mini_pe()
    found = embedded_exec_offset(blob)
    assert found is not None
    assert found[0] == "pe"
    assert found[1] > 0
    assert embedded_exec_offset(mini_pe()) is None


def test_java_class_magic_is_not_macho() -> None:
    assert sniff(b"\xca\xfe\xba\xbe" + b"\x00" * 16) != "macho"
