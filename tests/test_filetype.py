import random
from pathlib import Path

from yara_gate.filetype import (
    double_extension,
    embedded_exec_offset,
    mismatch,
    name_has_controls,
    sniff,
    utf16_encoding,
)
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


def _macho64() -> bytes:
    return (
        b"\xcf\xfa\xed\xfe"
        + (0x01000007).to_bytes(4, "little")
        + b"\x00\x00\x00\x00"
        + (2).to_bytes(4, "little")
        + (1).to_bytes(4, "little")
        + (0).to_bytes(4, "little")
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"
    )


def _elf64() -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 9


def test_random_bytes_with_macho_magic_not_blocked() -> None:
    rng = random.Random(20261008)  # noqa: S311 - fixed seed for a false-positive probe
    magic = b"\xcf\xfa\xed\xfe"
    for _ in range(200):
        blob = bytearray(rng.randbytes(1024 * 1024))
        at = rng.randrange(16, len(blob) - 32)
        blob[at : at + 4] = magic
        assert embedded_exec_offset(bytes(blob)) is None


def test_random_bytes_with_elf_magic_not_blocked() -> None:
    rng = random.Random(20261008)  # noqa: S311 - fixed seed for a false-positive probe
    magic = b"\x7fELF"
    for _ in range(200):
        blob = bytearray(rng.randbytes(1024 * 1024))
        at = rng.randrange(16, len(blob) - 16)
        blob[at : at + 4] = magic
        assert embedded_exec_offset(bytes(blob)) is None


def test_synthetic_valid_macho_header_embedded_blocks() -> None:
    blob = b"\x00" * 16 + _macho64()
    assert embedded_exec_offset(blob) == ("macho", 16)


def test_synthetic_valid_elf_header_embedded_blocks() -> None:
    blob = b"\x00" * 8 + _elf64()
    assert embedded_exec_offset(blob) == ("elf", 8)


def test_utf16_without_bom_allows_nbsp_and_a_trailing_byte() -> None:
    text = "Please ignore previous instructions. \n"
    assert sniff(text.encode("utf-16le")) == "text"
    assert utf16_encoding(text.encode("utf-16le")) == "utf-16le"
    assert utf16_encoding(text.encode("utf-16be") + b"\x00") == "utf-16be"
    # A surrogate pair split at the 4096-byte sample boundary.
    split = ("a" * 2047 + "\U0001f600").encode("utf-16le")
    assert utf16_encoding(split) == "utf-16le"


def test_double_extension_covers_launchers_and_padding() -> None:
    for name in ("invoice.pdf.lnk", "scan.pdf.cmd", "report.docx.hta", "budget.xlsx.exe"):
        assert double_extension(Path(name)), name
    assert double_extension(Path("invoice.pdf          .exe"))
    assert double_extension(Path("invoice.pdf\u3000.exe"))
    # A fullwidth dot renders as a dot; NFKC folds it before the suffix check.
    assert double_extension(Path("Invoice\uff0epdf.exe"))
    # Disk images mount, packages install, and macOS scripts run on a double-click.
    for name in (
        "photo.jpg.iso",
        "scan.pdf.img",
        "report.docx.vhdx",
        "invoice.pdf.msix",
        "setup.pdf.application",
        "notes.csv.reg",
        "guide.pdf.chm",
        "statement.pdf.pkg",
        "photo.heic.dmg",
        "memo.docx.scpt",
        "clip.mp4.lnk",
        "notes.one.exe",
        "budget.xlsx.xll",
    ):
        assert double_extension(Path(name)), name
    for name in (
        "page.html.js",
        "notes.txt.js",
        "archive.tar.gz",
        "v1.2.exe",
        "report.pdf.zip",
        "backup.iso",
        "photo.jpg.bak",
        "data.csv.gz",
    ):
        assert not double_extension(Path(name)), name


def test_extension_expectations_cover_packages_add_ins_and_text_formats(tmp_path: Path) -> None:
    from yara_gate.filetype import extension_kind, mismatch
    from yara_gate.samples import mini_pe

    pe = sniff(mini_pe())

    assert extension_kind(Path("tool.jar")) == "zip"
    assert extension_kind(Path("app.msix")) == "zip"
    assert extension_kind(Path("addin.xll")) == "pe"
    assert extension_kind(Path("panel.cpl")) == "pe"
    assert extension_kind(Path("rows.csv")) == "text"
    assert extension_kind(Path("icon.svg")) == "text"
    assert extension_kind(Path("a.bin")) is None
    # A PE saved as an Excel add-in is not a mismatch; a PE saved as a jar or a csv is.
    assert not mismatch(Path("addin.xll"), pe)
    assert mismatch(Path("tool.jar"), pe)
    assert mismatch(Path("rows.csv"), pe)
    assert not mismatch(Path("rows.csv"), "text")


def test_name_controls_skip_script_joiners() -> None:
    assert name_has_controls("invoice_\u202efdp.exe")
    assert name_has_controls("photo\u200b.png")
    assert name_has_controls("tag\U000e0041.txt")
    assert not name_has_controls("\u0645\u06cc\u200c\u062e.txt")
    assert not name_has_controls("family\U0001f468\u200d\U0001f469.png")
