"""Sniff a file from its bytes. The extension is never the type."""

import unicodedata
from pathlib import Path

OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP = b"PK\x03\x04"
ZIP_EMPTY = b"PK\x05\x06"
PDF = b"%PDF"
ELF = b"\x7fELF"
MACHO = (
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
)

# What an extension claims. OOXML is a zip. Legacy Office is OLE.
EXT_EXPECT: dict[str, str] = {
    ".pdf": "pdf",
    ".zip": "zip",
    ".docx": "zip",
    ".xlsx": "zip",
    ".pptx": "zip",
    ".docm": "zip",
    ".xlsm": "zip",
    ".pptm": "zip",
    ".doc": "ole",
    ".xls": "ole",
    ".ppt": "ole",
    ".exe": "pe",
    ".dll": "pe",
    ".scr": "pe",
    ".elf": "elf",
    ".txt": "text",
    ".md": "text",
    ".html": "text",
    ".htm": "text",
    ".json": "text",
    ".yaml": "text",
    ".yml": "text",
}

TEXT_EXTS = {".txt", ".md", ".html", ".htm", ".json", ".yaml", ".yml"}
OFFICE_EXTS = {".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".ppt", ".pptm", ".ppsm"}


def sniff(data: bytes) -> str:
    if data.startswith(OLE):
        return "ole"
    if data.startswith(ZIP) or data.startswith(ZIP_EMPTY):
        return "zip"
    if data.startswith(PDF):
        return "pdf"
    if _pe_at(data, 0):
        return "pe"
    if data.startswith(ELF):
        return "elf"
    if data.startswith(MACHO):
        return "macho"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if _mostly_text(data) or utf16_encoding(data) is not None:
        return "text"
    return "unknown"


def utf16_encoding(data: bytes) -> str | None:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    sample = data[:4096]
    if len(sample) < 4 or len(sample) % 2:
        return None
    encoding: str | None = None
    if sample[1::2].count(0) > len(sample) // 4:
        encoding = "utf-16le"
    elif sample[0::2].count(0) > len(sample) // 4:
        encoding = "utf-16be"
    if encoding is None:
        return None
    try:
        text = sample.decode(encoding)
    except UnicodeError:
        return None
    if all(
        char.isprintable() or char in "\r\n\t" or unicodedata.category(char) == "Cf"
        for char in text
    ):
        return encoding
    return None


def extension_kind(path: Path) -> str | None:
    return EXT_EXPECT.get(path.suffix.lower())


def mismatch(path: Path, kind: str) -> bool:
    expected = extension_kind(path)
    if expected is None:
        return False
    return expected != kind


def _mostly_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:4096]
    odd = sum(1 for byte in sample if byte < 9 or (13 < byte < 32))
    return odd / len(sample) < 0.05


def _pe_at(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 0x40 > len(data):
        return False
    if data[offset : offset + 2] != b"MZ":
        return False
    e_lfanew = int.from_bytes(data[offset + 0x3C : offset + 0x40], "little")
    if e_lfanew < 0x40 or e_lfanew > 0x400:
        return False
    pe = offset + e_lfanew
    return pe + 4 <= len(data) and data[pe : pe + 4] == b"PE\x00\x00"


def embedded_exec_offset(data: bytes) -> tuple[str, int] | None:
    """An executable header that does not start the file."""
    start = 1
    while True:
        found = data.find(b"MZ", start)
        if found < 0:
            break
        if _pe_at(data, found):
            return ("pe", found)
        start = found + 1
    elf_at = data.find(ELF, 1)
    if elf_at >= 0:
        return ("elf", elf_at)
    for magic in MACHO:
        at = data.find(magic, 1)
        if at >= 0:
            return ("macho", at)
    return None
