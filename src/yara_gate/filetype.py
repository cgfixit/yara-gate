"""Sniff a file from its bytes. The extension is never the type."""

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
    if _mostly_text(data):
        return "text"
    return "unknown"


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
