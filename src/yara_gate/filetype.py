"""Sniff a file from its bytes. The extension is never the type."""

import codecs
import re
import unicodedata
from pathlib import Path
from typing import Literal

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
    # Other zip containers that a double-click opens or installs.
    ".jar": "zip",
    ".apk": "zip",
    ".appx": "zip",
    ".msix": "zip",
    ".appxbundle": "zip",
    ".msixbundle": "zip",
    ".xpi": "zip",
    ".vsix": "zip",
    ".nupkg": "zip",
    ".whl": "zip",
    ".epub": "zip",
    ".odt": "zip",
    ".ods": "zip",
    ".odp": "zip",
    ".doc": "ole",
    ".xls": "ole",
    ".ppt": "ole",
    ".exe": "pe",
    ".dll": "pe",
    ".scr": "pe",
    ".xll": "pe",
    ".cpl": "pe",
    ".ocx": "pe",
    ".sys": "pe",
    ".drv": "pe",
    ".efi": "pe",
    ".elf": "elf",
    ".txt": "text",
    ".md": "text",
    ".html": "text",
    ".htm": "text",
    ".json": "text",
    ".yaml": "text",
    ".yml": "text",
    ".csv": "text",
    ".svg": "text",
    ".xml": "text",
    ".rtf": "text",
    ".ini": "text",
    ".url": "text",
    ".scf": "text",
    ".reg": "text",
    ".ps1": "text",
    ".vbs": "text",
    ".js": "text",
    ".sh": "text",
    ".bat": "text",
    ".cmd": "text",
}

TEXT_EXTS = {".txt", ".md", ".html", ".htm", ".json", ".yaml", ".yml"}
OFFICE_EXTS = {".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".ppt", ".pptm", ".ppsm"}
DOCUMENT_SUFFIXES = frozenset(
    {
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".webp",
        ".heic",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".odt",
        ".ods",
        ".csv",
        ".txt",
        ".md",
        ".rtf",
        ".html",
        ".htm",
        ".svg",
        ".eml",
    }
)
_DECOY = r"pdf|png|jpe?g|gif|bmp|webp|heic|docx?|xlsx?|pptx?|odt|ods|csv|rtf|mp[34]|mov|one"
# A decoy suffix, optional padding, then a suffix that runs or opens something on its own.
# Plain text and HTML decoys pair only with binaries: names such as page.html.js are real code.
# Launchers: Windows script hosts and shortcuts, disk images that mount, app packages and
# ClickOnce manifests that install, registry and setup files, and macOS scripts and packages.
_DOUBLE_EXT = re.compile(
    rf"(?i).*\.(?:(?:{_DECOY}|txt|html?)[\s._-]*\.(?:exe|dll|scr|app|com|pif|cpl|msi|xll)"
    rf"|(?:{_DECOY})[\s._-]*\.(?:lnk|url|scf|hta|js|jse|vbs|vbe|wsf|wsh|bat|cmd|ps1|msc|jar"
    r"|iso|img|vhdx?|msix(bundle)?|appx(bundle)?|application|appref-ms|reg|inf|chm|diagcab"
    r"|msp|mst|pkg|dmg|scpt|terminal|workflow|webloc"
    r"|desktop|command|library-ms|searchconnector-ms))$"
)
# Directional and invisible controls that can reorder or hide part of a displayed name.
# ZWNJ and ZWJ are left out: Persian and Indic names use them.
_NAME_CONTROLS = re.compile(
    "[\u061c\u200b\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\U000e0000-\U000e007f]"
)
_EXECUTABLE_KINDS = frozenset({"pe", "elf", "macho"})


def double_extension(path: Path) -> bool:
    # NFKC folds a fullwidth dot (U+FF0E) in "Invoice．pdf.exe" to the ASCII dot Explorer shows.
    return _DOUBLE_EXT.match(unicodedata.normalize("NFKC", path.name)) is not None


def name_has_controls(name: str) -> bool:
    return _NAME_CONTROLS.search(name) is not None


def is_document_name(path: Path) -> bool:
    return path.suffix.lower() in DOCUMENT_SUFFIXES


def is_executable_kind(kind: str) -> bool:
    return kind in _EXECUTABLE_KINDS


def sniff(data: bytes) -> str:
    if data.startswith(OLE):
        return "ole"
    if data.startswith(ZIP) or data.startswith(ZIP_EMPTY):
        return "zip"
    if data.startswith(PDF):
        return "pdf"
    if _pe_at(data, 0):
        return "pe"
    if _elf_header(data, 0):
        return "elf"
    if _macho_header(data, 0):
        return "macho"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if _mostly_text(data) or utf16_encoding(data) is not None:
        return "text"
    return "unknown"


def utf16_encoding(data: bytes) -> str | None:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    # Trim to whole code units: one trailing byte must not hide UTF-16 text.
    sample = data[: min(len(data), 4096) & ~1]
    if len(sample) < 4:
        return None
    encoding: str | None = None
    if sample[1::2].count(0) > len(sample) // 4:
        encoding = "utf-16le"
    elif sample[0::2].count(0) > len(sample) // 4:
        encoding = "utf-16be"
    if encoding is None:
        return None
    try:
        # The sample can end inside a surrogate pair; final=False keeps that half for later.
        text = codecs.getincrementaldecoder(encoding)().decode(sample, final=False)
    except UnicodeError:
        return None
    # isprintable() rejects every space separator but U+0020, including NBSP.
    if all(
        char.isprintable() or char in "\r\n\t" or unicodedata.category(char) in {"Cf", "Zs"}
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
    start = 1
    while True:
        elf_at = data.find(ELF, start)
        if elf_at < 0:
            break
        if _elf_header(data, elf_at):
            return ("elf", elf_at)
        start = elf_at + 1
    for magic in MACHO:
        start = 1
        while True:
            at = data.find(magic, start)
            if at < 0:
                break
            if _macho_header(data, at):
                return ("macho", at)
            start = at + 1
    return None


def _elf_header(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 16 > len(data) or data[offset : offset + 4] != ELF:
        return False
    return data[offset + 4] in (1, 2) and data[offset + 5] in (1, 2) and data[offset + 6] == 1


def _macho_header(data: bytes, offset: int) -> bool:
    if offset < 0 or offset + 28 > len(data):
        return False
    magic = data[offset : offset + 4]
    if magic not in MACHO:
        return False
    little = magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
    wide = magic in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe")
    endian: Literal["little", "big"] = "little" if little else "big"
    header = 32 if wide else 28
    if offset + header > len(data):
        return False
    cputype = int.from_bytes(data[offset + 4 : offset + 8], endian, signed=True)
    if (cputype & 0xFF) not in (7, 12):
        return False
    filetype = int.from_bytes(data[offset + 12 : offset + 16], endian)
    ncmds = int.from_bytes(data[offset + 16 : offset + 20], endian)
    sizeofcmds = int.from_bytes(data[offset + 20 : offset + 24], endian)
    if not 1 <= filetype <= 12 or not 0 < ncmds <= 512:
        return False
    return sizeofcmds <= len(data) - (offset + header)
