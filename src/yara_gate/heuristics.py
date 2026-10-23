"""Office, PDF, and embedded-executable checks that sit beside YARA."""

import io
import re
import unicodedata
import zipfile
from pathlib import Path

from yara_gate.filetype import OFFICE_EXTS, OLE, embedded_exec_offset, sniff
from yara_gate.models import Finding, FindingSource, Severity

PDF_TOKENS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
)
OFFICE_KEYWORDS = ("Shell", "CreateObject", "URLDownloadToFile")


_LETTER_PREFIXES = (
    "ARABIC LETTER",
    "DEVANAGARI LETTER",
    "BENGALI LETTER",
    "GURMUKHI LETTER",
    "GUJARATI LETTER",
    "ORIYA LETTER",
    "TAMIL LETTER",
    "TELUGU LETTER",
    "KANNADA LETTER",
    "MALAYALAM LETTER",
    "SINHALA LETTER",
)
_VARIATION = frozenset({0xFE0E, 0xFE0F})


def heuristic_findings(path: Path, data: bytes) -> tuple[list[Finding], str | None]:
    findings = pdf_findings(data)
    findings.extend(embedded_findings(data))
    office, error = office_findings(path, data)
    findings.extend(office)
    return findings, error


def joiner_findings(text: str) -> list[Finding]:
    """Block a ZWNJ or ZWJ that is not holding an emoji or a joining script together."""
    if "\u200c" not in text and "\u200d" not in text:
        return []
    findings: list[Finding] = []
    offset = 0
    chars = list(text)
    for index, char in enumerate(chars):
        size = len(char.encode("utf-8"))
        if char in {"\u200c", "\u200d"} and not _joiner_allowed(chars, index):
            findings.append(
                Finding(
                    rule_id="heuristic_invisible_joiner",
                    offset=offset,
                    length=size,
                    severity=Severity.block,
                    source=FindingSource.heuristic,
                )
            )
        offset += size
    return findings


def pdf_findings(data: bytes) -> list[Finding]:
    if sniff(data) != "pdf":
        return []
    findings: list[Finding] = []
    for token in PDF_TOKENS:
        found = _pdf_name_span(data, token)
        if found is None:
            continue
        offset, length = found
        name = token.decode("ascii").removeprefix("/")
        findings.append(
            Finding(
                rule_id=f"heuristic_pdf_{name}",
                offset=offset,
                length=length,
                severity=Severity.block,
                source=FindingSource.heuristic,
            )
        )
    return findings


def embedded_findings(data: bytes) -> list[Finding]:
    found = embedded_exec_offset(data)
    if found is None:
        return []
    kind, offset = found
    length = 4 if kind != "pe" else 2
    return [
        Finding(
            rule_id=f"heuristic_embedded_{kind}",
            offset=offset,
            length=length,
            severity=Severity.block,
            source=FindingSource.heuristic,
        )
    ]


def office_findings(path: Path, data: bytes) -> tuple[list[Finding], str | None]:
    if not _looks_like_office(path, data):
        return [], None
    from oletools.olevba import VBA_Parser, detect_autoexec

    try:
        parser = VBA_Parser(str(path), data=data)
    except Exception:
        if _claims_vba(data):
            return [], "office parse error"
        return [], None
    try:
        try:
            detected = bool(parser.detect_vba_macros())
        except Exception:
            if _claims_vba(data):
                return [], "office parse error"
            return [], None
        if not detected:
            return [], None
        code = _extracted_code(parser)
        if not code:
            # ponytail: olevba saw a VBA project whose dir stream did not yield source.
            # Scan that project only. A full MS-OVBA dir writer would retire this.
            code = _project_bytes(data).decode("latin-1", errors="ignore")
        findings: list[Finding] = []
        if detect_autoexec(code):
            findings.append(_office("heuristic_office_autoexec"))
        for keyword in OFFICE_KEYWORDS:
            if re.search(rf"(?i)\b{re.escape(keyword)}\b", code):
                findings.append(_office(f"heuristic_office_{keyword.lower()}"))
        return findings, None
    finally:
        close = getattr(parser, "close", None)
        if callable(close):
            close()


def _office(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.block,
        source=FindingSource.heuristic,
    )


def _extracted_code(parser: object) -> str:
    extract = getattr(parser, "extract_macros", None)
    if not callable(extract):
        return ""
    parts: list[str] = []
    try:
        for item in extract():
            if len(item) >= 4 and isinstance(item[3], str):
                parts.append(item[3])
    except Exception:
        return ""
    return "\n".join(parts)


def _looks_like_office(path: Path, data: bytes) -> bool:
    if path.suffix.lower() in OFFICE_EXTS:
        return True
    if data.startswith(OLE):
        return True
    return data.startswith(b"PK") and _claims_vba(data)


def _claims_vba(data: bytes) -> bool:
    return b"vbaProject" in data or data.startswith(OLE)


def _project_bytes(data: bytes) -> bytes:
    if data.startswith(OLE):
        return data
    if not data.startswith(b"PK"):
        return b""
    chunks: list[bytes] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                blob = archive.read(info)
                if blob.startswith(OLE):
                    chunks.append(blob)
    except zipfile.BadZipFile:
        return b""
    return b"\n".join(chunks)


def _joiner_allowed(chars: list[str], index: int) -> bool:
    left = _joiner_neighbor(chars, index, -1)
    right = _joiner_neighbor(chars, index, 1)
    if not left or not right:
        return False
    if chars[index] == "\u200d" and _emoji(left) and _emoji(right):
        return True
    return _script_letter(left) and _script_letter(right)


def _joiner_neighbor(chars: list[str], index: int, step: int) -> str:
    cursor = index + step
    while 0 <= cursor < len(chars) and ord(chars[cursor]) in _VARIATION:
        cursor += step
    if cursor < 0 or cursor >= len(chars):
        return ""
    return chars[cursor]


def _emoji(char: str) -> bool:
    code = ord(char)
    if 0x1F3FB <= code <= 0x1F3FF or 0x1F1E6 <= code <= 0x1F1FF:
        return True
    if 0x1F000 <= code <= 0x1FAFF or 0x2600 <= code <= 0x27BF:
        return True
    return "EMOJI" in unicodedata.name(char, "")


def _script_letter(char: str) -> bool:
    if unicodedata.category(char) not in {"Lo", "Lm"}:
        return False
    name = unicodedata.name(char, "")
    return any(name.startswith(prefix) for prefix in _LETTER_PREFIXES)


_PDF_NAME = re.compile(rb"/(?:[^\x00\t\n\f\r /<>\[\]()#%]|#[0-9A-Fa-f]{2})+")


def _pdf_name_span(data: bytes, token: bytes) -> tuple[int, int] | None:
    for match in _PDF_NAME.finditer(data):
        decoded = _decode_pdf_name(match.group())
        if decoded == token:
            return match.start(), len(match.group())
    return None


def _decode_pdf_name(token: bytes) -> bytes:
    if b"#" not in token:
        return token
    decoded = bytearray()
    index = 0
    while index < len(token):
        if token[index] == ord("#") and index + 2 < len(token):
            decoded.append(int(token[index + 1 : index + 3], 16))
            index += 3
            continue
        decoded.append(token[index])
        index += 1
    return bytes(decoded)
