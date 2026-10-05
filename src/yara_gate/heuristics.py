"""Office, PDF, and embedded-executable checks that sit beside YARA."""

import io
import re
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


def heuristic_findings(path: Path, data: bytes) -> tuple[list[Finding], str | None]:
    findings = pdf_findings(data)
    findings.extend(embedded_findings(data))
    office, error = office_findings(path, data)
    findings.extend(office)
    return findings, error


def pdf_findings(data: bytes) -> list[Finding]:
    if sniff(data) != "pdf":
        return []
    findings: list[Finding] = []
    for token in PDF_TOKENS:
        offset = _token_at(data, token)
        if offset < 0:
            continue
        name = token.decode("ascii").removeprefix("/")
        findings.append(
            Finding(
                rule_id=f"heuristic_pdf_{name}",
                offset=offset,
                length=len(token),
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


def _token_at(data: bytes, token: bytes) -> int:
    start = 0
    while True:
        offset = data.find(token, start)
        if offset < 0:
            return -1
        after = offset + len(token)
        if after >= len(data) or not chr(data[after]).isalpha():
            return offset
        start = offset + 1
