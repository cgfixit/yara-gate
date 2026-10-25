"""Office, PDF, and embedded-executable checks that sit beside YARA."""

import io
import json
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
    findings.extend(pickle_reduce_findings(path, data))
    findings.extend(model_header_findings(path, data))
    findings.extend(ooxml_structure_findings(path, data))
    findings.extend(mcp_tool_findings(path, data))
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


# Walk opcodes only. pickle.loads would run the callable this check exists to stop.
_PICKLE_MODULES = frozenset({"os", "subprocess", "builtins", "posix", "nt"})
_PICKLE_NAMES = frozenset({"eval", "exec"})
_SHELL_COMMAND = re.compile(r"(?i)^(sh|bash|zsh|curl|wget|osascript|powershell|pwsh)(\s|$)")
_SHELL_ARG = re.compile(r"(?i)\b(sh|bash|curl|wget|osascript|powershell|pwsh)\b")
# Tool-poisoning text hides in a tool description: a shouted tag, a "do not mention" clause,
# or a request to read a key or client config and pass it along in another argument.
_HIDDEN_INSTRUCTION = re.compile(
    r"(?i)do not (tell|mention|inform|reveal|show)( this| it| that)?( to)? the user"
    r"|don'?t (tell|mention)( this| it)?( to)? the user"
    r"|ignore (all )?previous instructions"
    r"|<\s*important\s*>"
    r"|before (using|calling|running) this tool,? (read|open|cat)\b"
    r"|~?/?\.ssh/|\bid_(rsa|ed25519)\b|\bmcp\.json\b"
    r"|\bpass (its|the|their|this) contents?\b|\b(as|in) an? sidenote\b"
)


def pickle_reduce_findings(path: Path, data: bytes) -> list[Finding]:
    if not _pickle_candidate(path, data):
        return []
    offset = _pickle_reduce_offset(data)
    if offset is None:
        return []
    return [
        Finding(
            rule_id="heuristic_pickle_reduce",
            offset=offset,
            length=1,
            severity=Severity.block,
            source=FindingSource.heuristic,
        )
    ]


def model_header_findings(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    if suffix == ".safetensors" and _safetensors_bad(data):
        findings.append(_block("heuristic_safetensors_header"))
    if (suffix == ".gguf" or data.startswith(b"GGUF")) and _gguf_bad(data):
        findings.append(_block("heuristic_gguf_header"))
    return findings


def ooxml_structure_findings(path: Path, data: bytes) -> list[Finding]:
    name = path.as_posix().lower()
    findings: list[Finding] = []
    if name.endswith("vbaproject.bin"):
        findings.append(_block("heuristic_ooxml_vba"))
    if "oleobject" in name:
        findings.append(_advisory("heuristic_ooxml_oleobject"))
    if b"http://schemas.openxmlformats.org" not in data:
        return findings
    if b"altChunk" in data:
        findings.append(_advisory("heuristic_ooxml_altchunk"))
    if b"DDE" in data and (b"instrText" in data or b"fldChar" in data):
        findings.append(_block("heuristic_ooxml_dde"))
    return findings


def mcp_tool_findings(path: Path, data: bytes) -> list[Finding]:
    if path.suffix.lower() != ".json" or not data.lstrip().startswith((b"{", b"[")):
        return []
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return []
    hits: list[str] = []
    _walk_mcp(parsed, hits, 0)
    findings: list[Finding] = []
    if "shell" in hits:
        findings.append(_advisory("heuristic_mcp_shell"))
    if "hidden" in hits:
        findings.append(_advisory("heuristic_mcp_hidden_instruction"))
    return findings


def _block(rule_id: str) -> Finding:
    return Finding(rule_id=rule_id, severity=Severity.block, source=FindingSource.heuristic)


def _advisory(rule_id: str) -> Finding:
    return Finding(rule_id=rule_id, severity=Severity.advisory, source=FindingSource.heuristic)


def _pickle_candidate(path: Path, data: bytes) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".pkl", ".pickle", ".pt", ".pth", ".ckpt"}:
        return data[:1] == b"\x80"
    return len(data) >= 2 and data[0] == 0x80 and data[1] <= 5


def _pickle_reduce_offset(data: bytes) -> int | None:
    stack: list[str | tuple[str, str] | None] = []
    offset = 0
    steps = 0
    while offset < len(data) and steps < 100_000:
        steps += 1
        opcode = data[offset]
        start = offset
        offset += 1
        if opcode == 0x80:  # PROTO
            offset += 1
        elif opcode == 0x95:  # FRAME
            offset += 8
        elif opcode == 0x2E:  # STOP
            return None
        elif opcode == 0x94:  # MEMOIZE
            continue
        elif opcode == 0x28:  # MARK
            stack.append(None)
        elif opcode in {0x29, 0x5D, 0x7D, 0x4E, 0x88, 0x89, 0x8F}:
            stack.append(None)
        elif opcode == 0x4B:  # BININT1
            offset += 1
            stack.append(None)
        elif opcode == 0x4D:  # BININT2
            offset += 2
            stack.append(None)
        elif opcode == 0x4A:  # BININT
            offset += 4
            stack.append(None)
        elif opcode == 0x47:  # BINFLOAT
            offset += 8
            stack.append(None)
        elif opcode == 0x8C:  # SHORT_BINUNICODE
            text, offset = _counted(data, offset, 1)
            if text is None:
                return None
            stack.append(text)
        elif opcode == 0x58:  # BINUNICODE
            text, offset = _counted(data, offset, 4)
            if text is None:
                return None
            stack.append(text)
        elif opcode == 0x8D:  # BINUNICODE8
            text, offset = _counted(data, offset, 8)
            if text is None:
                return None
            stack.append(text)
        elif opcode == 0x63:  # GLOBAL
            module, offset = _line(data, offset)
            name, offset = _line(data, offset) if module is not None else (None, offset)
            if module is None or name is None:
                return None
            stack.append((module, name))
        elif opcode == 0x93:  # STACK_GLOBAL
            if len(stack) < 2:
                return None
            top_name = stack.pop()
            top_module = stack.pop()
            if not isinstance(top_module, str) or not isinstance(top_name, str):
                return None
            stack.append((top_module, top_name))
        elif opcode in {0x52, 0x81}:  # REDUCE, NEWOBJ
            if len(stack) < 2:
                return None
            stack.pop()
            callable_item = stack.pop()
            if isinstance(callable_item, tuple) and _dangerous(*callable_item):
                return start
            stack.append(None)
        elif opcode == 0x85 and stack:  # TUPLE1
            stack.pop()
            stack.append(None)
        elif opcode == 0x86 and len(stack) >= 2:  # TUPLE2
            del stack[-2:]
            stack.append(None)
        elif opcode == 0x87 and len(stack) >= 3:  # TUPLE3
            del stack[-3:]
            stack.append(None)
        elif opcode == 0x73 and len(stack) >= 2:  # SETITEM
            del stack[-2:]
        elif opcode == 0x30 and stack:  # POP
            stack.pop()
        elif opcode == 0x71:  # BINPUT
            offset += 1
        elif opcode == 0x72:  # LONG_BINPUT
            offset += 4
        elif opcode == 0x43:  # SHORT_BINBYTES
            # The payload is an argument, not a callable. Skip it and keep walking.
            nxt = _skip_counted(data, offset, 1)
            if nxt is None:
                return None
            offset = nxt
            stack.append(None)
        elif opcode == 0x42:  # BINBYTES
            nxt = _skip_counted(data, offset, 4)
            if nxt is None:
                return None
            offset = nxt
            stack.append(None)
        else:
            # An opcode this walker does not know stops the walk with no finding.
            return None
        if offset > len(data):
            return None
    return None


def _dangerous(module: str, name: str) -> bool:
    return module in _PICKLE_MODULES or name in _PICKLE_NAMES


def _skip_counted(data: bytes, offset: int, width: int) -> int | None:
    if offset + width > len(data):
        return None
    size = int.from_bytes(data[offset : offset + width], "little")
    start = offset + width
    if size > len(data) - start:
        return None
    return start + size


def _counted(data: bytes, offset: int, width: int) -> tuple[str | None, int]:
    if offset + width > len(data):
        return None, offset
    size = int.from_bytes(data[offset : offset + width], "little")
    start = offset + width
    if size > len(data) - start:
        return None, start
    try:
        text = data[start : start + size].decode("utf-8")
    except UnicodeError:
        return None, start + size
    return text, start + size


def _line(data: bytes, offset: int) -> tuple[str | None, int]:
    end = data.find(b"\n", offset, offset + 256)
    if end < 0:
        return None, offset
    try:
        return data[offset:end].decode("ascii"), end + 1
    except UnicodeError:
        return None, end + 1


def _safetensors_bad(data: bytes) -> bool:
    if len(data) < 8:
        return True
    header_len = int.from_bytes(data[:8], "little")
    if header_len < 2 or header_len > len(data) - 8:
        return True
    try:
        parsed = json.loads(data[8 : 8 + header_len])
    except json.JSONDecodeError:
        return True
    if not isinstance(parsed, dict):
        return True
    data_len = len(data) - 8 - header_len
    for key, value in parsed.items():
        if key == "__metadata__":
            continue
        if not isinstance(value, dict):
            return True
        offsets = value.get("data_offsets")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not isinstance(offsets[0], int)
            or not isinstance(offsets[1], int)
        ):
            return True
        start = offsets[0]
        end = offsets[1]
        if start < 0 or end < start or end > data_len:
            return True
    return False


def _gguf_bad(data: bytes) -> bool:
    if len(data) < 24 or data[:4] != b"GGUF":
        return True
    version = int.from_bytes(data[4:8], "little")
    tensors = int.from_bytes(data[8:16], "little")
    pairs = int.from_bytes(data[16:24], "little")
    if version not in {1, 2, 3} or tensors > 100_000 or pairs > 100_000:
        return True
    offset: int | None = 24
    for _ in range(pairs):
        offset = _gguf_pair(data, offset)
        if offset is None:
            return True
    for _ in range(tensors):
        offset = _gguf_tensor(data, offset)
        if offset is None:
            return True
    return False


def _gguf_pair(data: bytes, offset: int | None) -> int | None:
    offset = _gguf_string(data, offset)
    if offset is None or offset + 4 > len(data):
        return None
    value_type = int.from_bytes(data[offset : offset + 4], "little")
    return _gguf_value(data, offset + 4, value_type)


def _gguf_tensor(data: bytes, offset: int | None) -> int | None:
    offset = _gguf_string(data, offset)
    if offset is None or offset + 4 > len(data):
        return None
    dims = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4
    if dims > 8 or offset + dims * 8 + 12 > len(data):
        return None
    offset += dims * 8 + 4
    tensor_offset = int.from_bytes(data[offset : offset + 8], "little")
    if tensor_offset > len(data):
        return None
    return offset + 8


def _gguf_string(data: bytes, offset: int | None) -> int | None:
    if offset is None or offset + 8 > len(data):
        return None
    size = int.from_bytes(data[offset : offset + 8], "little")
    if size > len(data) - (offset + 8):
        return None
    return offset + 8 + size


def _gguf_value(data: bytes, offset: int, value_type: int) -> int | None:
    widths = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
    if value_type in widths:
        size = widths[value_type]
        if offset + size > len(data):
            return None
        return offset + size
    if value_type == 8:
        return _gguf_string(data, offset)
    if value_type != 9 or offset + 12 > len(data):
        return None
    element = int.from_bytes(data[offset : offset + 4], "little")
    count = int.from_bytes(data[offset + 4 : offset + 12], "little")
    if count > 100_000:
        return None
    cursor: int | None = offset + 12
    for _ in range(count):
        cursor = _gguf_value(data, cursor, element) if cursor is not None else None
        if cursor is None:
            return None
    return cursor


def _walk_mcp(node: object, hits: list[str], depth: int) -> None:
    if depth > 8 or len(hits) > 4:
        return
    if isinstance(node, dict):
        command = node.get("command")
        if isinstance(command, str) and _SHELL_COMMAND.search(command):
            hits.append("shell")
        args = node.get("args")
        if isinstance(args, list):
            for item in args:
                if isinstance(item, str) and _SHELL_ARG.search(item):
                    hits.append("shell")
                    break
        description = node.get("description")
        if isinstance(description, str) and _HIDDEN_INSTRUCTION.search(description):
            hits.append("hidden")
        for value in node.values():
            _walk_mcp(value, hits, depth + 1)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk_mcp(item, hits, depth + 1)


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
