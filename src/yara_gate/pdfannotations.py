"""Decode annotation Contents text strings, separately from page glyph strings."""

import re
from collections.abc import Iterator

from yara_gate.content import (
    MAX_EXTRACT_BYTES,
    MAX_TEXT_PIECES,
    Budget,
    ContentLimit,
    PdfObjects,
    PdfValue,
    _pdf_stream_dict,
    _pdf_value,
)
from yara_gate.heuristics import _PDF_LEX, _decode_pdf_name
from yara_gate.pdftext import _literal
from yara_gate.pdfxref import xref_file_offsets

_MAX_STRING = 1024 * 1024
_SUBTYPES = frozenset(
    b"/Text /FreeText /Line /Square /Circle /Polygon /PolyLine /Highlight /Underline "
    b"/Squiggly /StrikeOut /Stamp /Caret /Ink /FileAttachment /Sound /Redact /Link "
    b"/Widget /Screen /Popup /Watermark /3D /RichMedia /Projection".split()
)
_LANGUAGE = re.compile("\x1b[a-z]{2}(?:[A-Z]{2})?")
_ENDSTREAM = re.compile(rb"(?<![A-Za-z0-9])endstream(?![A-Za-z0-9])")
# Chunk the span search so a large body still hits the shared deadline.
_SPAN_CHUNK = 1 << 20
# PDFDocEncoding differs from Latin-1 in these slots (ISO 32000, Annex D).
_PDFDOC = dict(enumerate("\u02d8\u02c7\u02c6\u02d9\u02dd\u02db\u02da\u02dc", 24))
_PDFDOC.update(
    dict(
        enumerate(
            "\u2022\u2020\u2021\u2026\u2014\u2013\u0192\u2044\u2039\u203a\u2212\u2030"
            "\u201e\u201c\u201d\u2018\u2019\u201a\u2122\ufb01\ufb02\u0141\u0152\u0160"
            "\u0178\u017d\u0131\u0142\u0153\u0161\u017e",
            128,
        )
    )
)
_PDFDOC[160] = "\u20ac"


def _text(token: bytes) -> str:
    if len(token) > _MAX_STRING:
        raise ContentLimit("pdf annotation string exceeds 1MiB")
    if token.startswith(b"("):
        if not token.endswith(b")"):
            raise ContentLimit("pdf annotation string malformed")
        raw, _ = _literal(token, 0)
    elif token.startswith(b"<") and not token.startswith(b"<<"):
        if not token.endswith(b">"):
            raise ContentLimit("pdf annotation string malformed")
        digits = b"".join(token[1:-1].split())
        if len(digits) % 2:
            digits += b"0"
        raw = bytes.fromhex(digits.decode("ascii"))
    else:
        raise ContentLimit("pdf annotation Contents is not a text string")
    try:
        if raw.startswith(b"\xfe\xff"):
            return _LANGUAGE.sub("", raw[2:].decode("utf-16-be"))
        if raw.startswith(b"\xef\xbb\xbf"):
            return _LANGUAGE.sub("", raw[3:].decode("utf-8"))
        if raw.startswith(b"\xff\xfe") or any(c in (0, 22, 0x7F, 0x9F, 0xAD) for c in raw):
            raise UnicodeError("not PDFDocEncoding or supported Unicode")
        return "".join(_PDFDOC.get(c, chr(c)) for c in raw)
    except UnicodeError as exc:
        raise ContentLimit("pdf annotation text encoding unreadable") from exc


def _earlier_endstream(data: bytes, begin: int, end_at: int, budget: Budget) -> bool:
    """True when a keyword ``endstream`` occurs in the span before the landed one."""
    if end_at > len(data):
        end_at = len(data)
    pos = begin
    while pos < end_at:
        budget.check()
        stop = min(end_at, pos + _SPAN_CHUNK)
        match = _ENDSTREAM.search(data, pos, stop)
        if match is not None and match.end() <= end_at:
            return True
        if stop == end_at:
            return False
        pos = stop - 8
    return False


def _tokens(
    data: bytes,
    budget: Budget,
    objects: PdfObjects | None = None,
    spans: list[tuple[int, int]] | None = None,
) -> Iterator[tuple[bytes, int]]:
    """Keep string tokens intact so names written inside them never become dictionaries."""
    position = count = 0
    while position < len(data):
        budget.check()
        count += 1
        if count > 4_000_000:
            raise ContentLimit("pdf annotation tokens exceed 4000000")
        match = _PDF_LEX.match(data, position)
        if match is None:
            # Keep malformed delimiters for the dictionary parser to reject if relevant.
            yield data[position : position + 1], position + 1
            position += 1
            continue
        start, position = position, match.end()
        token = match.group()
        if token[:1] in b"\x00\t\n\f\r " or token.startswith(b"%"):
            continue
        if token == b"(":
            depth = 1
            steps = 0
            while position < len(data) and depth:
                if steps % 4096 == 0:
                    budget.check()
                steps += 1
                char = data[position]
                position += 1
                if char == 92:
                    position += 1
                elif char == 40:
                    depth += 1
                elif char == 41:
                    depth -= 1
            token = data[start:position] if depth == 0 else b"("
        elif token.startswith(b"/"):
            token = _decode_pdf_name(token)
        yield token, position
        if token == b"stream":
            # Stream bodies are scanned by the existing stream readers, never as annotations.
            dictionary = _pdf_stream_dict(data, start)
            length = dictionary.get(b"/Length") if dictionary else None
            if isinstance(length, tuple) and objects is not None:
                bodies = objects(*length)
                length = bodies[0].split(maxsplit=1)[0] if len(bodies) == 1 and bodies[0] else None
            if isinstance(length, bytes) and length.isdigit() and len(length) < 10:
                begin = position + (2 if data[position : position + 2] == b"\r\n" else 1)
                end_at = begin + int(length)
                ending = re.match(rb"[\r\n]*endstream\b", data[end_at : end_at + 32])
                # The landed keyword is the boundary only when it is the first
                # ``endstream`` in the span. An earlier one can hide an object that
                # a reader stopping there would see. An object header alone does not:
                # with no earlier keyword, those bytes are inside the body.
                if ending and not _earlier_endstream(data, begin, end_at, budget):
                    if spans is not None:
                        # Include the newline and endstream the length landed on.
                        # An offset on those bytes is not an object a reader seeks.
                        spans.append((begin, end_at + ending.end()))
                    position = end_at + ending.end()
                    continue
            # Missing, unaligned, or ambiguous. Resuming the lexer is not safe.
            raise ContentLimit("pdf annotation stream length unaligned")


def _annotation(value: dict[bytes, PdfValue]) -> bool:
    return value.get(b"/Type") == b"/Annot" or (
        isinstance(value.get(b"/Subtype"), bytes)
        and value.get(b"/Subtype") in _SUBTYPES
        and b"/Rect" in value
    )


def _dictionaries(
    data: bytes,
    objects: PdfObjects,
    budget: Budget,
    strings: dict[tuple[int, int], list[bytes]] | None = None,
    spans: list[tuple[int, int]] | None = None,
) -> Iterator[dict[bytes, PdfValue]]:
    tokens: list[bytes] = []
    depth = 0
    previous: list[bytes] = []
    key: tuple[int, int] | None = None
    for token, _ in _tokens(data, budget, objects, spans):
        if strings is not None and not depth:
            if key is not None:
                strings.setdefault(key, []).append(token)
                key = None
                if len(strings) > MAX_TEXT_PIECES:
                    raise ContentLimit("pdf annotation objects exceed 100000")
            if (
                token == b"obj"
                and len(previous) == 2
                and all(t.isdigit() and len(t) <= 32 for t in previous)
            ):
                key = (int(previous[0]), int(previous[1]))
            previous = [*previous[-1:], token]
        if token == b"<<":
            depth += 1
        if not depth:
            continue
        tokens.append(token)
        if len(tokens) > 100_000:
            raise ContentLimit("pdf annotation dictionary exceeds 100000 tokens")
        if token == b">>":
            depth -= 1
            if depth:
                continue
            try:
                value, used = _pdf_value(tokens, 0, reject_duplicates=True)
                if used != len(tokens) or not isinstance(value, dict):
                    raise ValueError("dictionary")
            except (ValueError, IndexError):
                if (
                    b"/Annot" in tokens
                    or b"/Annots" in tokens
                    or (b"/Rect" in tokens and any(t in _SUBTYPES for t in tokens))
                ):
                    raise ContentLimit("pdf annotation dictionary malformed") from None
            else:
                pending: list[PdfValue] = [value]
                while pending:
                    item = pending.pop()
                    if isinstance(item, dict):
                        yield item
                        pending.extend(item.values())
                    elif isinstance(item, list):
                        pending.extend(item)
            tokens = []
    if depth and (
        b"/Annot" in tokens
        or b"/Annots" in tokens
        or (b"/Rect" in tokens and any(t in _SUBTYPES for t in tokens))
    ):
        raise ContentLimit("pdf annotation dictionary malformed")


_OBJECT_AT = re.compile(rb"[0-9]{1,10}[\x00\t\n\f\r ]+[0-9]{1,5}[\x00\t\n\f\r ]+obj\b")


def _reject_xref_inside(
    data: bytes,
    spans: list[tuple[int, int]],
    budget: Budget,
    decoded: dict[int, bytes | None] | None = None,
) -> None:
    offsets = xref_file_offsets(data, budget, decoded)
    if not offsets:
        return
    for offset in offsets:
        for begin, end in spans:
            if begin <= offset < end:
                raise ContentLimit("pdf annotation xref offset inside stream")
        window = data[offset : offset + 64] if 0 <= offset < len(data) else b""
        if _OBJECT_AT.match(window) is None:
            raise ContentLimit("pdf xref malformed")


def pdf_annotation_texts(data: bytes, objects: PdfObjects, budget: Budget) -> list[str]:
    if not data.startswith(b"%PDF"):
        return []
    values: list[PdfValue] = []
    strings: dict[tuple[int, int], list[bytes]] = {}

    def collect(entries: Iterator[dict[bytes, PdfValue]]) -> None:
        for entry in entries:
            if _annotation(entry) and b"/Contents" in entry:
                if len(values) >= MAX_TEXT_PIECES:
                    raise ContentLimit("text pieces exceed 100000")
                values.append(entry[b"/Contents"])

    spans: list[tuple[int, int]] = []
    collect(_dictionaries(data, objects, budget, strings, spans))
    _reject_xref_inside(data, spans, budget, objects.decoded)
    for number, source in objects.stream_members():
        body = bytes(source)
        strings.setdefault((number, 0), []).append(next(_tokens(body, budget), (b"", 0))[0])
        if len(strings) > MAX_TEXT_PIECES:
            raise ContentLimit("pdf annotation objects exceed 100000")
        collect(_dictionaries(body, objects, budget))
    pieces: list[str] = []
    size = 0

    def append(token: bytes) -> None:
        nonlocal size
        if token == b"null":
            return
        text = _text(token)
        size += len(text.encode("utf-8"))
        if budget.expanded + size > MAX_EXTRACT_BYTES:
            raise ContentLimit("pdf annotation text exceeds extracted size budget")
        # Blank lines and explicit Unicode paragraph separators cannot form one phrase.
        pieces.extend(
            re.split(r"\n[ \t]*\n|\u2029", text.replace("\r\n", "\n").replace("\r", "\n"))
        )

    for value in values:
        budget.check()
        if isinstance(value, tuple):
            tokens = strings.get(value, [])
            if not tokens:
                raise ContentLimit("pdf annotation Contents reference unresolved")
            for token in tokens:
                append(token)
        elif value != b"null":
            if not isinstance(value, bytes):
                raise ContentLimit("pdf annotation Contents is not a text string")
            append(value)
        if len(pieces) > MAX_TEXT_PIECES:
            raise ContentLimit("text pieces exceed 100000")
    return pieces
