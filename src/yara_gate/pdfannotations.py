"""Decode annotation Contents text strings, separately from page glyph strings."""

import re
from collections.abc import Iterator, Sequence
from typing import NamedTuple

from yara_gate.content import (
    MAX_EXTRACT_BYTES,
    MAX_PDF_STREAMS,
    MAX_TEXT_PIECES,
    Budget,
    ContentLimit,
    PdfObjects,
    PdfValue,
    _pdf_stream_dict,
    _pdf_value,
)
from yara_gate.heuristics import _PDF_LEX, _decode_pdf_name
from yara_gate.pdfpages import _LENGTH
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


def _string_bytes(token: bytes) -> bytes:
    if len(token) > _MAX_STRING:
        raise ContentLimit("pdf annotation string exceeds 1MiB")
    if token.startswith(b"("):
        if not token.endswith(b")"):
            raise ContentLimit("pdf annotation string malformed")
        raw, _ = _literal(token, 0)
        return raw
    if token.startswith(b"<") and not token.startswith(b"<<"):
        if not token.endswith(b">"):
            raise ContentLimit("pdf annotation string malformed")
        # NUL is PDF white space, which bytes.split() does not split on.
        digits = b"".join(token[1:-1].replace(b"\x00", b" ").split())
        if len(digits) % 2:
            digits += b"0"
        try:
            return bytes.fromhex(digits.decode("ascii"))
        except ValueError as exc:
            raise ContentLimit("pdf annotation string malformed") from exc
    raise ContentLimit("pdf annotation Contents is not a text string")


def _text(token: bytes) -> str:
    raw = _string_bytes(token)
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


def _shown_text(token: bytes) -> str:
    """A text string as pypdf decodes one: never unreadable, since nearly every file has an
    Info dictionary and a producer's odd byte must not make a benign file incomplete.

    A byte order mark, then a NUL in the first or second byte (UTF-16 without a mark), then
    PDFDocEncoding; an invalid sequence becomes U+FFFD, as a viewer draws it.
    """
    return shown_string(_string_bytes(token))


def shown_string(raw: bytes) -> str:
    """The bytes of a text string, its escapes or hex already decoded, read as
    ``_shown_text`` reads them."""
    if raw.startswith(b"\xef\xbb\xbf"):
        try:
            return _LANGUAGE.sub("", raw[3:].decode("utf-8"))
        except UnicodeError:
            pass
    elif raw.startswith((b"\xfe\xff", b"\xff\xfe")):
        return _LANGUAGE.sub("", raw.decode("utf-16", errors="replace"))
    elif raw[:1] == b"\x00":
        return _LANGUAGE.sub("", raw.decode("utf-16-be", errors="replace"))
    elif raw[1:2] == b"\x00":
        return _LANGUAGE.sub("", raw.decode("utf-16-le", errors="replace"))
    return "".join(_PDFDOC.get(c, chr(c)) for c in raw)


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
            span = stream_span(data, start, position, budget, objects)
            if span is None:
                # Missing, unaligned, or ambiguous. Resuming the lexer is not safe.
                raise ContentLimit("pdf annotation stream length unaligned")
            if spans is not None:
                spans.append(span)
            position = span[1]


def stream_span(
    data: bytes, start: int, position: int, budget: Budget, objects: PdfObjects | None
) -> tuple[int, int] | None:
    """The body of the stream whose keyword is ``data[start:position]``, through the
    ``endstream`` its ``/Length`` lands on; None when the length is missing or does not land.

    The landed keyword is the boundary only when it is the first ``endstream`` in the span.
    An earlier one can hide an object that a reader stopping there would see. An object
    header alone does not: with no earlier keyword, those bytes are inside the body. The span
    includes the newline and ``endstream`` the length landed on: an offset on those bytes is
    not an object a reader seeks.
    """
    dictionary = _pdf_stream_dict(data, start)
    length = dictionary.get(b"/Length") if dictionary else None
    if isinstance(length, tuple) and objects is not None:
        bodies = objects(*length)
        length = bodies[0].split(maxsplit=1)[0] if len(bodies) == 1 and bodies[0] else None
    if isinstance(length, bytes) and length.isdigit() and len(length) < 10:
        begin = position + (2 if data[position : position + 2] == b"\r\n" else 1)
        end_at = begin + int(length)
        ending = re.match(rb"[\r\n]*endstream\b", data[end_at : end_at + 32])
        if ending and not _earlier_endstream(data, begin, end_at, budget):
            return begin, end_at + ending.end()
    return None


def _annotation(value: dict[bytes, PdfValue]) -> bool:
    return value.get(b"/Type") == b"/Annot" or (
        isinstance(value.get(b"/Subtype"), bytes)
        and value.get(b"/Subtype") in _SUBTYPES
        and b"/Rect" in value
    )


# An array object kept for a shown value that refers to it; past this many tokens it is kept
# as None, and only a reference to it from a shown value makes the scan incomplete.
_MAX_ARRAY_TOKENS = 100_000
Arrays = dict[tuple[int, int], list[list[bytes] | None]]


class _ArrayCapture:
    """The tokens of one array object, from its opening ``[`` to the matching ``]``."""

    def __init__(self) -> None:
        self.tokens: list[bytes] | None = []
        self.depth = 0

    def feed(self, token: bytes) -> bool:
        """Take one token; True once the array has closed."""
        if token == b"[":
            self.depth += 1
            if self.depth == 1:
                return False
        elif token == b"]":
            self.depth -= 1
            if self.depth == 0:
                return True
        if self.tokens is not None:
            self.tokens.append(token)
            if len(self.tokens) > _MAX_ARRAY_TOKENS:
                self.tokens = None
        return False


def _dictionaries(
    data: bytes,
    objects: PdfObjects,
    budget: Budget,
    strings: dict[tuple[int, int], list[bytes]] | None = None,
    spans: list[tuple[int, int]] | None = None,
    arrays: Arrays | None = None,
) -> Iterator[dict[bytes, PdfValue]]:
    tokens: list[bytes] = []
    depth = 0
    previous: list[bytes] = []
    key: tuple[int, int] | None = None
    capture: tuple[tuple[int, int], _ArrayCapture] | None = None
    for token, _ in _tokens(data, budget, objects, spans):
        if capture is not None and arrays is not None and capture[1].feed(token):
            arrays.setdefault(capture[0], []).append(capture[1].tokens)
            capture = None
        if strings is not None and not depth:
            if key is not None:
                strings.setdefault(key, []).append(token)
                if token == b"[" and arrays is not None and capture is None:
                    capture = (key, _ArrayCapture())
                    capture[1].feed(token)
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
# A raw header inside a landed stream. Whitespace between the tokens is any PDF
# whitespace, including a run of them. The number must start the span or follow
# whitespace or a delimiter. ``obj`` must end on whitespace, a delimiter, or ``<<``.
_STREAM_HEADER = re.compile(
    rb"([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+obj"
    rb"(?=[\x00\t\n\f\r ()<>\[\]{}/%]|<<)"
)
_HEADER_BOUND = b"\x00\t\n\f\r ()<>[]{}/%"


def _reject_headers_inside(data: bytes, spans: list[tuple[int, int]]) -> None:
    """A keyword-delimited object header in raw stream bytes is incomplete.

    Decoded object-stream members are not these spans. They are read separately.
    """
    for begin, end in spans:
        for match in _STREAM_HEADER.finditer(data, begin, end):
            at = match.start()
            if at == begin or data[at - 1] in _HEADER_BOUND:
                raise ContentLimit("pdf object header inside stream")


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


_FIELD_MARKS = (b"/FT", b"/T", b"/Parent", b"/Kids")
# The document information strings pdfinfo, pypdf, and PyMuPDF show. /Title is also an
# outline item's label, and a reader lists every outline title.
_SHOWN_KEYS = (b"/Title", b"/Author", b"/Subject", b"/Keywords", b"/Creator", b"/Producer")


def _shown_values(entry: dict[bytes, PdfValue]) -> Iterator[PdfValue]:
    """Text strings a reader shows from this dictionary outside annotation /Contents: a form
    field's value, a document information string, and an outline title."""
    for key in _SHOWN_KEYS:
        if key in entry:
            yield entry[key]
    if b"/V" in entry and (
        entry.get(b"/Subtype") == b"/Widget" or any(mark in entry for mark in _FIELD_MARKS)
    ):
        value = entry[b"/V"]
        # A multiple-selection choice field holds an array of its chosen options.
        if isinstance(value, list):
            yield from value
        else:
            yield value


def _array_items(
    definitions: list[list[bytes] | None], strings: dict[tuple[int, int], list[bytes]]
) -> Iterator[bytes]:
    for tokens in definitions:
        if tokens is None:
            raise ContentLimit("pdf string array exceeds 100000 tokens")
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if (
                index + 2 < len(tokens)
                and token.isdigit()
                and tokens[index + 1].isdigit()
                and tokens[index + 2] == b"R"
                and len(token) <= 32
                and len(tokens[index + 1]) <= 32
            ):
                yield from strings.get((int(token), int(tokens[index + 1])), [])
                index += 3
                continue
            yield token
            index += 1


def _property_list(entry: dict[bytes, PdfValue]) -> bool:
    """True for a dictionary whose /ActualText a page's marked content can name: anything but
    a structure element, which has /S (ISO 32000-1, Table 323). poppler and PDFium show a
    property list's /ActualText in place of its glyphs when a ``BDC`` names it from the page's
    /Properties, and show no structure element's."""
    return b"/S" not in entry and entry.get(b"/Type") != b"/StructElem"


def pdf_annotation_texts(data: bytes, objects: PdfObjects, budget: Budget) -> list[str]:
    return pdf_string_texts(data, objects, budget).annotations


class PdfStrings(NamedTuple):
    # Annotation /Contents (``pdf-annotation``).
    annotations: list[str]
    # Form field values, document information strings, outline titles (``pdf-string``).
    shown: list[str]
    # /ActualText of a property list outside a content stream (``pdf-actual-text``).
    actual: list[str]


def pdf_string_texts(data: bytes, objects: PdfObjects, budget: Budget) -> PdfStrings:
    """Annotation /Contents text (``pdf-annotation``), the other text strings a reader shows
    (``pdf-string``): form field values, document information strings, outline titles; and
    the /ActualText of property lists written as objects, which a page's ``/Span /MC0 BDC``
    names from its /Properties (``pdf-actual-text``).

    All come from one pass over the file's dictionaries. An annotation string that does not
    decode is incomplete, as before. The other strings are decoded as pypdf decodes them, and
    a value that is not a text string (a check box's name, a signature dictionary, a missing
    object) is passed over: a reader shows no text for it. A property list is read whether or
    not a page names it, as a document information string is read whether or not a reader
    shows the dictionary; its value is one piece, never joined to the glyphs around it.
    """
    if not data.startswith(b"%PDF"):
        return PdfStrings([], [], [])
    values: list[PdfValue] = []
    shown: list[PdfValue] = []
    actual: list[PdfValue] = []
    strings: dict[tuple[int, int], list[bytes]] = {}

    def collect(entries: Iterator[dict[bytes, PdfValue]]) -> None:
        for entry in entries:
            if _annotation(entry) and b"/Contents" in entry:
                values.append(entry[b"/Contents"])
            shown.extend(_shown_values(entry))
            if b"/ActualText" in entry and _property_list(entry):
                actual.append(entry[b"/ActualText"])
            if len(values) + len(shown) + len(actual) > MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")

    spans: list[tuple[int, int]] = []
    # One pass over the file finds every stream length kept in an object of its own; a lookup
    # per stream would rescan the file once each (qpdf's QDF mode writes every length so).
    lengths: set[tuple[int, int]] = set()
    for count, match in enumerate(_LENGTH.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        lengths.add((int(match.group(1)), int(match.group(2))))
        if len(lengths) >= MAX_PDF_STREAMS:
            break
    objects.prime(lengths)
    arrays: Arrays = {}
    collect(_dictionaries(data, objects, budget, strings, spans, arrays))
    _reject_headers_inside(data, spans)
    _reject_xref_inside(data, spans, budget, objects.decoded)
    for number, source in objects.stream_members():
        body = bytes(source)
        first = next(_tokens(body, budget), (b"", 0))[0]
        strings.setdefault((number, 0), []).append(first)
        if len(strings) > MAX_TEXT_PIECES:
            raise ContentLimit("pdf annotation objects exceed 100000")
        if first == b"[":
            member = _ArrayCapture()
            for token, _ in _tokens(body, budget):
                if member.feed(token):
                    break
            arrays.setdefault((number, 0), []).append(member.tokens)
        collect(_dictionaries(body, objects, budget))
    size = 0

    def append(pieces: list[str], text: str) -> None:
        nonlocal size
        size += len(text.encode("utf-8"))
        if budget.expanded + size > MAX_EXTRACT_BYTES:
            raise ContentLimit("pdf annotation text exceeds extracted size budget")
        # Blank lines and explicit Unicode paragraph separators cannot form one phrase.
        pieces.extend(
            re.split(r"\n[ \t]*\n|\u2029", text.replace("\r\n", "\n").replace("\r", "\n"))
        )
        if len(pieces) > MAX_TEXT_PIECES:
            raise ContentLimit("text pieces exceed 100000")

    annotations: list[str] = []
    for value in values:
        budget.check()
        if isinstance(value, tuple):
            tokens = strings.get(value, [])
            if not tokens:
                raise ContentLimit("pdf annotation Contents reference unresolved")
            for token in tokens:
                if token != b"null":
                    append(annotations, _text(token))
        elif value != b"null":
            if not isinstance(value, bytes):
                raise ContentLimit("pdf annotation Contents is not a text string")
            append(annotations, _text(value))
    texts: list[str] = []
    for value in shown:
        budget.check()
        # Every definition of a referenced object, as for /Contents.
        found: Sequence[PdfValue] = strings.get(value, []) if isinstance(value, tuple) else [value]
        if isinstance(value, tuple):
            # A choice field's /V may refer to an array of its chosen options, and each
            # option may itself be a reference to a string (pypdf reads both).
            found = [*found, *_array_items(arrays.get(value, []), strings)]
        for item in found:
            if isinstance(item, bytes) and item[:1] in (b"(", b"<") and item[:2] != b"<<":
                append(texts, _shown_text(item))
    replacements: list[str] = []
    for value in dict.fromkeys(actual):
        budget.check()
        found = strings.get(value, []) if isinstance(value, tuple) else [value]
        for item in found:
            if isinstance(item, bytes) and item[:1] in (b"(", b"<") and item[:2] != b"<<":
                text = _shown_text(item)
                if text.strip():
                    size += len(text.encode("utf-8"))
                    if budget.expanded + size > MAX_EXTRACT_BYTES:
                        raise ContentLimit("pdf annotation text exceeds extracted size budget")
                    replacements.append(text)
    return PdfStrings(annotations, texts, list(dict.fromkeys(replacements)))
