"""File offsets a PDF reader can seek, from classic tables and xref streams.

ISO 32000-1 7.5.4 describes the 20-byte table. 7.5.8 describes xref streams
(``/W``, ``/Index``, Flate, predictors) and hybrid ``/XRefStm``. A newer
``/Prev`` section overrides an older one. At one trailer, a classic entry and
a stream entry for the same object are both kept, because readers disagree
which one wins.
"""

import re
from dataclasses import dataclass
from enum import Enum

from yara_gate.content import (
    Budget,
    ContentLimit,
    PdfValue,
    _inflate,
    _pdf_predictor,
    _pdf_stream_dict,
    _pdf_tokens,
    _pdf_value,
    _png_rows,
    _tiff_rows,
)

_MAX_ENTRIES = 100_000
_MAX_HOPS = 32
_MAX_WIDTH = 8
_TRAILER_END = frozenset({b"startxref"})
# The keyword, any byte a reader skips as whitespace, then the offset (group 1) or the start
# of a number only some readers accept (group 2).
_STARTXREF = re.compile(rb"startxref[\x00\t\n\x0b\f\r ]*+(?:([0-9]++)|([+\-.]))?")
_ENTRY = re.compile(rb"(\d{10}) (\d{5}) ([nf])(?: \n|\r\n| \r)")


class XrefUse(Enum):
    RESOLVED = "resolved"
    FREE = "free"
    COMPRESSED = "compressed"


@dataclass(frozen=True)
class XrefEntry:
    """One object in one xref section. Only ``resolved`` carries a file offset."""

    use: XrefUse
    offset: int = 0
    generation: int = 0


def _startxref_candidates(data: bytes, budget: Budget) -> list[int]:
    """The section offset each ``startxref`` in the file gives, in file order.

    Every occurrence of the bytes counts, wherever it is written. Readers find the keyword by
    searching the end of the file for the bytes or for a line that holds them, without
    lexing what is around it: one inside a comment, a literal string, or a stream body is
    taken by PDFium and pdf.js, and pypdf and pdfminer.six take one inside a string.

    An occurrence is skipped when no reader gets a section from it: the offset is 0, or what
    follows the keyword is not a number. Offset 0 is the ``%PDF`` header, and a linearized
    file's first-page trailer ends with ``startxref 0`` by design; the live pointer is the
    last one in the file, which names the first-page section, whose ``/Prev`` names the main
    one. A sign or a dot after the keyword is malformed: three readers read ``+12`` as 12.
    """
    found: list[int] = []
    for count, match in enumerate(_STARTXREF.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        if match.group(2) is not None:
            raise ContentLimit("pdf xref malformed")
        digits = match.group(1)
        if digits is None or len(digits) > 20 or int(digits) == 0:
            continue
        found.append(int(digits))
        if len(found) > _MAX_HOPS:
            raise ContentLimit("pdf xref malformed")
    return found


def xref_file_offsets(
    data: bytes, budget: Budget, decoded: dict[int, bytes | None] | None = None
) -> list[int] | None:
    """Type-1 offsets from every ``startxref``, or None when the file has none to follow.

    Readers do not agree on which ``startxref`` is live, so each one is a
    candidate, whether or not ``%%EOF`` follows it (``_startxref_candidates``).
    A candidate includes its ``/Prev`` chain. Malformed structure, an
    unsupported filter or predictor, too many entries or candidates, and a
    spent deadline raise ``ContentLimit``. ``decoded`` is the stream cache
    ``pdf_streams`` already inflated.
    """
    candidates = _startxref_candidates(data, budget)
    if not candidates:
        return None
    union: list[int] = []
    seen: set[int] = set()
    # Each section is parsed once, however many candidates and /Prev chains reach it.
    parsed: _Parsed = {}
    for at in dict.fromkeys(candidates):
        budget.check()
        found: dict[int, list[int]] = {}
        _section(data, at, budget, set(), found, decoded, parsed)
        for offsets in found.values():
            for offset in offsets:
                if offset not in seen:
                    seen.add(offset)
                    union.append(offset)
    return union


# (is it read as an xref stream, offset) -> the section's entries and its trailer
_Parsed = dict[tuple[bool, int], tuple[dict[int, XrefEntry], dict[bytes, PdfValue]]]


def _section(
    data: bytes,
    at: int,
    budget: Budget,
    seen: set[int],
    found: dict[int, list[int]],
    decoded: dict[int, bytes | None] | None,
    parsed: _Parsed,
) -> None:
    budget.check()
    if at in seen or len(seen) >= _MAX_HOPS or not 0 <= at < len(data):
        raise ContentLimit("pdf xref malformed")
    seen.add(at)
    as_stream = not data.startswith(b"xref", at)
    if (as_stream, at) not in parsed:
        parsed[as_stream, at] = (
            _xref_stream(data, at, budget, decoded) if as_stream else _classic(data, at, budget)
        )
    classic, trailer = parsed[as_stream, at]
    stream: dict[int, XrefEntry] = {}
    previous = trailer.get(b"/Prev")
    if isinstance(previous, bytes) and previous.isdigit():
        _section(data, int(previous), budget, seen, found, decoded, parsed)
    sibling = trailer.get(b"/XRefStm")
    if isinstance(sibling, bytes) and sibling.isdigit():
        if (True, int(sibling)) not in parsed:
            parsed[True, int(sibling)] = _xref_stream(data, int(sibling), budget, decoded)
        stream = parsed[True, int(sibling)][0]
    defined = set(classic) | set(stream)
    for number in defined:
        offsets: list[int] = []
        for table in (classic, stream):
            entry = table.get(number)
            if entry is not None and entry.use is XrefUse.RESOLVED and entry.offset not in offsets:
                offsets.append(entry.offset)
        found[number] = offsets


def _classic(
    data: bytes, at: int, budget: Budget
) -> tuple[dict[int, XrefEntry], dict[bytes, PdfValue]]:
    pos = at + len(b"xref")
    if pos >= len(data) or data[pos : pos + 1] not in b"\r\n \t":
        raise ContentLimit("pdf xref malformed")
    pos = _whitespace(data, pos)
    entries: dict[int, XrefEntry] = {}
    total = 0
    while True:
        budget.check()
        # MuPDF leaves a blank line between the last entry and ``trailer``.
        pos = _whitespace(data, pos)
        if data.startswith(b"trailer", pos):
            break
        head = re.match(rb"(\d+) (\d+)", data[pos : pos + 40])
        if head is None:
            raise ContentLimit("pdf xref malformed")
        start, count = int(head.group(1)), int(head.group(2))
        pos = _whitespace(data, pos + head.end())
        if count > _MAX_ENTRIES or total + count > _MAX_ENTRIES:
            raise ContentLimit("pdf xref entries exceed 100000")
        for index in range(count):
            chunk = data[pos : pos + 20]
            parsed = _ENTRY.fullmatch(chunk)
            if parsed is None:
                raise ContentLimit("pdf xref malformed")
            offset, generation, use = int(parsed.group(1)), int(parsed.group(2)), parsed.group(3)
            if use == b"n":
                entries[start + index] = XrefEntry(XrefUse.RESOLVED, offset, generation)
            else:
                entries[start + index] = XrefEntry(XrefUse.FREE, 0, generation)
            pos += 20
        total += count
    trailer = _trailer(data, pos + len(b"trailer"))
    return entries, trailer


def _xref_stream(
    data: bytes,
    at: int,
    budget: Budget,
    decoded: dict[int, bytes | None] | None = None,
) -> tuple[dict[int, XrefEntry], dict[bytes, PdfValue]]:
    window = data[at : at + 8192]
    keyword = re.search(rb"stream\r?\n", window)
    if keyword is None:
        raise ContentLimit("pdf xref malformed")
    stream_at = at + keyword.start()
    dictionary = _pdf_stream_dict(data, stream_at)
    if not isinstance(dictionary, dict) or dictionary.get(b"/Type") != b"/XRef":
        raise ContentLimit("pdf xref malformed")
    length = dictionary.get(b"/Length")
    if not (isinstance(length, bytes) and length.isdigit() and len(length) < 10):
        raise ContentLimit("pdf xref unsupported")
    begin = at + keyword.end()
    end_at = begin + int(length)
    if end_at > len(data):
        raise ContentLimit("pdf xref malformed")
    raw = _decode_stream(data[begin:end_at], dictionary, budget, decoded, stream_at)
    return _stream_entries(raw, dictionary, budget), dictionary


def _decode_stream(
    raw: bytes,
    dictionary: dict[bytes, PdfValue],
    budget: Budget,
    cache: dict[int, bytes | None] | None,
    stream_at: int,
) -> bytes:
    cached = None if cache is None else cache.get(stream_at)
    # pdf_streams stores Flate output before a binary predictor is reversed.
    if isinstance(cached, bytes) and cached:
        decoded: bytes | None = cached
    else:
        filt = dictionary.get(b"/Filter")
        if filt is None:
            decoded = raw
        elif filt in (b"/FlateDecode", b"/Fl"):
            decoded = _inflate(raw, budget)
        else:
            raise ContentLimit("pdf xref unsupported")
    if not decoded:
        raise ContentLimit("pdf xref malformed")
    parms = dictionary.get(b"/DecodeParms")
    if not isinstance(parms, dict):
        return decoded
    spec = _pdf_predictor(parms)
    if spec is None:
        raise ContentLimit("pdf xref unsupported")
    kind, colors, bits, columns = spec
    if kind <= 1:
        return decoded
    pixel = max(1, (colors * bits + 7) // 8)
    row = max(1, (colors * bits * columns + 7) // 8)
    if kind == 2:
        return _tiff_rows(decoded, row, pixel, budget, None)
    rows = _png_rows(decoded, row, pixel, budget, None)
    if rows is None:
        raise ContentLimit("pdf xref malformed")
    return rows


def _stream_entries(
    raw: bytes, dictionary: dict[bytes, PdfValue], budget: Budget
) -> dict[int, XrefEntry]:
    widths = dictionary.get(b"/W")
    if not isinstance(widths, list) or len(widths) != 3:
        raise ContentLimit("pdf xref malformed")
    fields: list[int] = []
    for item in widths:
        if not (isinstance(item, bytes) and item.isdigit()):
            raise ContentLimit("pdf xref malformed")
        width = int(item)
        if width > _MAX_WIDTH:
            raise ContentLimit("pdf xref unsupported")
        fields.append(width)
    first, second, third = fields
    stride = first + second + third
    if stride == 0:
        raise ContentLimit("pdf xref malformed")
    size = dictionary.get(b"/Size")
    if not (isinstance(size, bytes) and size.isdigit()):
        raise ContentLimit("pdf xref malformed")
    pairs = _index(dictionary.get(b"/Index"), int(size))
    if len(raw) != sum(count for _, count in pairs) * stride:
        raise ContentLimit("pdf xref malformed")
    entries: dict[int, XrefEntry] = {}
    cursor = total = 0
    for start, count in pairs:
        if count > _MAX_ENTRIES or total + count > _MAX_ENTRIES:
            raise ContentLimit("pdf xref entries exceed 100000")
        for index in range(count):
            if cursor + stride > len(raw):
                raise ContentLimit("pdf xref malformed")
            budget.check()
            chunk = raw[cursor : cursor + stride]
            cursor += stride
            kind = _integer(chunk[:first]) if first else 1
            field2 = _integer(chunk[first : first + second]) if second else 0
            field3 = _integer(chunk[first + second :]) if third else 0
            number = start + index
            if kind == 0:
                entries[number] = XrefEntry(XrefUse.FREE, 0, field3)
            elif kind == 1:
                entries[number] = XrefEntry(XrefUse.RESOLVED, field2, field3)
            elif kind == 2:
                entries[number] = XrefEntry(XrefUse.COMPRESSED)
            else:
                raise ContentLimit("pdf xref malformed")
        total += count
    return entries


def _index(value: PdfValue | None, size: int) -> list[tuple[int, int]]:
    if value is None:
        return [(0, size)]
    if not isinstance(value, list) or len(value) % 2:
        raise ContentLimit("pdf xref malformed")
    numbers: list[int] = []
    for item in value:
        if not (isinstance(item, bytes) and item.isdigit()):
            raise ContentLimit("pdf xref malformed")
        numbers.append(int(item))
    return list(zip(numbers[0::2], numbers[1::2], strict=True))


def _integer(raw: bytes) -> int:
    return int.from_bytes(raw, "big") if raw else 0


def _trailer(data: bytes, pos: int) -> dict[bytes, PdfValue]:
    """The trailer dictionary at ``data[pos:]``.

    The lexer stops at the ``startxref`` that follows the dictionary. A linearized file's
    first-page trailer is followed by objects and their stream bytes, which do not lex.
    """
    pos = _whitespace(data, pos)
    tokens = _pdf_tokens(data, pos, min(len(data), pos + 65536), _TRAILER_END)
    if not tokens or tokens[0] != b"<<":
        raise ContentLimit("pdf xref malformed")
    try:
        value, _used = _pdf_value(tokens, 0)
    except (IndexError, ValueError) as exc:
        raise ContentLimit("pdf xref malformed") from exc
    if not isinstance(value, dict):
        raise ContentLimit("pdf xref malformed")
    return value


def _whitespace(data: bytes, pos: int) -> int:
    while pos < len(data) and data[pos : pos + 1] in b"\x00\t\n\f\r ":
        pos += 1
    return pos
