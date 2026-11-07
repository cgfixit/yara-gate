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


def xref_file_offsets(data: bytes, budget: Budget) -> list[int] | None:
    """Type-1 offsets, or None when ``data`` has no ``startxref``.

    Malformed structure, an unsupported filter or predictor, too many entries,
    and a spent deadline raise ``ContentLimit`` instead of returning a map.
    """
    marker = data.rfind(b"startxref")
    if marker < 0:
        return None
    number = re.match(rb"[\x00\t\n\f\r ]*(\d+)", data[marker + len(b"startxref") :])
    if number is None:
        raise ContentLimit("pdf xref malformed")
    found: dict[int, list[int]] = {}
    _section(data, int(number.group(1)), budget, set(), found)
    return [offset for offsets in found.values() for offset in offsets]


def _section(
    data: bytes,
    at: int,
    budget: Budget,
    seen: set[int],
    found: dict[int, list[int]],
) -> None:
    budget.check()
    if at in seen or len(seen) >= _MAX_HOPS or not 0 <= at < len(data):
        raise ContentLimit("pdf xref malformed")
    seen.add(at)
    if data.startswith(b"xref", at):
        classic, trailer = _classic(data, at, budget)
        stream: dict[int, XrefEntry] = {}
    else:
        classic, trailer = _xref_stream(data, at, budget)
        stream = {}
    previous = trailer.get(b"/Prev")
    if isinstance(previous, bytes) and previous.isdigit():
        _section(data, int(previous), budget, seen, found)
    sibling = trailer.get(b"/XRefStm")
    if isinstance(sibling, bytes) and sibling.isdigit():
        stream, _trailer = _xref_stream(data, int(sibling), budget)
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
    while not data.startswith(b"trailer", pos):
        budget.check()
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
    data: bytes, at: int, budget: Budget
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
    raw = _decode_stream(data[begin:end_at], dictionary, budget)
    return _stream_entries(raw, dictionary, budget), dictionary


def _decode_stream(raw: bytes, dictionary: dict[bytes, PdfValue], budget: Budget) -> bytes:
    filt = dictionary.get(b"/Filter")
    if filt is None:
        decoded: bytes | None = raw
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
    pos = _whitespace(data, pos)
    tokens = _pdf_tokens(data, pos, min(len(data), pos + 65536))
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
