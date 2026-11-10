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
    """One object in one xref section. ``resolved`` carries a file offset. ``compressed``
    carries the object stream's number as ``offset`` and the member's position in it as
    ``generation``."""

    use: XrefUse
    offset: int = 0
    generation: int = 0


def _startxref_candidates(data: bytes, budget: Budget) -> list[int]:
    """Line-start ``startxref`` keywords outside comments and literal strings."""
    found: list[int] = []
    index = 0
    size = len(data)
    line_start = True
    comment = False
    depth = 0
    escaped = False
    hex_string = False
    while index < size:
        if index % 65536 == 0:
            budget.check()
        byte = data[index]
        if comment:
            if byte in b"\r\n":
                comment = False
                line_start = True
            index += 1
            continue
        if depth:
            if escaped:
                escaped = False
            elif byte == 0x5C:
                escaped = True
            elif byte == 0x28:
                depth += 1
            elif byte == 0x29:
                depth -= 1
            line_start = byte in b"\r\n"
            index += 1
            continue
        if hex_string:
            if byte == 0x3E:
                hex_string = False
            line_start = byte in b"\r\n"
            index += 1
            continue
        if byte == 0x25:
            comment = True
            line_start = False
            index += 1
            continue
        if byte == 0x28:
            depth = 1
            line_start = False
            index += 1
            continue
        if byte == 0x3C and index + 1 < size and data[index + 1] != 0x3C:
            hex_string = True
            line_start = False
            index += 1
            continue
        if line_start and data.startswith(b"startxref", index):
            after = index + len(b"startxref")
            if after >= size or data[after : after + 1] in b"\x00\t\n\f\r ":
                found.append(index)
                if len(found) > _MAX_HOPS:
                    raise ContentLimit("pdf xref malformed")
                index = after
                line_start = False
                continue
        if byte in b"\r\n":
            line_start = True
        elif byte not in b"\x00\t\f ":
            line_start = False
        index += 1
    return found


@dataclass(frozen=True)
class XrefTables:
    """Every section any ``startxref`` reaches.

    ``offsets`` are the type-1 offsets a reader can seek: within one ``/Prev`` chain a newer
    section overrides an older one. ``resolved`` and ``compressed`` hold every type-1 entry as
    (object number, offset) and every type-2 entry as (object number, object stream number,
    position in it), from every section, overridden or not.
    """

    offsets: list[int]
    resolved: frozenset[tuple[int, int]]
    compressed: frozenset[tuple[int, int, int]]


def xref_tables(
    data: bytes,
    budget: Budget,
    decoded: dict[int, bytes | None] | None = None,
    *,
    anywhere: bool = False,
    entries: bool = True,
) -> XrefTables | None:
    """The entries of every ``startxref``'s sections, or None when there is no ``startxref``.

    Readers do not agree on which ``startxref`` is live, so each one is a
    candidate, whether or not ``%%EOF`` follows it. A candidate includes its
    ``/Prev`` chain. Malformed structure, an unsupported filter or predictor,
    too many entries or candidates, and a spent deadline raise ``ContentLimit``.
    ``decoded`` is the stream cache ``pdf_streams`` already inflated.

    With ``anywhere``, every occurrence of the bytes ``startxref`` is a candidate, which is
    what a reader searching backward from the end of the file can find. The default takes
    only a keyword at a line start outside comments and literal strings, as the scanner
    reads the file from the top; bytes inside a stream body can leave that scanner inside a
    string, so it may see none where a reader sees one. Without ``entries`` only ``offsets``
    is filled.
    """
    if anywhere:
        candidates = [match.start() for match in re.finditer(rb"startxref", data)]
        if len(candidates) > _MAX_HOPS:
            raise ContentLimit("pdf xref malformed")
    else:
        candidates = _startxref_candidates(data, budget)
    if not candidates:
        return None
    union: list[int] = []
    seen: set[int] = set()
    resolved: set[tuple[int, int]] | None = set() if entries else None
    compressed: set[tuple[int, int, int]] | None = set() if entries else None
    for marker in candidates:
        budget.check()
        number = re.match(rb"[\x00\t\n\f\r ]*(\d+)", data[marker + len(b"startxref") :])
        if number is None:
            raise ContentLimit("pdf xref malformed")
        found: dict[int, list[int]] = {}
        _section(data, int(number.group(1)), budget, set(), found, decoded, resolved, compressed)
        for offsets in found.values():
            for offset in offsets:
                if offset not in seen:
                    seen.add(offset)
                    union.append(offset)
    return XrefTables(union, frozenset(resolved or ()), frozenset(compressed or ()))


def xref_file_offsets(
    data: bytes, budget: Budget, decoded: dict[int, bytes | None] | None = None
) -> list[int] | None:
    """Type-1 offsets from every ``startxref``, or None when there are none."""
    tables = xref_tables(data, budget, decoded, entries=False)
    return None if tables is None else tables.offsets


def _section(
    data: bytes,
    at: int,
    budget: Budget,
    seen: set[int],
    found: dict[int, list[int]],
    decoded: dict[int, bytes | None] | None = None,
    resolved: set[tuple[int, int]] | None = None,
    compressed: set[tuple[int, int, int]] | None = None,
) -> None:
    budget.check()
    if at in seen or len(seen) >= _MAX_HOPS or not 0 <= at < len(data):
        raise ContentLimit("pdf xref malformed")
    seen.add(at)
    if data.startswith(b"xref", at):
        classic, trailer = _classic(data, at, budget)
        stream: dict[int, XrefEntry] = {}
    else:
        classic, trailer = _xref_stream(data, at, budget, decoded)
        stream = {}
    previous = trailer.get(b"/Prev")
    if isinstance(previous, bytes) and previous.isdigit():
        _section(data, int(previous), budget, seen, found, decoded, resolved, compressed)
    sibling = trailer.get(b"/XRefStm")
    if isinstance(sibling, bytes) and sibling.isdigit():
        stream, _trailer = _xref_stream(data, int(sibling), budget, decoded)
    if resolved is not None and compressed is not None:
        for table in (classic, stream):
            for number, listed in table.items():
                if listed.use is XrefUse.RESOLVED:
                    resolved.add((number, listed.offset))
                elif listed.use is XrefUse.COMPRESSED:
                    compressed.add((number, listed.offset, listed.generation))
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
                entries[number] = XrefEntry(XrefUse.COMPRESSED, field2, field3)
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
