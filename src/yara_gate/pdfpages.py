"""Which fonts each page's content streams can select, from the page's own resources.

A font resource name such as ``/F1`` is looked up in the resources of the page that draws the
content stream (ISO 32000-1 7.8.3), and a merged file keeps every source's ``/F1``. Reading a
stream through only its own page's fonts gives each string one reading instead of one per font
the name means anywhere in the file.

The map narrows what is read, so it is built only from structure every reader agrees on, and
anything else keeps the file-wide union, which is what the reader did before this map existed
(docs/verification/2026-11-10-pdf-page-fonts.md). ``page_font_refs`` returns None, for the
whole file, when

- the objects are not laid out as ``N G obj ... endobj`` one after another, found by one
  string-aware pass over the file: an ``obj`` inside an open object, a stray ``endobj``, a
  comment inside an object (it could split a reference the byte count below must see), or a
  stream whose ``/Length`` does not land;
- a stream the text reader decoded is not one this pass stepped over, or the two number it
  differently, so a page's ``/Contents`` reference and the stream it reads could differ;
- a stream has the ``/N`` and ``/First`` of an object stream without ``/Type /ObjStm``: a
  reader can take objects from it that the object index does not hold;
- bytes that read as an object header lie anywhere that pass did not find one: inside a
  literal string or a stream, where a cross-reference entry or a reader rebuilding the table
  can still find an object;
- a cross-reference entry does not agree with the headers: it gives an object number an
  offset that is not the start of that object's header, or a place in an object stream whose
  own table lists another number there. The map links pages to streams and resources by the
  numbers in the headers, and a reader that follows the table would link them differently.
  A table that cannot be read counts the same. Every occurrence of the bytes ``startxref``
  is followed, as a reader searching from the end of the file can find any of them; a file
  with none is rebuilt from its headers by every reader;
- an object stream could not be read;
- more than ``MAX_PAGE_OBJECTS`` objects hold ``/Contents``, more than ``MAX_PAGE_BYTES`` are
  parsed, or the file has more than ``MAX_OBJECTS`` objects;
- an array a page's ``/Contents`` goes through cannot be followed, or is referenced from
  anywhere else.

A page is any object with a ``/Contents`` key at its top level that parses as one dictionary
with no key repeated (readers disagree on which copy of a repeated key wins). Its
``/Contents`` is followed through nested arrays and references to arrays. A stream is given
its pages' fonts only when every reference to its object number in the file, counted in the
bytes, is one of those ``/Contents`` references: a reference from anywhere else (an
annotation's appearance, a Type 3 font's glyph procedures, a page that did not parse) can run
the stream with other resources. A stream maps to None, and reads the union, when that count
does not match, when a page that draws it has no ``/Resources`` of its own (some readers
inherit through ``/Parent`` and some through the ``/Kids`` they walked), when its page's
``/Resources`` or ``/Font`` does not resolve to one value (an object number defined twice
with different values, under any generation), or when one of its names means more fonts than
the caller allows. A name the page's ``/Font`` dictionary does not list is left out, so it
too falls back to the union. A stream two pages draw gets both pages' fonts.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field

from yara_gate.content import (
    MAX_PDF_STREAMS,
    Budget,
    ContentLimit,
    PdfObjects,
    PdfStream,
    PdfValue,
    _pdf_stream_dict,
    _pdf_string_end,
    _pdf_tokens,
    _pdf_value,
)
from yara_gate.heuristics import _PDF_LEX, _decode_pdf_name
from yara_gate.pdfxref import xref_tables

Ref = tuple[int, int]
# name (without the slash) -> the font objects it can mean in one content stream
StreamFonts = dict[bytes, frozenset[Ref]]

_REGULAR = rb"[^\x00\t\n\f\r ()<>\[\]{}/%]"
# Where the layout pass stops. A keyword counts only as a whole token: after whitespace or a
# delimiter that is not the slash of a name, and before whitespace or any delimiter. A name is
# looked at when it is /Contents, or holds a ``#`` escape that could spell it.
_MARK = re.compile(
    rb"\(|%[^\r\n]*+"
    rb"|(?<![^\x00\t\n\f\r ()<>\[\]{}])(?:endobj|obj|stream)(?!" + _REGULAR + rb")"
    rb"|/Contents(?!" + _REGULAR + rb")"
    rb"|/[^\x00\t\n\f\r ()<>\[\]{}/%#]*+#"
)
# Every ``obj`` a lexer could end a header with, wherever it is written.
_OBJ = re.compile(rb"obj(?!" + _REGULAR + rb")")
_WHITESPACE = b"\x00\t\n\f\r "
# How far back from an ``obj`` the bytes before it are read.
_BEFORE_OBJ = 256
# The two integers before ``obj``: digits only, set off by plain whitespace, and no longer
# than the stream reader's own header test takes (``content._PDF_OBJ_HEADER``).
_NUMBERS = re.compile(
    rb"(?<![^\x00\t\n\f\r ()<>\[\]{}])([0-9]{1,10})[\x00\t\n\f\r ]+[0-9]{1,5}[\x00\t\n\f\r ]+\Z"
)
_HEADER_WINDOW = 64
# An indirect reference as any lexer reads one: two integers and ``R``, with no space needed
# before the ``R``. Comments between the tokens are not matched; the layout pass turns a file
# with a comment inside an object away.
_REFERENCE = re.compile(
    rb"(?<![0-9])([0-9]++)[\x00\t\n\f\r ]++[+-]?[0-9]++[\x00\t\n\f\r ]*+R(?!" + _REGULAR + rb")"
)
_STRING_OR_COMMENT = re.compile(rb"[(%]")
# A literal string longer than this is not stepped over. The annotation reader holds a file
# with one as incomplete.
MAX_STRING_BYTES = 1 << 20
_ENDS = frozenset({b"stream", b"endobj"})
# A page dictionary is a few hundred bytes; a body this long is read no further.
MAX_PAGE_OBJECT_BYTES = 1 << 20
# Objects with /Contents, and the bytes of every object parsed, before the map is given up and
# the union is used. A page dictionary is a few hundred bytes, so books and merged reports of
# several thousand pages stay below both; a file past either is read as before this map
# existed.
MAX_PAGE_OBJECTS = 20_000
MAX_PAGE_BYTES = 2 * 1024 * 1024
# Objects in the file. The annotation reader holds a file past this as incomplete.
MAX_OBJECTS = 100_000
# Arrays inside arrays, and arrays behind references, followed from one /Contents.
MAX_CONTENT_DEPTH = 32
# Definitions of one object number, raw and in object streams, before it counts as unresolved.
MAX_DEFINITIONS = 16
_CHECK_EVERY = 256


@dataclass
class _Object:
    """One ``N G obj`` the pass found: its number, where its value starts and ends."""

    number: int
    start: int
    stop: int = 0
    contents: bool = False


@dataclass
class _Layout:
    """What the pass found: every object, where each header starts, and each stream keyword's
    offset. The last two map an offset to the object's number."""

    objects: list[_Object]
    starts: dict[int, int]
    streams: dict[int, int]


def _layout(data: bytes, objects: PdfObjects, budget: Budget) -> _Layout | None:
    """Every object in file order, or None when the file is not a plain run of objects.

    One pass that stops only where the layout can change: a literal string (kept whole), a
    comment, a stream (stepped over by its ``/Length``, the way the annotation reader does),
    the keywords ``obj`` and ``endobj``, and the name this module reads. A header written
    inside a string or a stream is never taken for an object here. Such a header is then
    caught by the byte scan: an ``obj`` anywhere in the file that could end a header
    (``_after_a_number``) must be one this pass opened an object at.
    """
    # The annotation reader imports the text reader, which imports this module.
    from yara_gate.pdfannotations import stream_span

    found: list[_Object] = []
    starts: dict[int, int] = {}
    streams: dict[int, int] = {}
    opened: set[int] = set()
    current: _Object | None = None
    position = count = marked = 0
    size = len(data)
    while position < size:
        if count % 4096 == 0:
            budget.check()
        count += 1
        mark = _MARK.search(data, position)
        if mark is None:
            break
        start, position = mark.span()
        first = data[start]
        if first == 0x25:  # a comment, already consumed to the end of its line
            if current is not None:
                return None
            continue
        if first == 0x28:  # a literal string
            budget.check()
            position = _pdf_string_end(data, position, min(size, position + MAX_STRING_BYTES))
            if position < 0:
                return None
            continue
        if first == 0x2F:  # a name that is, or could spell, /Contents
            name = _PDF_LEX.match(data, start)
            if name is None:
                return None
            position = name.end()
            if _decode_pdf_name(name.group()) == b"/Contents" and current is not None:
                if not current.contents:
                    marked += 1
                    if marked > MAX_PAGE_OBJECTS:
                        return None
                current.contents = True
            continue
        keyword = mark.group()
        if keyword == b"obj":
            header = _NUMBERS.search(data, max(0, start - _HEADER_WINDOW), start)
            if current is not None or header is None or len(found) >= MAX_OBJECTS:
                return None
            current = _Object(int(header.group(1)), position)
            starts[header.start(1)] = current.number
            opened.add(position)
        elif keyword == b"endobj":
            if current is None:
                return None
            current.stop = start
            found.append(current)
            current = None
        else:  # stream
            if current is None or len(streams) >= MAX_PDF_STREAMS:
                return None
            dictionary = _pdf_stream_dict(data, start)
            if dictionary is None or (
                b"/N" in dictionary
                and b"/First" in dictionary
                and dictionary.get(b"/Type") != b"/ObjStm"
            ):
                return None
            span = stream_span(data, start, position, budget, objects)
            if span is None:
                return None
            streams[start] = current.number
            position = span[1]
    if current is not None:
        return None
    for count, match in enumerate(_OBJ.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        if match.end() not in opened and _after_a_number(data, match.start()):
            return None
    return _Layout(found, starts, streams)


def _after_a_number(data: bytes, at: int) -> bool:
    """True when the ``obj`` at ``data[at:]`` could end an object header for some lexer.

    A header is two integers and ``obj``, with whitespace or comments between them and no
    space needed before ``obj``. So the bytes before it end in a digit, or the nearest text
    before it is on a comment line. Deliberately loose: it is asked only about an ``obj`` the
    layout pass did not open an object at, and a yes keeps the file-wide union.
    """
    before = data[max(0, at - _BEFORE_OBJ) : at]
    text = before.rstrip(_WHITESPACE)
    if not text:
        # Nothing but whitespace this far back, or the start of the file.
        return at > 0
    if text[-1:].isdigit():
        return True
    if len(text) == len(before):
        return False
    line = text[max(text.rfind(b"\n"), text.rfind(b"\r")) + 1 :]
    return b"%" in line


def _xref_agrees(data: bytes, layout: _Layout, objects: PdfObjects, budget: Budget) -> bool:
    """True when every cross-reference entry names the object the headers name.

    A type-1 entry must point at the first digit of a header with its object number. A type-2
    entry must name an object stream this file's index read, and a position where that
    stream's own table lists the same number. Readers differ on what they do otherwise: one
    takes the member at the position whatever its number, another accepts a header with a
    different number.
    """
    try:
        tables = xref_tables(data, budget, objects.decoded, anywhere=True)
    except ContentLimit:
        return False
    if tables is None:
        # The bytes ``startxref`` are nowhere in the file: every reader rebuilds the table
        # from the headers.
        return True
    for count, (number, offset) in enumerate(tables.resolved):
        if count % 4096 == 0:
            budget.check()
        if layout.starts.get(offset) != number:
            return False
    members: dict[int, list[int]] = {}
    for offset, numbers in objects.member_tables():
        container = layout.streams.get(offset)
        if container is None or members.setdefault(container, numbers) != numbers:
            return False
    for count, (number, container, index) in enumerate(tables.compressed):
        if count % 4096 == 0:
            budget.check()
        listed = members.get(container)
        if listed is None or index >= len(listed) or listed[index] != number:
            return False
    return True


class _Index:
    """Every definition of every object number: raw bodies and object-stream members."""

    def __init__(self, data: bytes, raw: list[_Object], members: list[tuple[int, bytes]]) -> None:
        self._data = data
        self._bodies: dict[int, list[_Object | bytes]] = {}
        for item in raw:
            self._bodies.setdefault(item.number, []).append(item)
        for number, body in members:
            self._bodies.setdefault(number, []).append(body)
        self._every: dict[int, list[PdfValue] | None] = {}
        # Bytes of the objects parsed so far, and whether that passed MAX_PAGE_BYTES.
        self.spent = 0
        self.exhausted = False

    def charge(self, size: int) -> bool:
        """Count ``size`` more bytes to parse; False once the budget is spent."""
        self.spent += size
        self.exhausted = self.exhausted or self.spent > MAX_PAGE_BYTES
        return not self.exhausted

    def value(self, ref: Ref) -> PdfValue | None:
        """The object's one value, or None when it is missing, unreadable, or defined more
        than once with different values. The generation is not compared: a reader that
        ignores it and one that does not would pick different definitions."""
        values = self.every(ref[0])
        if not values or any(value != values[0] for value in values[1:]):
            return None
        return values[0]

    def every(self, number: int) -> list[PdfValue] | None:
        """Each definition's value; empty when there is none, None when one is unreadable,
        there are more than ``MAX_DEFINITIONS``, or the byte budget is spent."""
        if number not in self._every:
            self._every[number] = self._parsed(self._bodies.get(number, []))
        return self._every[number]

    def _parsed(self, bodies: list[_Object | bytes]) -> list[PdfValue] | None:
        if len(bodies) > MAX_DEFINITIONS:
            return None
        values: list[PdfValue] = []
        for body in bodies:
            if isinstance(body, bytes):
                value = parse(body, 0, len(body)) if self.charge(len(body)) else None
            else:
                charged = self.charge(body.stop - body.start)
                value = parse(self._data, body.start) if charged else None
            if value is None:
                return None
            values.append(value)
        return values


def parse(data: bytes, start: int, stop: int | None = None) -> PdfValue | None:
    """The one object value at ``data[start:]``, up to ``stream`` or ``endobj``; None if bad.

    A dictionary that repeats a key is bad: readers disagree on which copy they keep.
    """
    if stop is None:
        stop = min(len(data), start + MAX_PAGE_OBJECT_BYTES)
    tokens = _pdf_tokens(data, start, stop, until=_ENDS)
    if not tokens:
        return None
    try:
        value, used = _pdf_value(tokens, 0, reject_duplicates=True)
    except (IndexError, ValueError):
        return None
    return value if used == len(tokens) else None


@dataclass
class _Followed:
    """The /Contents references followed so far.

    ``counted`` holds how many reference tokens to each object number were followed.
    ``reached`` maps an object a /Contents led to onto the decoded streams it draws (None when
    it could not be followed), ``arrays`` holds the ones that are arrays, and ``walking`` the
    ones being followed now.
    """

    counted: Counter[int] = field(default_factory=Counter)
    reached: dict[int, set[int] | None] = field(default_factory=dict)
    arrays: set[int] = field(default_factory=set)
    walking: set[int] = field(default_factory=set)


def page_font_refs(
    data: bytes,
    objects: object,
    decoded: list[PdfStream],
    budget: Budget,
    max_fonts: int,
) -> dict[int, StreamFonts | None] | None:
    """Content stream number -> the fonts its pages name, or None to use the union throughout.

    ``objects`` is the file's ``PdfObjects``; with anything else the object streams cannot be
    read, so the answer is None. ``decoded`` holds the streams the text reader decoded; the
    ones with text are the content it reads. A stream whose pages give one name more than
    ``max_fonts`` fonts maps to None, so the union and its own cap apply.
    """
    if not isinstance(objects, PdfObjects) or not data.startswith(b"%PDF"):
        return None
    layout = _layout(data, objects, budget)
    if layout is None or objects.opaque or not _xref_agrees(data, layout, objects, budget):
        return None
    streams: set[int] = set()
    for stream in decoded:
        if stream.text is None or stream.number is None:
            continue
        if layout.streams.get(stream.offset) != stream.number:
            return None
        streams.add(stream.number)
    members = [
        (number, bytes(view[:MAX_PAGE_OBJECT_BYTES])) for number, view in objects.stream_members()
    ]
    if any(_commented(body) for _, body in members):
        return None
    index = _Index(data, layout.objects, members)
    followed = _Followed()
    # Merged in place: a stream many pages draw is updated per page, never copied.
    mapped: dict[int, dict[bytes, set[Ref]] | None] = {}
    for count, value in enumerate(_pages(data, layout.objects, members, index)):
        if count % _CHECK_EVERY == 0:
            budget.check()
        if count >= MAX_PAGE_OBJECTS or index.exhausted:
            return None
        if not isinstance(value, dict):
            continue
        targets = _content_streams(index, value.get(b"/Contents"), streams, followed)
        if targets is None:
            return None
        if not targets or all(number in mapped and mapped[number] is None for number in targets):
            continue
        named = _page_fonts(index, value)
        for number in targets:
            if named is None:
                mapped[number] = None
                continue
            merged = mapped.setdefault(number, {})
            if merged is None:
                continue
            for name, ref in named.items():
                refs = merged.setdefault(name, set())
                refs.add(ref)
                if len(refs) > max_fonts:
                    mapped[number] = None
                    break
    if index.exhausted:
        return None
    written = _references(data, members, set(followed.reached), budget)
    for number in followed.reached:
        if written[number] == followed.counted[number]:
            continue
        if number in followed.arrays:
            return None
        if number in mapped:
            mapped[number] = None
    return {
        number: None if names is None else {name: frozenset(refs) for name, refs in names.items()}
        for number, names in mapped.items()
    }


def _commented(body: bytes) -> bool:
    """True when an object-stream member holds a comment outside its literal strings."""
    position = 0
    while (mark := _STRING_OR_COMMENT.search(body, position)) is not None:
        if mark.group() == b"%":
            return True
        position = _pdf_string_end(body, mark.end(), len(body))
        if position < 0:
            return True
    return False


def _pages(
    data: bytes, raw: list[_Object], members: list[tuple[int, bytes]], index: _Index
) -> Iterator[PdfValue | None]:
    """The parsed value of each object that holds ``/Contents``, or None for one that does
    not parse.

    The pass marked the raw objects by their decoded names. A member is parsed when it holds
    the name as written or any ``#`` escape that could spell it. Their bytes count toward
    ``MAX_PAGE_BYTES``.
    """
    for item in raw:
        if item.contents:
            yield parse(data, item.start) if index.charge(item.stop - item.start) else None
    for _, body in members:
        if b"/Contents" in body or b"#" in body:
            yield parse(body, 0, len(body)) if index.charge(len(body)) else None


def _references(
    data: bytes, members: list[tuple[int, bytes]], wanted: set[int], budget: Budget
) -> Counter[int]:
    """How many times each object number in ``wanted`` is referenced, in the file's bytes and
    in every object-stream member.

    Every match counts, wherever it is: one inside a literal string or a stream body only
    makes the count too high, which keeps the union.
    """
    written: Counter[int] = Counter()
    count = 0
    for source in (data, *(body for _, body in members)):
        for match in _REFERENCE.finditer(source):
            if count % 4096 == 0:
                budget.check()
            count += 1
            digits = match.group(1).lstrip(b"0")
            if len(digits) <= 10:
                number = int(digits or b"0")
                if number in wanted:
                    written[number] += 1
    return written


def _content_streams(
    index: _Index, contents: PdfValue | None, streams: set[int], followed: _Followed
) -> set[int] | None:
    """The decoded content streams one page's ``contents`` draws; None when that cannot be
    followed.

    A string or a missing entry is not page content (an annotation's /Contents is its text).
    A reference names a stream or an array, and an array holds references or more arrays.
    Each reference written in this value is counted in ``followed``.
    """
    found: set[int] = set()
    pending: list[tuple[PdfValue | None, int]] = [(contents, 0)]
    while pending:
        item, depth = pending.pop()
        if isinstance(item, list):
            if depth >= MAX_CONTENT_DEPTH:
                return None
            pending.extend((each, depth + 1) for each in item)
        elif isinstance(item, tuple):
            followed.counted[item[0]] += 1
            reached = _reach(index, item[0], streams, followed, depth)
            if reached is None:
                return None
            found |= reached
    return found


def _reach(
    index: _Index, number: int, streams: set[int], followed: _Followed, depth: int
) -> set[int] | None:
    """The decoded streams object ``number`` draws when a /Contents names it.

    Itself when the text reader decoded a stream with that number, and whatever its array
    definitions name. Every definition is followed, so an object that is a stream in one
    definition and an array in another counts as both. The references an array holds are
    counted once, however many pages come through it. A reference to nothing draws nothing.
    An array that leads back to itself cannot be followed.
    """
    if number in followed.reached:
        return followed.reached[number]
    if depth >= MAX_CONTENT_DEPTH or number in followed.walking:
        return None
    followed.walking.add(number)
    found: set[int] | None = {number} if number in streams else set()
    values = index.every(number)
    if values is None:
        found = None
    for value in values or []:
        if not isinstance(value, list) or found is None:
            continue
        followed.arrays.add(number)
        pending: list[tuple[PdfValue, int]] = [(value, depth + 1)]
        while pending and found is not None:
            item, level = pending.pop()
            if isinstance(item, list):
                if level >= MAX_CONTENT_DEPTH:
                    found = None
                else:
                    pending.extend((each, level + 1) for each in item)
            elif isinstance(item, tuple):
                followed.counted[item[0]] += 1
                inner = _reach(index, item[0], streams, followed, level)
                found = None if inner is None else found | inner
    followed.walking.discard(number)
    followed.reached[number] = found
    return found


def _page_fonts(index: _Index, page: dict[bytes, PdfValue]) -> dict[bytes, Ref] | None:
    """Font name -> font reference in the page's own resources.

    None when the page has no ``/Resources`` of its own, or it or its ``/Font`` does not
    resolve to one dictionary. Resources with no ``/Font`` name nothing, so each of the page's
    names falls back to the union.
    """
    if b"/Resources" not in page:
        return None
    resources = _resolve(index, page[b"/Resources"])
    if not isinstance(resources, dict):
        return None
    entry = resources.get(b"/Font")
    if entry is None:
        return {}
    fonts = _resolve(index, entry)
    if not isinstance(fonts, dict):
        return None
    return {name[1:]: ref for name, ref in fonts.items() if isinstance(ref, tuple)}


def _resolve(index: _Index, value: PdfValue) -> PdfValue | None:
    return index.value(value) if isinstance(value, tuple) else value
