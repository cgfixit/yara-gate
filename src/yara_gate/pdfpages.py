"""Which fonts each page's content streams can select, from the page's own resources.

A font resource name such as ``/F1`` is looked up in the resources of the page that draws the
content stream (ISO 32000-1 7.8.3), and a merged file keeps every source's ``/F1``. Reading a
stream through only its own page's fonts gives each string one reading instead of one per font
the name means anywhere in the file.

The map narrows what is read, so it is built only for a file that every reader reads the same
way, and anything else keeps the file-wide union, which is what the reader did before this
map existed (docs/verification/2026-11-10-pdf-page-fonts.md). Readers recover from malformed
syntax in different ways, so the file has to be written plainly throughout, not only in the
objects the map reads. ``page_font_refs`` returns None, for the whole file, when

- the file is not a run of ``N G obj <one value> endobj`` objects with only comments,
  cross-reference sections, and trailers between them. One pass reads every token outside
  stream bodies and literal strings. Each object must hold exactly one well-formed value: a
  dictionary's keys are names, containers close in order, and nothing is left over. A reader
  that meets a string where a key belongs can read the string's bytes as tokens;
- a token is not written plainly: a byte that is not printable ASCII, a tab, or a line end
  (lexers differ on which other bytes separate tokens), a number such as ``5.0e0`` or
  ``5-``, a comment right after a number, a hex string holding anything but hex digits, or
  an ``R`` that does not end a reference written as two runs of digits and ``R`` (readers
  differ on ``5.0 0 R``, ``5- 0 R``, ``5 0 R#``, and a reference split by a comment);
- a stream's ``/Length`` does not land on its ``endstream``, or is kept in another object and
  not written as a plain reference;
- a stream the text reader decoded is not one this pass stepped over, or the two number it
  differently, so a page's ``/Contents`` reference and the stream it reads could differ;
- a stream has the ``/N`` and ``/First`` of an object stream without ``/Type /ObjStm``: a
  reader can take objects from it that the object index does not hold;
- bytes that read as an object header lie anywhere that pass did not find one: inside a
  literal string, a comment, or a stream, where a cross-reference entry or a reader
  rebuilding the table can still find an object;
- a cross-reference entry does not agree with the headers: it gives an object number an
  offset that is not the start of that object's header, another generation, or a place in an
  object stream whose own table lists another number there. A table that cannot be read
  counts the same. Every occurrence of the bytes ``startxref`` is followed, as a reader
  searching from the end of the file can find any of them;
- an object stream could not be read, or is not written plainly: its header is not exactly
  the pairs its ``/N`` counts, its first object is not at ``/First``, or a member's place
  does not hold exactly one well-formed value. A reader may take the objects in the order
  they are written instead of at the header's offsets;
- the file has more than ``MAX_OBJECTS`` objects or ``MAX_TOKENS`` tokens, more than
  ``MAX_PAGE_OBJECTS`` objects hold ``/Contents``, or more than ``MAX_PAGE_BYTES`` are parsed;
- an array a page's ``/Contents`` goes through cannot be followed, or is referenced from
  anywhere else.

A page is any object with a ``/Contents`` key at its top level whose dictionary repeats no
key (readers disagree on which copy wins) and escapes no name with ``#`` (one reader cuts a
name at an escaped NUL). Its ``/Contents`` is followed through nested arrays and references
to arrays. A stream is given its pages' fonts only when every reference to its object number
in the file is one of those ``/Contents`` references: a reference from anywhere else (an
annotation's appearance, a Type 3 font's glyph procedures, a page that did not parse, a page
written in the trailer) can run the stream with other resources.

A stream maps to None, and reads the union, when that count does not match, when a page that
draws it has no ``/Resources`` of its own (some readers inherit through ``/Parent`` and some
through the ``/Kids`` they walked), or when its page's ``/Resources`` or ``/Font`` is not a
dictionary every reader resolves the same way. A reference resolves when its object is
defined once (or every definition has the same value), under the generation the reference
gives, and the cross-reference table lists it in use under that generation with no section
listing it free: a reader that reads null there can take the entry from the page's parent
instead. With no table at all, readers rebuild one from the headers, and an object-stream
member does not resolve. A name is given a stream's fonts only when every page that draws
the stream lists it, as a reference to one font dictionary that resolves; any other name
falls back to the union. A stream two pages draw gets both pages' fonts.
"""

from __future__ import annotations

import re
from array import array
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
from yara_gate.pdfxref import xref_tables

Ref = tuple[int, int]
# name (without the slash) -> the font objects it can mean in one content stream
StreamFonts = dict[bytes, frozenset[Ref]]

# A printable regular character: one every lexer keeps inside a token.
_PRINTABLE = rb"!-$&'*-.0-;=?-Z\\^-z|~"
# Where a keyword or number ends: before whitespace, a delimiter, or the end of the bytes.
_ENDS = rb"(?![" + _PRINTABLE + rb"])"
# One token of a value, after plain whitespace. A reference is two runs of digits and ``R``
# (groups 2 and 3 are the object number and the generation). A number is a decimal with an
# optional sign. A comment holds plain bytes to the end of its line. Anything else, a byte
# that is not plain among them, does not match.
_TOKEN = re.compile(
    rb"[\t\n\r ]*+(?:"
    rb"(([0-9]++)[\t\n\r ]++([0-9]++)[\t\n\r ]*+R" + _ENDS + rb")"
    rb"|(<<|\[)"
    rb"|(>>|\])"
    rb"|(/[" + _PRINTABLE + rb"]*+)"
    rb"|(\()"
    rb"|(<[0-9A-Fa-f\t\n\r ]*+>)"
    rb"|((?:[+-]?(?:[0-9]++(?:\.[0-9]*+)?|\.[0-9]++)|true|false|null)" + _ENDS + rb")"
    rb"|(%[\t -~]*+)"
    rb")"
)
_REFERENCE, _OPEN, _CLOSE, _NAME, _STRING, _ATOM, _NOTE = 1, 4, 5, 6, 7, 9, 10
# What follows an object's value.
_AFTER_VALUE = re.compile(rb"[\t\n\r ]*+(endobj|stream)" + _ENDS)
# One token between objects: a comment, ``trailer``, ``obj``, a token of a cross-reference
# section, or the end of the file.
_OUTSIDE = re.compile(
    rb"[\t\n\r ]*+(?:(%[^\r\n]*+)|(trailer)"
    + _ENDS
    + rb"|(obj)"
    + _ENDS
    + rb"|(?:[0-9]++|xref|startxref|n|f)"
    + _ENDS
    + rb"|(\Z))"
)
_COMMENT, _TRAILER, _OBJECT, _END = 1, 2, 3, 4
_DICTIONARY = re.compile(rb"[\t\n\r ]*+<<")
# A stream length kept in another object. Each one is looked up before the pass, in one scan
# of the file: looked up one at a time, every stream would cost a scan of its own.
_LENGTH = re.compile(rb"/Length[\t\n\r ]++([0-9]{1,10})[\t\n\r ]++([0-9]{1,5})[\t\n\r ]*+R")
# An object stream's header: integers and plain whitespace.
_PLAIN_HEADER = re.compile(rb"[0-9\t\n\r ]*+")
# Every ``obj`` a lexer could end a header with, wherever it is written.
_OBJ = re.compile(rb"obj" + _ENDS)
# Two integers and the bytes ``obj``, whatever follows them: a reader that searches for
# headers may not look past the keyword.
_LOOSE_HEADER = re.compile(rb"[0-9][\x00\t\n\x0b\x0c\r ]++[0-9]++[\x00\t\n\x0b\x0c\r ]++obj")
# Every byte some lexer takes for whitespace.
_WHITESPACE = b"\x00\t\n\x0b\x0c\r "
# How far back from an ``obj`` the bytes before it are read.
_BEFORE_OBJ = 256
# The two integers before ``obj``: digits only, set off by plain whitespace, and no longer
# than the stream reader's own header test takes (``content._PDF_OBJ_HEADER``).
_NUMBERS = re.compile(rb"(?<![^\t\n\r ()<>\[\]{}])([0-9]{1,10})[\t\n\r ]+([0-9]{1,5})[\t\n\r ]+\Z")
_HEADER_WINDOW = 64
# The largest object number a file may use (ISO 32000-1 Annex C). A reader that keeps a
# larger one in fewer bits would read another number.
MAX_OBJECT_NUMBER = 8_388_607
# A literal string longer than this is not stepped over. The annotation reader holds a file
# with one as incomplete.
MAX_STRING_BYTES = 1 << 20
# Tokens outside stream bodies and strings, in the file and its object streams. A merge of
# 200 pages has about 40,000, and the stream reader holds a file past about a thousand
# streams as incomplete.
MAX_TOKENS = 1_000_000
# Containers inside containers in one value.
MAX_DEPTH = 64
# A page dictionary is a few hundred bytes; an object this long is not parsed.
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


@dataclass(slots=True)
class _Object:
    """One object: its number and generation, the buffer its value is in and where the value
    starts and ends there, and what the pass saw in it. ``member`` is true for an object
    stream's member, whose buffer is the decoded stream."""

    number: int
    generation: int
    start: int
    source: bytes
    stop: int = 0
    member: bool = False
    # It holds a /Contents name, at any depth.
    contents: bool = False
    # One of its names has a ``#`` escape.
    escaped: bool = False


@dataclass
class _Found:
    """What the pass adds up over the file and its object streams: the object number of
    every reference outside strings and streams, and how many tokens it has read."""

    budget: Budget
    references: array[int] = field(default_factory=lambda: array("L"))
    tokens: int = 0


@dataclass
class _Layout:
    """What the pass found: every object, the object each header offset starts, the object
    number of each ``stream`` keyword's offset, and the references and token count."""

    objects: list[_Object]
    starts: dict[int, _Object]
    streams: dict[int, int]
    found: _Found


def _value(source: bytes, position: int, stop: int, item: _Object, found: _Found) -> int:
    """The offset just past the one value at ``source[position:stop]``, or -1 when it is not
    written plainly.

    A dictionary's keys must be names and every container must close in order, so a literal
    string is only ever a value. A comment may follow anything but a number: after a number
    it could split a reference (``5 %c`` then ``0 R``), which some lexers join and the count
    of references would not see. Each reference is added to ``found``, and ``item`` is marked
    when a name is /Contents or holds a ``#`` escape.
    """
    # One entry per open container: 1 a dictionary before a key, 2 a dictionary before a
    # value, 3 an array.
    stack: list[int] = []
    match = _TOKEN.match
    number = False
    while True:
        token = match(source, position, stop)
        if token is None:
            return -1
        found.tokens += 1
        if not found.tokens & 4095:
            found.budget.check()
            if found.tokens > MAX_TOKENS:
                return -1
        position = token.end()
        kind = token.lastindex
        if kind == _NOTE:
            if number:
                return -1
            continue
        number = kind == _ATOM
        top = stack[-1] if stack else 0
        if kind == _NAME:
            name = token.group(_NAME)
            if name == b"/Contents":
                item.contents = True
            elif b"#" in name:
                item.escaped = True
            if top == 1:
                stack[-1] = 2
                continue
        elif kind == _OPEN:
            if top == 1 or len(stack) >= MAX_DEPTH:
                return -1
            stack.append(1 if token.group(_OPEN) == b"<<" else 3)
            continue
        elif kind == _CLOSE:
            if top != (1 if token.group(_CLOSE) == b">>" else 3):
                return -1
            stack.pop()
        elif top == 1:
            return -1
        elif kind == _REFERENCE:
            target = _number(token.group(2))
            if target is None:
                return -1
            found.references.append(target)
        elif kind == _STRING:
            position = _pdf_string_end(source, position, min(stop, position + MAX_STRING_BYTES))
            if position < 0:
                return -1
        if not stack:
            return position
        if stack[-1] == 2:
            stack[-1] = 1


def _number(digits: bytes) -> int | None:
    """The object number written as ``digits``, or None when it is past the largest one."""
    digits = digits.lstrip(b"0")
    if len(digits) > 7 or int(digits or b"0") > MAX_OBJECT_NUMBER:
        return None
    return int(digits or b"0")


def _layout(data: bytes, objects: PdfObjects, budget: Budget) -> _Layout | None:
    """Every object in file order, or None when the file is not written plainly.

    One pass reads every token outside stream bodies and literal strings. Between objects it
    takes comments, cross-reference sections, and trailers. An object is its header, one
    well-formed value (``_value``), and ``endobj``, with a stream stepped over by its
    ``/Length`` the way the annotation reader does. A header written inside a string, a
    comment, or a stream is never taken for an object here. Such a header is then caught by
    the byte scans: an ``obj`` anywhere in the file that could end a header must be one this
    pass opened an object at.
    """
    # The annotation reader imports the text reader, which imports this module.
    from yara_gate.pdfannotations import stream_span

    lengths: set[Ref] = set()
    for count, match in enumerate(_LENGTH.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        lengths.add((int(match.group(1)), int(match.group(2))))
        if len(lengths) > MAX_PDF_STREAMS:
            return None
    objects.prime(lengths)
    found = _Found(budget)
    items: list[_Object] = []
    starts: dict[int, _Object] = {}
    streams: dict[int, int] = {}
    opened: set[int] = set()
    trailer = _Object(0, 0, 0, data)
    position = 0
    size = len(data)
    while True:
        token = _OUTSIDE.match(data, position)
        if token is None:
            return None
        found.tokens += 1
        if not found.tokens & 4095:
            budget.check()
            if found.tokens > MAX_TOKENS:
                return None
        position = token.end()
        kind = token.lastindex
        if kind is None or kind == _COMMENT:
            continue
        if kind == _END:
            break
        if kind == _TRAILER:
            position = _value(data, position, size, trailer, found)
            if position < 0:
                return None
            continue
        start = token.start(_OBJECT)
        header = _NUMBERS.search(data, max(0, start - _HEADER_WINDOW), start)
        if header is None or len(items) >= MAX_OBJECTS:
            return None
        number = _number(header.group(1))
        if number is None:
            return None
        item = _Object(number, int(header.group(2)), position, data)
        starts[header.start(1)] = item
        opened.add(position)
        item.stop = _value(data, position, size, item, found)
        if item.stop < 0:
            return None
        after = _AFTER_VALUE.match(data, item.stop)
        if after is None:
            return None
        position = after.end()
        if after.group(1) == b"stream":
            keyword = after.start(1)
            dictionary = _pdf_stream_dict(data, keyword)
            if dictionary is None or len(streams) >= MAX_PDF_STREAMS:
                return None
            if (
                b"/N" in dictionary
                and b"/First" in dictionary
                and dictionary.get(b"/Type") != b"/ObjStm"
            ):
                return None
            length = dictionary.get(b"/Length")
            if isinstance(length, tuple) and length not in lengths:
                return None
            span = stream_span(data, keyword, position, budget, objects)
            if span is None:
                return None
            streams[keyword] = number
            after = _AFTER_VALUE.match(data, span[1])
            if after is None or after.group(1) != b"endobj":
                return None
            position = after.end()
        items.append(item)
    for count, match in enumerate(_OBJ.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        if match.end() not in opened and _after_a_number(data, match.start()):
            return None
    for count, match in enumerate(_LOOSE_HEADER.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        if match.end() not in opened:
            return None
    return _Layout(items, starts, streams, found)


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


def _listed(
    data: bytes, layout: _Layout, objects: PdfObjects, budget: Budget
) -> tuple[bool, dict[int, int] | None]:
    """Whether every cross-reference entry names the object the headers name, and the
    generation under which the table lists each object a reader can use.

    A type-1 entry must point at the first digit of a header with its object number and
    generation. A type-2 entry must name an object stream this file's index read, and a
    position where that stream's own table lists the same number. Readers differ on what they
    do otherwise: one takes the member at the position whatever its number, another accepts a
    header with a different number.

    An object is usable when the table lists it in use under one generation and no section
    lists it free. A reader that follows the table reads any other object as null, and one
    that rebuilds the table from the headers reads it. The second value is None when the
    bytes ``startxref`` are nowhere in the file: every reader then rebuilds the table.
    """
    members: dict[int, list[int]] = {}
    for table in objects.object_streams():
        container = layout.streams.get(table.offset)
        if container is None or members.setdefault(container, table.numbers) != table.numbers:
            return False, None
    try:
        tables = xref_tables(data, budget, objects.decoded, anywhere=True)
    except ContentLimit:
        return False, None
    if tables is None:
        return True, None
    generations: dict[int, set[int]] = {}
    for count, (number, offset, generation) in enumerate(tables.resolved):
        if count % 4096 == 0:
            budget.check()
        item = layout.starts.get(offset)
        if item is None or item.number != number or item.generation != generation:
            return False, None
        generations.setdefault(number, set()).add(generation)
    for count, (number, container, index) in enumerate(tables.compressed):
        if count % 4096 == 0:
            budget.check()
        listed = members.get(container)
        if listed is None or index >= len(listed) or listed[index] != number:
            return False, None
        generations.setdefault(number, set()).add(0)
    usable = {
        number: next(iter(found))
        for number, found in generations.items()
        if len(found) == 1 and number not in tables.free
    }
    return True, usable


class _Index:
    """Every definition of every object number: raw objects and object-stream members."""

    def __init__(self, raw: list[_Object], usable: dict[int, int] | None) -> None:
        self._usable = usable
        self._bodies: dict[int, list[_Object]] = {}
        for item in raw:
            self._bodies.setdefault(item.number, []).append(item)
        self._every: dict[int, list[PdfValue] | None] = {}
        # Bytes of the objects parsed so far, and whether that passed MAX_PAGE_BYTES.
        self.spent = 0
        self.exhausted = False

    def add(self, item: _Object) -> None:
        """One more definition: an object-stream member."""
        self._bodies.setdefault(item.number, []).append(item)

    def parse(self, item: _Object) -> PdfValue | None:
        """The object's value; None when it is not read: a name in it has a ``#`` escape, it
        repeats a key, it is too long, or the byte budget is spent."""
        size = item.stop - item.start
        if item.escaped or size > MAX_PAGE_OBJECT_BYTES:
            return None
        self.spent += size
        self.exhausted = self.exhausted or self.spent > MAX_PAGE_BYTES
        if self.exhausted:
            return None
        tokens = _pdf_tokens(item.source, item.start, item.stop)
        if not tokens:
            return None
        try:
            value, used = _pdf_value(tokens, 0, reject_duplicates=True)
        except (IndexError, ValueError):
            return None
        return value if used == len(tokens) else None

    def value(self, ref: Ref) -> PdfValue | None:
        """The value every reader resolves ``ref`` to, or None when readers can differ.

        They can when the object is missing or unreadable, is defined more than once with
        different values, is defined under a generation other than the reference's (one
        reader ignores the generation and another reads null), or is not one the
        cross-reference table lists in use under that generation. A reader that reads null
        may then take the entry from somewhere else, such as the page's parent.
        """
        if not self._agreed(ref):
            return None
        values = self.every(ref[0])
        if not values or any(value != values[0] for value in values[1:]):
            return None
        return values[0]

    def dictionary(self, ref: Ref) -> bool:
        """True when ``ref`` names one definition, a dictionary, that every reader resolves
        it to. An object that is itself a reference is followed by some readers only."""
        bodies = self._bodies.get(ref[0], [])
        if len(bodies) != 1 or not self._agreed(ref):
            return False
        body = bodies[0]
        return _DICTIONARY.match(body.source, body.start, body.stop) is not None

    def _agreed(self, ref: Ref) -> bool:
        number, generation = ref
        bodies = self._bodies.get(number, [])
        if self._usable is None:
            # No table: a reader rebuilds one from the headers, and may not look inside
            # object streams when it does.
            return all(not body.member and body.generation == generation for body in bodies)
        if self._usable.get(number) != generation:
            return False
        return all(body.generation == generation for body in bodies)

    def every(self, number: int) -> list[PdfValue] | None:
        """Each definition's value; empty when there is none, None when one is not read or
        there are more than ``MAX_DEFINITIONS``."""
        if number not in self._every:
            self._every[number] = self._parsed(self._bodies.get(number, []))
        return self._every[number]

    def _parsed(self, bodies: list[_Object]) -> list[PdfValue] | None:
        if len(bodies) > MAX_DEFINITIONS:
            return None
        values: list[PdfValue] = []
        for body in bodies:
            value = self.parse(body)
            if value is None:
                return None
            values.append(value)
        return values


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
    if layout is None or objects.opaque:
        return None
    agrees, usable = _listed(data, layout, objects, budget)
    if not agrees:
        return None
    streams: set[int] = set()
    for stream in decoded:
        if stream.text is None or stream.number is None:
            continue
        if layout.streams.get(stream.offset) != stream.number:
            return None
        streams.add(stream.number)
    index = _Index(layout.objects, usable)
    members = _members(objects, index, layout.found)
    if members is None:
        return None
    followed = _Followed()
    # Merged in place: a stream many pages draw is updated per page, never copied.
    mapped: dict[int, dict[bytes, set[Ref]] | None] = {}
    for count, value in enumerate(_pages([*layout.objects, *members], index)):
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
            elif number not in mapped:
                mapped[number] = {name: {ref} for name, ref in named.items()}
            elif (merged := mapped[number]) is not None:
                # A name is settled for the stream only when every page that draws it lists
                # the name: a page that does not reads it from somewhere else.
                for name in [name for name in merged if name not in named]:
                    del merged[name]
                for name, refs in merged.items():
                    refs.add(named[name])
                    if len(refs) > max_fonts:
                        mapped[number] = None
                        break
    if index.exhausted:
        return None
    budget.check()
    wanted = followed.reached.keys()
    written = Counter(number for number in layout.found.references if number in wanted)
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


def _members(objects: PdfObjects, index: _Index, found: _Found) -> list[_Object] | None:
    """Every object-stream member, added to ``index``; None when an object stream is not
    written plainly.

    A reader may find a member three ways: by the offset its stream's header gives, by its
    place in that header, or by counting the objects in the order they are written. They
    agree when the header is exactly the pairs ``/N`` counts, the first object is at
    ``/First``, and each member's place, up to the next member's offset, holds exactly one
    value. A member is read the way the layout pass reads an object, and its references are
    added to ``found``.
    """
    members: list[_Object] = []
    for table in objects.object_streams():
        data = bytes(table.data)
        header = data[: table.first]
        if _PLAIN_HEADER.fullmatch(header) is None or len(header.split()) != 2 * len(table.numbers):
            return None
        if not table.offsets or table.offsets[0] != 0:
            return None
        bounds = [*table.offsets[1:], len(data) - table.first]
        for number, begin, stop in zip(table.numbers, table.offsets, bounds, strict=True):
            if number > MAX_OBJECT_NUMBER or stop <= begin:
                return None
            item = _Object(number, 0, table.first + begin, data, member=True)
            item.stop = _value(data, item.start, table.first + stop, item, found)
            if item.stop < 0 or data[item.stop : table.first + stop].strip(b"\t\n\r "):
                return None
            index.add(item)
            members.append(item)
    return members


def _pages(items: list[_Object], index: _Index) -> Iterator[PdfValue | None]:
    """The value of each object that holds a ``/Contents`` name, or None for one that is not
    read. Their bytes count toward ``MAX_PAGE_BYTES``."""
    for item in items:
        if item.contents:
            yield index.parse(item)


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
    names falls back to the union. So does a name whose font is not a reference to one
    dictionary every reader resolves.
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
    return {
        name[1:]: ref
        for name, ref in fonts.items()
        if isinstance(ref, tuple) and index.dictionary(ref)
    }


def _resolve(index: _Index, value: PdfValue) -> PdfValue | None:
    return index.value(value) if isinstance(value, tuple) else value
