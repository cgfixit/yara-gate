"""Which fonts each page's content streams can select, from the page tree's resources.

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
  stream whose ``/Length`` does not land, or a ``/Contents`` or ``/CharProcs`` key outside
  every object (a trailer);
- bytes that read as an object header lie anywhere that pass did not find one: inside a
  literal string, a comment, or a stream, where a cross-reference entry or a reader
  rebuilding the table can still find an object;
- an object stream could not be read, or an object that holds ``/Contents`` or
  ``/CharProcs`` does not parse, repeats a dictionary key (readers disagree on which copy
  wins), or holds ``/Contents`` below its top level;
- more than ``MAX_PAGE_OBJECTS`` objects, or ``MAX_PAGE_BYTES`` of them, hold ``/Contents``
  or ``/CharProcs``, or the file has more than ``MAX_OBJECTS`` objects.

A stream maps to None, and reads the union, when its page's ``/Parent``, ``/Resources`` or
``/Font`` does not resolve to one value (an object number defined twice with different
values, under any generation), when one of its names means more fonts than the caller
allows, or when it is also a Type 3 glyph procedure, which runs with its font's resources.
A name the page's ``/Font`` dictionary does not list is left out, so it too falls back to the
union. A stream two pages draw gets both pages' fonts.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass

from yara_gate.content import (
    Budget,
    PdfObjects,
    PdfValue,
    _pdf_string_end,
    _pdf_tokens,
    _pdf_value,
)
from yara_gate.heuristics import _PDF_LEX, _decode_pdf_name

Ref = tuple[int, int]
# name (without the slash) -> the font objects it can mean in one content stream
StreamFonts = dict[bytes, frozenset[Ref]]

_REGULAR = rb"[^\x00\t\n\f\r ()<>\[\]{}/%]"
# Where the layout pass stops. A keyword counts only as a whole token: after whitespace or a
# delimiter that is not the slash of a name, and before whitespace or any delimiter. A name is
# looked at when it is one of the two this module reads, or holds a ``#`` escape that could
# spell one.
_MARK = re.compile(
    rb"\(|%[^\r\n]*+"
    rb"|(?<![^\x00\t\n\f\r ()<>\[\]{}])(?:endobj|obj|stream)(?!" + _REGULAR + rb")"
    rb"|/(?:Contents|CharProcs)(?!" + _REGULAR + rb")"
    rb"|/[^\x00\t\n\f\r ()<>\[\]{}/%#]*+#"
)
# Every ``obj`` a lexer could end a header with, wherever it is written.
_OBJ = re.compile(rb"obj(?!" + _REGULAR + rb")")
_WHITESPACE = b"\x00\t\n\f\r "
# How far back from an ``obj`` the bytes before it are read.
_BEFORE_OBJ = 256
# The two integers before ``obj``: digits only, set off by plain whitespace.
_NUMBERS = re.compile(
    rb"(?<![^\x00\t\n\f\r ()<>\[\]{}])([0-9]+)[\x00\t\n\f\r ]+[0-9]+[\x00\t\n\f\r ]+\Z"
)
_HEADER_WINDOW = 64
# A literal string longer than this is not stepped over. The annotation reader holds a file
# with one as incomplete.
MAX_STRING_BYTES = 1 << 20
_ENDS = frozenset({b"stream", b"endobj"})
# A page dictionary is a few hundred bytes; a body this long is read no further.
MAX_PAGE_OBJECT_BYTES = 1 << 20
# Objects with /Contents or /CharProcs, and their bytes, read before the map is given up and
# the union is used. A page dictionary is a few hundred bytes, so books and merged reports of
# several thousand pages stay below both; a file past either is read as before this map
# existed.
MAX_PAGE_OBJECTS = 20_000
MAX_PAGE_BYTES = 2 * 1024 * 1024
# Objects in the file. The annotation reader holds a file past this as incomplete.
MAX_OBJECTS = 100_000
# /Parent links followed from a page to find inherited /Resources.
MAX_PARENT_DEPTH = 32
# Definitions of one object number, raw and in object streams, before it counts as unresolved.
MAX_DEFINITIONS = 16
_CHECK_EVERY = 256


@dataclass
class _Object:
    """One ``N G obj`` the pass found: its number, where its value starts, and its keys."""

    number: int
    start: int
    stop: int = 0
    contents: bool = False
    glyphs: bool = False


def _objects(data: bytes, objects: PdfObjects, budget: Budget) -> list[_Object] | None:
    """Every object in file order, or None when the file is not a plain run of objects.

    One pass that stops only where the layout can change: a literal string (kept whole), a
    comment, a stream (stepped over by its ``/Length``, the way the annotation reader does),
    the keywords ``obj`` and ``endobj``, and the two names this module reads. A header written
    inside a string or a stream is never taken for an object here. Such a header is then
    caught by the byte scan: an ``obj`` anywhere in the file that could end a header
    (``_after_a_number``) must be one this pass opened an object at.
    """
    # The annotation reader imports the text reader, which imports this module.
    from yara_gate.pdfannotations import stream_span

    found: list[_Object] = []
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
            continue
        if first == 0x28:  # a literal string
            budget.check()
            position = _pdf_string_end(data, position, min(size, position + MAX_STRING_BYTES))
            if position < 0:
                return None
            continue
        if first == 0x2F:  # a name that is, or could spell, /Contents or /CharProcs
            name = _PDF_LEX.match(data, start)
            if name is None:
                return None
            position = name.end()
            key = _decode_pdf_name(name.group())
            if key in (b"/Contents", b"/CharProcs"):
                if current is None:
                    return None
                if not (current.contents or current.glyphs):
                    marked += 1
                    if marked > MAX_PAGE_OBJECTS:
                        return None
                if key == b"/Contents":
                    current.contents = True
                else:
                    current.glyphs = True
            continue
        keyword = mark.group()
        if keyword == b"obj":
            header = _NUMBERS.search(data, max(0, start - _HEADER_WINDOW), start)
            if current is not None or header is None or len(found) >= MAX_OBJECTS:
                return None
            current = _Object(int(header.group(1)), position)
            opened.add(position)
        elif keyword == b"endobj":
            if current is None:
                return None
            current.stop = start
            found.append(current)
            current = None
        else:  # stream
            if current is None:
                return None
            span = stream_span(data, start, position, budget, objects)
            if span is None:
                return None
            position = span[1]
    if current is not None:
        return None
    for count, match in enumerate(_OBJ.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        if match.end() not in opened and _after_a_number(data, match.start()):
            return None
    return found


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


class _Index:
    """Every definition of every object number: raw bodies and object-stream members."""

    def __init__(self, data: bytes, raw: list[_Object], members: list[tuple[int, bytes]]) -> None:
        self._data = data
        self._bodies: dict[int, list[int | bytes]] = {}
        for item in raw:
            self._bodies.setdefault(item.number, []).append(item.start)
        for number, body in members:
            self._bodies.setdefault(number, []).append(body)
        self._values: dict[int, PdfValue | None] = {}
        # A page-tree node's resolved fonts, so pages that share a parent walk it once.
        self.inherited: dict[int, dict[bytes, Ref] | None] = {}

    def value(self, ref: Ref) -> PdfValue | None:
        """The object's one value, or None when it is missing, unreadable, or defined more
        than once with different values. The generation is not compared: a reader that
        ignores it and one that does not would pick different definitions."""
        number = ref[0]
        if number not in self._values:
            self._values[number] = self._one(number)
        return self._values[number]

    def _one(self, number: int) -> PdfValue | None:
        bodies = self._bodies.get(number, [])
        if not bodies or len(bodies) > MAX_DEFINITIONS:
            return None
        first: PdfValue | None = None
        for body in bodies:
            value = parse(self._data, body) if isinstance(body, int) else parse(body, 0, len(body))
            if value is None or (first is not None and value != first):
                return None
            first = value
        return first


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


def page_font_refs(
    data: bytes,
    objects: object,
    streams: set[int],
    budget: Budget,
    max_fonts: int,
) -> dict[int, StreamFonts | None] | None:
    """Content stream number -> the fonts its pages name, or None to use the union throughout.

    ``objects`` is the file's ``PdfObjects``; with anything else the object streams cannot be
    read, so the answer is None. ``streams`` holds the numbers of the content streams the
    reader decoded. A stream whose pages give one name more than ``max_fonts`` fonts maps to
    None, so the union and its own cap apply.
    """
    if not isinstance(objects, PdfObjects) or not data.startswith(b"%PDF"):
        return None
    raw = _objects(data, objects, budget)
    if raw is None or objects.opaque:
        return None
    members = [(number, bytes(view[:MAX_PAGE_OBJECT_BYTES])) for number, view in _members(objects)]
    if sum(item.stop - item.start for item in raw if item.contents or item.glyphs) > MAX_PAGE_BYTES:
        return None
    index = _Index(data, raw, members)
    pages: list[PdfValue] = []
    fonts: list[PdfValue] = []
    for count, value in enumerate(_marked(data, raw, members)):
        if count % _CHECK_EVERY == 0:
            budget.check()
        if value is None or count >= MAX_PAGE_OBJECTS:
            return None
        if _holds(value, b"/Contents"):
            pages.append(value)
        if _holds(value, b"/CharProcs"):
            fonts.append(value)
    glyphs = _glyph_streams(index, fonts)
    if glyphs is None:
        return None
    # Merged in place: a stream many pages draw is updated per page, never copied.
    mapped: dict[int, dict[bytes, set[Ref]] | None] = dict.fromkeys(glyphs & streams)
    for count, value in enumerate(pages):
        if count % _CHECK_EVERY == 0:
            budget.check()
        if not isinstance(value, dict):
            if _draws(value):
                return None
            continue
        if any(_draws(item) for item in value.values()):
            return None
        targets = _content_streams(index, value.get(b"/Contents"), streams)
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
    return {
        number: None if names is None else {name: frozenset(refs) for name, refs in names.items()}
        for number, names in mapped.items()
    }


def _members(objects: PdfObjects) -> Iterator[tuple[int, memoryview]]:
    return objects.stream_members()


def _marked(
    data: bytes, raw: list[_Object], members: list[tuple[int, bytes]]
) -> Iterator[PdfValue | None]:
    """The parsed value of each object that holds ``/Contents`` or ``/CharProcs``.

    The pass marked the raw objects by their decoded names. A member is parsed when it holds
    either name as written or any ``#`` escape that could spell one.
    """
    for item in raw:
        if item.contents or item.glyphs:
            yield parse(data, item.start)
    for _, body in members:
        if b"/Contents" in body or b"/CharProcs" in body or b"#" in body:
            yield parse(body, 0, len(body))


def _holds(value: PdfValue, key: bytes) -> bool:
    """True when ``key`` is a dictionary key in ``value`` at any depth."""
    if isinstance(value, dict):
        return key in value or any(_holds(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_holds(item, key) for item in value)
    return False


def _draws(value: PdfValue) -> bool:
    """True when ``value`` holds, at any depth, a /Contents that is not a string.

    An annotation written inside its page has a text /Contents. A reference or an array there
    is page content one level too deep: a page dictionary written inside another object.
    """
    if isinstance(value, dict):
        nested = value.get(b"/Contents")
        if isinstance(nested, (tuple, list, dict)):
            return True
        return any(_draws(item) for item in value.values())
    if isinstance(value, list):
        return any(_draws(item) for item in value)
    return False


def _glyph_streams(index: _Index, fonts: list[PdfValue]) -> set[int] | None:
    """Object numbers named as Type 3 glyph procedures; None when a ``/CharProcs`` is unread.

    A glyph procedure is a content stream that runs with its font's resources, not a page's,
    so a stream named here is never narrowed to a page.
    """
    found: set[int] = set()
    pending = list(fonts)
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            for key, item in value.items():
                if key != b"/CharProcs":
                    pending.append(item)
                    continue
                procedures = index.value(item) if isinstance(item, tuple) else item
                if not isinstance(procedures, dict):
                    return None
                found.update(ref[0] for ref in procedures.values() if isinstance(ref, tuple))
    return found


def _content_streams(index: _Index, contents: PdfValue | None, streams: set[int]) -> list[int]:
    """The decoded content streams ``contents`` names.

    A string or a missing entry is not page content (an annotation's /Contents is its text).
    A reference names a stream, or an array of stream references.
    """
    if isinstance(contents, tuple):
        if contents[0] in streams:
            return [contents[0]]
        # Not a decoded stream: an array of them, or nothing this reader shows.
        contents = index.value(contents)
    if not isinstance(contents, list):
        return []
    return [ref[0] for ref in contents if isinstance(ref, tuple) and ref[0] in streams]


def _page_fonts(index: _Index, page: dict[bytes, PdfValue]) -> dict[bytes, Ref] | None:
    """Font name -> font reference in the page's resources, inherited through /Parent.

    None when a link on the way does not resolve to one dictionary. A page with no resources,
    or resources with no /Font, names nothing, so each of its names falls back to the union.
    """
    if b"/Resources" in page:
        return _resource_fonts(index, page[b"/Resources"])
    parent = page.get(b"/Parent")
    if parent is None:
        return {}
    return _inherited(index, parent, 0)


def _inherited(index: _Index, parent: PdfValue, depth: int) -> dict[bytes, Ref] | None:
    if not isinstance(parent, tuple) or depth >= MAX_PARENT_DEPTH:
        return None
    number = parent[0]
    if number in index.inherited:
        return index.inherited[number]
    # Marked before the walk, so a /Parent loop ends here instead of recursing.
    index.inherited[number] = None
    node = index.value(parent)
    found: dict[bytes, Ref] | None
    if not isinstance(node, dict):
        found = None
    elif b"/Resources" in node:
        found = _resource_fonts(index, node[b"/Resources"])
    elif b"/Parent" in node:
        found = _inherited(index, node[b"/Parent"], depth + 1)
    else:
        found = {}
    index.inherited[number] = found
    return found


def _resource_fonts(index: _Index, value: PdfValue) -> dict[bytes, Ref] | None:
    resources = _resolve(index, value)
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
