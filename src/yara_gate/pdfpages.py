"""Which fonts each page's content streams can select, from the page tree's resources.

A font resource name such as ``/F1`` is looked up in the resources of the page that draws the
content stream (ISO 32000-1 7.8.3), and a merged file keeps every source's ``/F1``. Reading a
stream through only its own page's fonts gives each string one reading instead of one per font
the name means anywhere in the file.

This is a conservative map. ``page_font_refs`` returns None, and the caller keeps reading every
stream through the file-wide union, when the page tree cannot be read whole: an object that
holds ``/Contents`` does not parse, an object stream could not be read, or a ``/Contents``
reference sits somewhere a page tree does not put one. A stream whose page resources do not
resolve to one definition maps to None; a name the page's ``/Font`` dictionary does not list is
left out, so it too falls back to the union. A stream two pages draw gets both pages' fonts.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Callable, Iterable, Iterator

from yara_gate.content import Budget, PdfValue, _pdf_tokens, _pdf_value

Ref = tuple[int, int]
# name (without the slash) -> the font objects it can mean in one content stream
StreamFonts = dict[bytes, frozenset[Ref]]

_HEADER = re.compile(rb"(?<![0-9])([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+obj\b")
_CONTENTS = re.compile(rb"/Contents(?![^\x00\t\n\f\r ()<>\[\]{}/%])")
_ENDS = frozenset({b"stream", b"endobj"})
# A page dictionary is a few hundred bytes; a body this long is read no further.
MAX_PAGE_OBJECT_BYTES = 1 << 20
# Objects with /Contents read before the map is given up and the union is used. Books and
# merged reports stay well below this; a file past it is read as before this map existed.
MAX_PAGE_OBJECTS = 20_000
# /Parent links followed from a page to find inherited /Resources.
MAX_PARENT_DEPTH = 32
# Definitions of one object, raw and in object streams, before it counts as unresolved.
MAX_DEFINITIONS = 16
_CHECK_EVERY = 256


class _Index:
    """Every definition of every object: raw ``N G obj`` bodies and object-stream members."""

    def __init__(self, data: bytes, members: Iterable[tuple[int, memoryview]], budget: Budget):
        self._data = data
        self._budget = budget
        self.raw: list[tuple[Ref, int, int]] = []
        starts = [(match, match.end()) for match in _HEADER.finditer(data)]
        for position, (match, start) in enumerate(starts):
            if position % 4096 == 0:
                budget.check()
            stop = starts[position + 1][0].start() if position + 1 < len(starts) else len(data)
            stop = min(stop, start + MAX_PAGE_OBJECT_BYTES)
            self.raw.append(((int(match.group(1)), int(match.group(2))), start, stop))
        self._bodies: dict[Ref, list[bytes | tuple[int, int]]] = {}
        for key, start, stop in self.raw:
            self._bodies.setdefault(key, []).append((start, stop))
        self.members: list[tuple[Ref, bytes]] = []
        for number, view in members:
            body = bytes(view[:MAX_PAGE_OBJECT_BYTES])
            self.members.append(((number, 0), body))
            self._bodies.setdefault((number, 0), []).append(body)
        self._values: dict[Ref, list[PdfValue] | None] = {}
        # A page-tree node's resolved fonts, so pages that share a parent walk it once.
        self.inherited: dict[Ref, dict[bytes, Ref] | None] = {}

    def value(self, key: Ref) -> PdfValue | None:
        """The object's one value, or None when it is missing, unreadable, or defined twice
        with different values (an incremental update a reader may resolve either way)."""
        if key not in self._values:
            self._values[key] = self._parse_all(key)
        values = self._values[key]
        if not values or any(value != values[0] for value in values[1:]):
            return None
        return values[0]

    def _parse_all(self, key: Ref) -> list[PdfValue] | None:
        bodies = self._bodies.get(key, [])
        if not bodies or len(bodies) > MAX_DEFINITIONS:
            return None
        values: list[PdfValue] = []
        for body in bodies:
            value = (
                parse(self._data, body[0], body[1])
                if isinstance(body, tuple)
                else parse(body, 0, len(body))
            )
            if value is None:
                return None
            values.append(value)
        return values


def parse(data: bytes, start: int, stop: int) -> PdfValue | None:
    """The object value at ``data[start:stop]``, up to ``stream`` or ``endobj``; None if bad."""
    tokens = _pdf_tokens(data, start, stop, until=_ENDS)
    if not tokens:
        return None
    try:
        value, used = _pdf_value(tokens, 0)
    except (IndexError, ValueError):
        return None
    return value if used == len(tokens) else None


def page_font_refs(
    data: bytes,
    members: Callable[[], Iterator[tuple[int, memoryview]]] | None,
    opaque: bool,
    streams: set[int],
    budget: Budget,
    max_fonts: int,
) -> dict[int, StreamFonts | None] | None:
    """Content stream number -> the fonts its pages name, or None to use the union throughout.

    ``members`` yields the object-stream members (``PdfObjects.stream_members``) and ``opaque``
    says an object stream could not be read; without the first, or with the second, a page may
    be defined where this cannot see it, so the answer is None. ``streams`` holds the numbers of
    the content streams the reader decoded. A stream whose pages give one name more than
    ``max_fonts`` fonts maps to None, so the union and its own cap apply.
    """
    if members is None or opaque or not data.startswith(b"%PDF"):
        return None
    index = _Index(data, members(), budget)
    positions = [match.start() for match in _CONTENTS.finditer(data)]
    candidates: list[PdfValue] = []
    for count, (_key, start, stop) in enumerate(index.raw):
        if count % 4096 == 0:
            budget.check()
        at = bisect.bisect_left(positions, start)
        if at == len(positions) or positions[at] >= stop:
            continue
        value = parse(data, start, stop)
        if value is None or len(candidates) >= MAX_PAGE_OBJECTS:
            return None
        candidates.append(value)
    for count, (_key, body) in enumerate(index.members):
        if count % 4096 == 0:
            budget.check()
        if b"/Contents" in body:
            value = parse(body, 0, len(body))
            if value is None or len(candidates) >= MAX_PAGE_OBJECTS:
                return None
            candidates.append(value)
    # Merged in place: a stream many pages draw is updated per page, never copied.
    mapped: dict[int, dict[bytes, set[Ref]] | None] = {}
    for count, value in enumerate(candidates):
        if count % _CHECK_EVERY == 0:
            budget.check()
        if not isinstance(value, dict):
            if _nested_contents(value):
                return None
            continue
        contents = value.get(b"/Contents")
        if any(_nested_contents(item) for name, item in value.items() if name != b"/Contents"):
            return None
        targets = _content_streams(index, contents, streams)
        if targets is None:
            return None
        if not targets or all(number in mapped and mapped[number] is None for number in targets):
            continue
        fonts = _page_fonts(index, value)
        for number in targets:
            if fonts is None:
                mapped[number] = None
                continue
            merged = mapped.setdefault(number, {})
            if merged is None:
                continue
            for name, ref in fonts.items():
                refs = merged.setdefault(name, set())
                refs.add(ref)
                if len(refs) > max_fonts:
                    mapped[number] = None
                    break
    return {
        number: None if names is None else {name: frozenset(refs) for name, refs in names.items()}
        for number, names in mapped.items()
    }


def _nested_contents(value: PdfValue) -> bool:
    """True when a /Contents reference sits inside ``value`` at any depth."""
    if isinstance(value, dict):
        for name, item in value.items():
            if name == b"/Contents" and (
                isinstance(item, tuple)
                or (isinstance(item, list) and any(isinstance(each, tuple) for each in item))
            ):
                return True
            if _nested_contents(item):
                return True
    elif isinstance(value, list):
        return any(_nested_contents(item) for item in value)
    return False


def _content_streams(
    index: _Index, contents: PdfValue | None, streams: set[int]
) -> list[int] | None:
    """The content streams ``contents`` names; None when it names something unreadable.

    A string or a missing entry is not page content (an annotation's /Contents is its text).
    A reference names a stream, or an array of stream references.
    """
    if contents is None or isinstance(contents, bytes):
        return []
    refs: list[PdfValue]
    if isinstance(contents, tuple):
        if contents[0] in streams:
            return [contents[0]]
        target = index.value(contents)
        if target is None:
            # Not a decoded stream and not an object this reads: it shows nothing here.
            return []
        if not isinstance(target, list):
            return []
        refs = target
    elif isinstance(contents, list):
        refs = contents
    else:
        return []
    return [ref[0] for ref in refs if isinstance(ref, tuple) and ref[0] in streams]


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
    if parent in index.inherited:
        return index.inherited[parent]
    # Marked before the walk, so a /Parent loop ends here instead of recursing.
    index.inherited[parent] = None
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
    index.inherited[parent] = found
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
