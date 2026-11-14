"""The text a PDF reader shows: strings of Tj, TJ, ', and " joined per BT ... ET block.

A content stream rarely holds a sentence as one string. Word, LaTeX, and browsers write kerned
``[(Ign) -20 (ore)] TJ`` arrays, one word per ``Tj``, or hex strings, so the raw and
``pdf-flate`` views see fragments. This module rebuilds each text block from the operators and
decodes each string through its font: a simple font as WinAnsi bytes, a font with a ToUnicode
CMap through that map, and a Type0 font with no map whose encoding is a predefined Unicode
CMap as UTF-16BE. Any other composite (two-byte) font with no readable ToUnicode map cannot be
decoded; the caller reports that as a coverage note instead of a silent clean. A font object
or ToUnicode map that the file defines more than once is read through every definition, since
readers differ in which one they use. A font's map is the one its own dictionary names, each
of them when the key is written more than once; what follows the dictionary is read with it
only where some reader could take it for the font's (``_Definitions.ways``). A composite font
that names no map is still read through a map the 4 KB after its header hold, and through
that alone unless its encoding is a predefined Unicode CMap (detection backlog B8).

Nothing is rendered and no font program is read. Positions are not tracked, so text placed out
of reading order is joined in stream order, and a sentence split across two text blocks is not
rejoined. Every loop is bounded and checks the scan deadline.

Text a reader does not show is also collected on its own (``PdfText.hidden``): text drawn in
render mode 3 (invisible) or 7 (clip only); text painted only in near-white whose first glyph
sits on nothing the same content stream painted in another colour (a filled path, an image, or
a shading, each taken as its bounding box), so white on a dark header or slide stays shown;
and, in a page's own content streams, text under 1 pt or placed outside every ``/MediaBox`` in
the file. Form XObjects, patterns, and glyph procedures are drawn through a matrix this reader
does not know, so their size and position are not judged. Clipping, transparency, blend modes,
and text covered by a later fill are not computed.
"""

from __future__ import annotations

import binascii
import math
import re
import unicodedata
import zlib
from collections import Counter
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import cached_property

from yara_gate.content import (
    _PDF_END,
    _PDF_OBJ_HEADER,
    _PDF_STREAM,
    Budget,
    ContentLimit,
    PdfStream,
    _pdf_stream_dict,
    _pdf_tokens,
    _pdf_value,
)
from yara_gate.heuristics import (
    _PDF_HEADER,
    _PDF_VALUE_WINDOW,
    MAX_PDF_DEFINITIONS,
    _pdf_header_key,
    _pdf_reference,
    _pdf_value_end,
)
from yara_gate.pdfpages import PlainFile, page_font_refs, plain_dictionary

MAX_TEXT_BLOCKS = 20_000
MAX_BLOCK_CHARS = 64 * 1024
_CHUNK_OVERLAP = 1024
MAX_TOKENS = 4_000_000
# A TJ array holds a few hundred items; one this long is not text a reader shows.
MAX_ARRAY_ITEMS = 100_000
MAX_CMAP_ENTRIES = 1 << 17
MAX_CMAP_BYTES = 64 * 1024 * 1024
_MAX_CMAP_CODE_BYTES = 4
MAX_PDF_DECODED_CHARS = 16 * 1024 * 1024
# ToUnicode entries written in one file, across all its fonts and overwrites included. One
# 20-byte `<0000> <FFFF> <0000>` bfrange writes 65,536 entries, so many fonts with their own
# maps, or one map repeating the range, would otherwise spend the deadline and memory on maps.
MAX_CMAP_TOTAL = 4 * MAX_CMAP_ENTRIES
# CMap tokens lexed in one file. A well-formed entry takes two tokens (bfchar) or at most three
# (a one-code bfrange), so this admits every map within MAX_CMAP_TOTAL.
MAX_CMAP_TOKENS = 3 * MAX_CMAP_TOTAL
# Each text string is decoded once per font its resource name means, up to this many. Past
# it, or past MAX_FONT_REFERENCES fonts behind one name, some readings go undecoded, which is
# reported as unmapped text (docs/verification/2026-11-07-pdf-font-readings.md). The reading
# of a font with no map, WinAnsi bytes, is one more pass and is not counted
# (``_Paragraphs.show``).
MAX_FONT_VARIANTS = 4
MAX_FONT_REFERENCES = 64
# Raw definitions of one object number read as a font or a font resource dictionary. A font
# with more is also given an unresolved reading, and a resource dictionary with more leaves
# every name unsettled, so the text is reported as unmapped
# (docs/verification/2026-11-10-pdf-font-definitions.md).
MAX_FONT_DEFINITIONS = MAX_PDF_DEFINITIONS
# Bytes read past the lookup's 4 KB window, over every long font object in one file. Objects
# that do not overlap stay under it in any file this size or smaller; past it a long font is
# given an unresolved reading instead of being read to its end.
MAX_FONT_OBJECT_BYTES = 256 * 1024 * 1024
# Bytes of font dictionaries read token by token in one file, to find each one's own keys:
# half the file's size, and never less than this. A font dictionary is a few hundred bytes,
# or a few kilobytes with its widths written in it, and an object stream's members are
# decoded bytes, which the file's size does not bound. Past the allowance a font is read as
# it was before its own dictionary was, and given an unresolved reading.
MIN_FONT_DICTIONARY_BYTES = 1024 * 1024
# Bytes of font dictionaries read with the lenient lexer in one file. It is needed only for
# a dictionary that is not written plainly, which generators do not write, and it is slower
# than the strict one. Past it such a font is read as it was before and given an unresolved
# reading.
MAX_LOOSE_FONT_BYTES = 512 * 1024
# Ways one definition of a font is read (``_Definitions.ways``): a /ToUnicode key written
# five times is five. A definition with more is also given an unresolved reading, and so is
# a font whose definitions have more than this many ways between them besides each one's
# first.
MAX_FONT_WAYS = MAX_FONT_VARIANTS + 1
# Readings of further ways kept for one font, and looked at for one resource name. A string
# is decoded through fewer, so past this the name is given an unresolved reading instead.
MAX_FURTHER_READINGS = 2 * MAX_FONT_VARIANTS
# A TJ adjustment is in thousandths of an em; a gap this wide reads as a word space.
_SPACE_ADJUST = -200.0

_NUMBER = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)\Z")
_CP1252 = [bytes((value,)).decode("cp1252", errors="replace") for value in range(256)]
_HEX_WHITESPACE = b"\x00\t\n\f\r "
_NOT_HEX = re.compile(rb"[^0-9A-Fa-f]")
_INLINE_IMAGE_END = re.compile(rb"[\x00\t\n\f\r ]EI(?=[\x00\t\n\f\r ]|\Z)")
_LITERAL_ESCAPES = {
    ord("n"): b"\n",
    ord("r"): b"\r",
    ord("t"): b"\t",
    ord("b"): b"\b",
    ord("f"): b"\f",
    ord("("): b"(",
    ord(")"): b")",
    ord("\\"): b"\\",
}

_FONT_RESOURCES = re.compile(rb"/Font[\x00\t\n\f\r ]*<<(.{0,8192}?)>>", re.DOTALL)
_FONT_RESOURCE_REF = re.compile(
    rb"/Font[\x00\t\n\f\r ]+([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+R\b"
)
_NAME_REF = re.compile(
    rb"/([^\x00\t\n\f\r ()<>\[\]{}/%]{1,127})"
    rb"[\x00\t\n\f\r ]+([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+R\b"
)
_TO_UNICODE = re.compile(
    rb"/ToUnicode[\x00\t\n\f\r ]+([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+R\b"
)
_TYPE0 = re.compile(rb"/Subtype[\x00\t\n\f\r ]*/Type0\b")
_IDENTITY = re.compile(rb"/Encoding[\x00\t\n\f\r ]*/Identity-[HV]\b")
_IDENTITY_NAMES = (b"/Identity-H", b"/Identity-V")
# Adobe's predefined CMaps whose codes are Unicode (ISO 32000-1, 9.7.5.2, Table 118): a font
# that names one and no /ToUnicode shows UTF-16BE codes.
_UNICODE_CMAP = re.compile(rb"/Uni(?:GB|CNS|JIS|KS)-(?:UCS2|UTF16)(?:-HW)?-[HV]")
# The map number a way gives such a font in place of "no map": no object has it.
_UTF16_MAP = -1
# The encodings whose printable ASCII a font with no map shows as this reader decodes it.
_LATIN_ENCODINGS = (b"/WinAnsiEncoding", b"/MacRomanEncoding")
# What the reading of a font dictionary can turn on, as bytes: a /ToUnicode key, a composite
# /Subtype or /Encoding, a ``#`` that can spell any of them, and a string or a comment, which
# can hold the bytes ``endobj``.
_FONT_CUES = re.compile(rb"[#(%]|ToUnicode|/Type0|/Identity-")
# ``endobj`` as a token of its own: after whitespace or a closing bracket, and ending there.
_ENDOBJ = re.compile(rb"(?<![^\x00\t\n\f\r \]>])endobj(?![^\x00\t\n\f\r /<>\[\]()%{}])")
_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{2})")
_LOOSE_ESCAPE = re.compile(rb"#([0-9A-Fa-f]{0,2})")
# A ``#`` that keeps a font dictionary from settling how the font is read: one readers do
# not all take alike (it does not start two hex digits, or it spells NUL), and one that
# spells a byte outside printable ASCII. PDFium reads a TrueType font whose /BaseFont starts
# with one of five two-character names in GBK, and has no font file, as a composite font.
_ODD_ESCAPE = re.compile(rb"#(?![2-6][0-9A-Fa-f]|7[0-9A-Ea-e])")
_CMAP_BEGIN = re.compile(rb"begin(codespacerange|bfchar|bfrange)")
_CMAP_TOKEN = re.compile(rb"<([0-9A-Fa-f\x00\t\n\f\r ]*)>|\[|\]")

Lookup = Callable[[int, int], list[bytes]]
# One way a font definition is read: its ToUnicode map's object number, or None for no map,
# and whether the font is composite.
_Way = tuple[int | None, bool]
# A dictionary entry as readers may take it: the names its key can be; the names its value
# can be, the object number it refers to, or None for any other value; and whether the
# value is written as every reader takes it (``pdfpages._EXACT_REFERENCE``).
_Entry = tuple[tuple[bytes, ...], tuple[bytes, ...] | int | None, bool]


@dataclass
class Font:
    """How a font's string bytes become text: ``cmap`` when it has a map, else WinAnsi."""

    composite: bool
    cmap: dict[bytes, str] | None = None
    lengths: tuple[int, ...] = (1,)
    # No font: what a reader that compares generations finds for a reference whose generation
    # no definition has. It shows the string in a fallback font, read here as WinAnsi.
    missing: bool = False
    # A composite font with no map whose /Encoding is a predefined Unicode CMap: its codes are
    # UTF-16BE, read as PDFium, pdfminer.six, and pypdf read them (backlog B8).
    utf16: bool = False

    @property
    def unreadable(self) -> bool:
        return self.composite and not self.cmap and not self.utf16

    @cached_property
    def widest(self) -> int:
        """The most characters one code decodes to: the longest map value, and at least the
        one WinAnsi character a simple font falls back to."""
        return max(1, max(map(len, self.cmap.values()), default=0)) if self.cmap else 1


@dataclass
class PdfText:
    """Text blocks, multi-block paragraphs, and whether some text could not be decoded.

    ``unmapped`` is set when a composite font has no readable map, a font the file never
    resolves shows two-byte codes, or a string is shown in a resource name that means more
    fonts than ``MAX_FONT_VARIANTS`` (or ``MAX_FONT_REFERENCES``), so a reading went undecoded.
    A font object or ToUnicode map defined more than once counts once per distinct definition,
    and so does each way a font dictionary can be read; the reading with no map is not counted.

    ``blocks`` holds the joined strings of each text object (BT ... ET), cut where the text
    moves to a new paragraph, so each is scanned on its own. ``paragraphs`` holds the text of
    each paragraph that spans two or more blocks (a word in bold, a wrapped line), which no
    single block shows whole.
    """

    blocks: list[str] = field(default_factory=list)
    paragraphs: list[str] = field(default_factory=list)
    unmapped: bool = False
    # The same grouping for text drawn so that a reader does not see it.
    hidden_blocks: list[str] = field(default_factory=list)
    hidden_paragraphs: list[str] = field(default_factory=list)
    decoded_chars: int = field(default=0, repr=False)

    @property
    def hidden(self) -> list[str]:
        return self.hidden_blocks + self.hidden_paragraphs


Box = tuple[float, float, float, float]
_BOX_NUMBER = rb"([+-]?(?:\d{1,9}+(?:\.\d{0,9}+)?|\.\d{1,9}+))"
_MEDIA_BOX = re.compile(
    rb"/MediaBox[\x00\t\n\f\r ]*+\[[\x00\t\n\f\r ]*+"
    + rb"[\x00\t\n\f\r ]++".join([_BOX_NUMBER] * 4)
    + rb"[\x00\t\n\f\r ]*+\]"
)
# Stream dictionary keys of a form XObject, pattern, or other stream drawn through its own matrix.
_NOT_PAGE_KEYS = frozenset({b"/Subtype", b"/Type", b"/PatternType", b"/BBox", b"/Matrix"})
_CONTENTS_ARRAY = re.compile(rb"/Contents[\x00\t\n\f\r ]*+\[")
_PAGE_DICT_WINDOW = 4096


def pdf_text(data: bytes, streams: list[PdfStream], objects: Lookup, budget: Budget) -> PdfText:
    """Text blocks from every content stream in ``streams``, decoded through the file's fonts."""
    result = PdfText()
    if not data.startswith(b"%PDF"):
        return result
    # Every stream under one object number, in file order: a ToUnicode map defined twice is
    # read through each definition.
    by_number: dict[int, list[bytes | None]] = {}
    for stream in streams:
        if stream.number is not None:
            by_number.setdefault(stream.number, []).append(stream.text)
    reader = _FontReader(data, objects, _Cmaps(by_number, budget), budget)
    fonts = _fonts(data, streams, objects, reader, budget)
    # Each page content stream reads a name through its own page's fonts; a stream or name the
    # page tree does not settle keeps the file-wide union
    # (docs/verification/2026-11-10-pdf-page-fonts.md). Where no name means two fonts there is
    # nothing to tell apart, so the page tree is not read at all.
    pages = None
    if any(len(found) > 1 for found in fonts.values()):
        plain = reader.definitions.plain
        pages = page_font_refs(data, objects, streams, budget, MAX_FONT_REFERENCES, plain)
    if pages:
        reader.prime(
            {ref for names in pages.values() if names for refs in names.values() for ref in refs},
        )
    if reader.definitions.resources_unread:
        # A /Font resource dictionary has more definitions than were read, so what a name
        # means in the unread ones is not known: no text in the file counts as decoded.
        result.unmapped = True
    by_page: dict[int, Mapping[bytes, list[Font]]] = {}
    box = _page_box([data, *(stream.inflated for stream in streams if stream.inflated)], budget)
    tokens = 0
    # Keep the existing font approximation in file order. Visibility needs stronger evidence
    # of a continuation because leaking an invisible mode across pages can hold shown text.
    occurrences = Counter(stream.number for stream in streams)
    predecessors = _contents_predecessors(data, occurrences, budget) if len(streams) > 1 else {}
    if len(streams) > 1:
        _other_contents(data, streams, objects, occurrences, predecessors, budget)
    joined, members = _joined_contents(data, streams, occurrences, predecessors, pages, budget)
    previous: int | None = None
    state = _TextState()
    for stream in streams:
        number = stream.number
        if number in members:
            # Read as part of the /Contents array it belongs to, from the array's first stream.
            continue
        body = joined.get(number, stream.text) if number is not None else stream.text
        linked = number in predecessors
        if number is None or not linked or previous is None or predecessors.get(number) != previous:
            state.render = 0
            state.white = state.white_stroke = False
        previous = None
        if body is None or (
            not linked and b"BT" not in body and b"Tj" not in body and b"TJ" not in body
        ):
            continue
        page = _page_content(data, stream)
        if state.name is not None:
            # A font selected in an earlier stream is carried in by its name and read through
            # every font the name means: which stream a reader continues from is not known.
            state.fonts = fonts.get(state.name, [])
        selected: Mapping[bytes, list[Font]] = fonts
        names = pages.get(number) if page and pages and number is not None else None
        if names and number is not None:
            if number not in by_page:
                by_page[number] = _PageFonts(names, reader, fonts)
            selected = by_page[number]
        tokens = _blocks(body, selected, result, budget, tokens, state, box if page else None, page)
        if linked and page:
            previous = number
    return result


# Streams of one /Contents array read as one: an array is one stream (ISO 32000-1, 7.8.2).
MAX_JOINED_STREAMS = 1024


def _joined_contents(
    data: bytes,
    streams: list[PdfStream],
    occurrences: Counter[int | None],
    predecessors: dict[int, int | None],
    pages: Mapping[int, object] | None,
    budget: Budget,
) -> tuple[dict[int, bytes], set[int]]:
    """The streams of each direct /Contents array joined in array order, as every reader
    joins them, keyed by the array's first stream; and the numbers of the other members.

    A run is joined only where ``predecessors`` names each stream's place once, each member is
    one decoded stream, its dictionary marks it as page content, and the page map gives every
    member the same fonts. A run breaks where any of these fails, and the streams on either side
    are read as before. Streams are joined with a line feed, so a token never straddles two.
    """
    single = {
        stream.number: stream
        for stream in streams
        if stream.number is not None and occurrences[stream.number] == 1
    }
    successor: dict[int, int] = {}
    shared: set[int] = set()
    for number, before in predecessors.items():
        if before is None or before not in single or number not in single:
            continue
        if before in successor:
            shared.add(before)
        successor[before] = number
    for before in shared:
        del successor[before]
    joined: dict[int, bytes] = {}
    members: set[int] = set()
    if not successor:
        return joined, members
    following = set(successor.values())
    content: dict[int, bool] = {}

    def readable(number: int) -> bool:
        stream = single[number]
        if stream.text is None and not _empty_stream(data, stream):
            return False
        if number not in content:
            content[number] = _page_content(data, stream)
        return content[number]

    def fonts_of(number: int) -> object:
        return pages.get(number) if pages else None

    def flush(run: list[int]) -> None:
        if len(run) > 1:
            joined[run[0]] = b"\n".join(single[number].text or b"" for number in run)
            members.update(run[1:])

    for count, head in enumerate(number for number in successor if number not in following):
        if count % 4096 == 0:
            budget.check()
        run: list[int] = []
        seen: set[int] = set()
        current: int | None = head
        while current is not None and current not in seen:
            seen.add(current)
            if readable(current) and (not run or fonts_of(current) == fonts_of(run[0])):
                if len(run) >= MAX_JOINED_STREAMS:
                    flush(run)
                    run = []
                run.append(current)
            else:
                flush(run)
                run = [current] if readable(current) else []
            current = successor.get(current)
        flush(run)
    return joined, members


def _empty_stream(data: bytes, stream: PdfStream) -> bool:
    """True for a stream that holds nothing, written as it is or deflated: an empty member of a
    /Contents array, which a reader joins past."""
    start = _PDF_STREAM.match(data, stream.offset)
    if start is None:
        return False
    end = _PDF_END.search(data, start.end(), start.end() + 64)
    if end is None:
        return False
    body = data[start.end() : end.start()]
    if not body.strip(b"\x00\t\n\f\r "):
        return True
    try:
        return zlib.decompress(body) == b""
    except zlib.error:
        return False


def _contents_predecessors(
    data: bytes, occurrences: Counter[int | None], budget: Budget
) -> dict[int, int | None]:
    """Identify adjacent streams in direct /Contents arrays of raw page dictionaries.

    The page object around each ``/Contents[`` is the nearest object header that ends before
    it and starts within ``_PAGE_DICT_WINDOW``, read up to the first ``endobj`` after it inside
    that window. The header cursor and ``endobj`` search move forward only. Each object is
    parsed once however many matches fall inside it, and only the current and next header
    are retained.
    Merging one page's references is idempotent, so parsing it once gives the same result.
    """
    predecessors: dict[int, int | None] = {}
    headers = _PDF_OBJ_HEADER.finditer(data)
    upcoming = current = None
    headers_seen = 0
    last_parsed = -1
    next_end = -2  # The first endobj at or after the last search point; -1 when there is none.
    for count, match in enumerate(_CONTENTS_ARRAY.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        if count == 0:
            upcoming = next(headers, None)
        while upcoming is not None and upcoming.end() <= match.start():
            current = upcoming
            if headers_seen % 4096 == 0:
                budget.check()
            headers_seen += 1
            upcoming = next(headers, None)
        if current is None or current.start() < match.start() - _PAGE_DICT_WINDOW:
            continue
        start = current.end()
        if start == last_parsed:
            continue
        last_parsed = start
        if next_end != -1 and next_end < match.end():
            next_end = data.find(b"endobj", match.end())
        if next_end == -1 or next_end + len(b"endobj") > start + _PAGE_DICT_WINDOW:
            continue
        end = next_end
        if not (tokens := _pdf_tokens(data, start, end)):
            continue
        try:
            page, used = _pdf_value(tokens, 0)
        except (IndexError, ValueError):
            continue
        if used != len(tokens) or not isinstance(page, dict) or page.get(b"/Type") != b"/Page":
            continue
        refs = page.get(b"/Contents")
        if not isinstance(refs, list):
            continue
        _link(refs, occurrences, predecessors)
    return predecessors


def _link(
    refs: Sequence[object], occurrences: Counter[int | None], predecessors: dict[int, int | None]
) -> None:
    """Record each stream of one /Contents array after the one before it."""
    previous: int | None = None
    for ref in refs:
        if not isinstance(ref, tuple) or ref[1] != 0:
            previous = None
            continue
        number = ref[0]
        # A stream reused in different positions cannot safely inherit either state.
        if occurrences[number] == 1:
            predecessors[number] = (
                previous if predecessors.get(number, previous) == previous else None
            )
        previous = number


_CONTENTS_VALUE = re.compile(
    rb"/Contents[\x00\t\n\f\r ]*+(?:([0-9]{1,10})[\x00\t\n\f\r ]++0[\x00\t\n\f\r ]++R"
    # An array of references holds only digits, R, and white space, so a "[" followed by
    # anything else fails at once and repeated "/Contents[" costs one step each.
    rb"|(\[[0-9R\x00\t\n\f\r ]{0,65536}+\]))"
)
_OBJECT_END = frozenset({b"endobj", b"stream"})
# /Contents values read past the raw page dictionaries, so one hostile file cannot make many.
MAX_OTHER_CONTENTS = 4096


def _other_contents(
    data: bytes,
    streams: list[PdfStream],
    objects: Lookup,
    occurrences: Counter[int | None],
    predecessors: dict[int, int | None],
    budget: Budget,
) -> None:
    """Add the /Contents arrays ``_contents_predecessors`` cannot see: an array kept in an object
    of its own (``/Contents 7 0 R``), and a page dictionary kept in an object stream.

    Every reader follows both (ISO 32000-1, 7.7.3.3: the value may be a reference to an array).
    A referenced object is used only when it has one definition and it is an array; an array in
    an object stream is used as written.
    """
    sources = [data]
    for stream in streams:
        if stream.inflated:
            dictionary = _pdf_stream_dict(data, stream.offset)
            # Only an object stream holds page dictionaries; a content stream's own text is not one.
            if dictionary is not None and dictionary.get(b"/Type") == b"/ObjStm":
                sources.append(stream.inflated)
    count = 0
    for source in sources:
        budget.check()
        for match in _CONTENTS_VALUE.finditer(source):
            count += 1
            if count % 4096 == 0:
                budget.check()
            if count > MAX_OTHER_CONTENTS:
                return
            if match.group(1) is not None:
                # A reference to a stream has nothing to order; only an array object is used.
                bodies = objects(int(match.group(1)), 0)
                if len(bodies) != 1:
                    continue
                text = bodies[0]
            elif source is data:
                # A direct array in the file's own bytes is the raw page dictionaries' case.
                continue
            else:
                text = match.group(2)
            # A raw definition runs on past its object; it is read up to its endobj.
            tokens = _pdf_tokens(text, 0, min(len(text), 65536), _OBJECT_END)
            if not tokens:
                continue
            try:
                value, used = _pdf_value(tokens, 0)
            except (IndexError, ValueError):
                continue
            if used == len(tokens) and isinstance(value, list):
                _link(value, occurrences, predecessors)


def _page_box(sources: list[bytes], budget: Budget) -> Box | None:
    """The union of every ``/MediaBox`` written in the file, or None when there is none."""
    found: Box | None = None
    for source in sources:
        budget.check()
        for index, match in enumerate(_MEDIA_BOX.finditer(source)):
            if index % 4096 == 0:
                budget.check()
            try:
                a, b, c, d = (float(group) for group in match.groups())
            except ValueError:
                continue
            box = (min(a, c), min(b, d), max(a, c), max(b, d))
            if found is None:
                found = box
            else:
                found = (
                    min(found[0], box[0]),
                    min(found[1], box[1]),
                    max(found[2], box[2]),
                    max(found[3], box[3]),
                )
    return found


def _page_content(data: bytes, stream: PdfStream) -> bool:
    """True for a stream whose dictionary marks it as page content, drawn in page space."""
    dictionary = _pdf_stream_dict(data, stream.offset)
    return dictionary is not None and not (_NOT_PAGE_KEYS & dictionary.keys())


def _fonts(
    data: bytes,
    streams: list[PdfStream],
    objects: Lookup,
    reader: _FontReader,
    budget: Budget,
) -> dict[bytes, list[Font]]:
    """Resource name to the distinct fonts it names anywhere in the file (pages may differ)."""
    definitions = reader.definitions
    sources: list[bytes] = [data]
    sources.extend(stream.text for stream in streams if stream.text and stream.inflated)
    references: dict[bytes, set[tuple[int, int]]] = {}
    truncated: set[bytes] = set()
    dictionaries: list[bytes] = []
    indirect: set[tuple[int, int]] = set()
    for source in sources:
        budget.check()
        dictionaries.extend(match.group(1) for match in _FONT_RESOURCES.finditer(source))
        indirect.update(
            (int(match.group(1)), int(match.group(2)))
            for match in _FONT_RESOURCE_REF.finditer(source)
        )
    # One pass over the file finds every wanted object; a lookup per key would rescan it.
    definitions.prime(indirect)
    for number in sorted({number for number, _ in indirect}):
        bodies, complete, _ = definitions(number)
        dictionaries.extend(body for body, _ in bodies)
        if not complete:
            definitions.resources_unread = True
    for dictionary in dictionaries:
        for ref in _NAME_REF.finditer(dictionary):
            name = _name(ref.group(1))
            slot = references.setdefault(name, set())
            key = (int(ref.group(2)), int(ref.group(3)))
            if len(slot) < MAX_FONT_REFERENCES:
                slot.add(key)
            elif key not in slot:
                truncated.add(name)
    fonts: dict[bytes, list[Font]] = {}
    reader.prime(key for refs in references.values() for key in refs)
    for name, refs in references.items():
        found = reader.readings(refs)
        unresolved = Font(True, None, (2,))
        if name in truncated and unresolved not in found:
            # The fonts past the reference cap are never resolved: a composite font with no
            # map stands for them, so text shown in this name is reported as unmapped.
            found.append(unresolved)
        if found:
            fonts[name] = found
    return fonts


class _PageFonts(Mapping[bytes, list[Font]]):
    """One content stream's fonts: its pages' fonts for the names they list, resolved when a
    ``Tf`` selects one, and the file-wide union for every other name."""

    def __init__(
        self,
        names: Mapping[bytes, Iterable[tuple[int, int]]],
        reader: _FontReader,
        union: Mapping[bytes, list[Font]],
    ) -> None:
        self._names = names
        self._reader = reader
        self._union = union
        self._resolved: dict[bytes, list[Font]] = {}

    def __getitem__(self, name: bytes) -> list[Font]:
        if name in self._names:
            if name not in self._resolved:
                self._resolved[name] = self._reader.readings(self._names[name])
            resolved = self._resolved[name]
            if resolved and not any(font.missing for font in resolved):
                return resolved
        return self._union[name]

    def __iter__(self) -> Iterator[bytes]:
        yield from self._names
        yield from (name for name in self._union if name not in self._names)

    def __len__(self) -> int:
        return len(self._names) + sum(1 for name in self._union if name not in self._names)


class _FontReader:
    """Fonts by object number, each read once whichever names and pages share it."""

    def __init__(self, data: bytes, objects: Lookup, cmaps: _Cmaps, budget: Budget) -> None:
        self.definitions = _Definitions(data, objects, budget)
        self._cmaps = cmaps
        self._check = budget.check
        # By object number: a reference's generation does not choose among the definitions.
        self._cache: dict[int, _Readings] = {}
        self._undefined: dict[tuple[int, int], bool] = {}
        # Names that list the same references mean the same fonts, and a file can have
        # thousands of them.
        self._named: dict[frozenset[tuple[int, int]], tuple[Font, ...]] = {}

    def prime(self, refs: Iterable[tuple[int, int]]) -> None:
        self.definitions.prime(refs)

    def readings(self, refs: Iterable[tuple[int, int]]) -> list[Font]:
        """The distinct readings of ``refs``: every font's first, then any further ones.

        A further reading of one font (another definition of it, or a carried map) comes
        after every font's first, so it never displaces a font the name also means within
        MAX_FONT_VARIANTS. The readings of a font's further ways (``_font``) come after all
        of those, whichever font they belong to, so they never displace a reading the fonts
        had before a definition was read more than one way. Past ``MAX_FURTHER_READINGS``
        of them the name is given an unresolved reading.
        """
        refs = frozenset(refs)
        known = self._named.get(refs)
        if known is not None:
            return list(known)
        keys = sorted(refs)
        found: list[Font] = []
        alternates: list[Font] = []
        further: list[Font] = []
        held: set[int] = set()
        if keys and all(self._is_undefined(key) for key in keys):
            # No reference has a font under its own generation. A reader that compares
            # generations (pdf.js) then has no font and shows the string in a fallback one.
            # That reading comes first so the cap never drops it; the definitions under other
            # generations, which a reader that ignores generations uses, follow.
            found.append(Font(False, missing=True))
        for number in sorted({number for number, _ in keys}):
            self._check()
            if number not in self._cache:
                self._cache[number] = _font(number, self.definitions, self._cmaps)
            readings = self._cache[number]
            if readings and readings[0] not in found:
                found.append(readings[0])
            alternates.extend(each for each in readings[1:] if each not in alternates)
            # Fonts that share a way share its reading, the very object: it is listed once.
            for each in readings.further:
                if id(each) not in held:
                    held.add(id(each))
                    further.append(each)
        found.extend(each for each in alternates if each not in found)
        # A reading that decodes nothing takes no place before one that decodes.
        further.sort(key=lambda each: each.unreadable)
        if len(further) > MAX_FURTHER_READINGS:
            further[MAX_FURTHER_READINGS:] = [Font(True, None, (2,))]
        for each in further:
            if not any(_same_text(each, have) for have in found):
                found.append(each)
        self._named[refs] = tuple(found)
        return found

    def _is_undefined(self, key: tuple[int, int]) -> bool:
        if key not in self._undefined:
            self._check()
            self._undefined[key] = not self.definitions.exact(*key)
        return self._undefined[key]


class _Definitions:
    """Every definition of an object number, whatever generation its header or a reference has.

    A file can define one object number more than once: an incremental update appends a new
    ``6 0 obj``, a reused number carries a new generation, and an object stream can hold a
    member that a raw definition also names. A reader takes one of them, and readers differ in
    which. One that follows the cross-reference table takes the entry the last section names.
    One that rebuilds a damaged table takes a later or higher-generation header. PDFium, MuPDF,
    and pdfminer.six resolve a reference by object number alone, and pdf.js falls back to an
    earlier generation, so ``6 0 R`` can reach ``6 1 obj``
    (docs/verification/2026-11-10-pdf-font-definitions.md). Each definition is therefore one
    some reader may use, and the caller reads every one.

    The raw definitions kept are the first ``MAX_FONT_DEFINITIONS`` in the file, the last of
    them replaced by the file's last when there are more. The lookup adds the bodies only it
    has: its own definitions under each generation a reference names, and object-stream
    members, which it returns for generation 0. A body is the lookup's window; ``to_unicode``
    reads a raw definition to its ``endobj``, and ``ways`` reads a definition's own dictionary
    to its closing bracket.

    With ``looks``, only the bodies it accepts are returned, ordered for a caller that decodes
    a few of them. First comes the one a generation-exact lookup reads under each generation a
    reference names: the first such body under that generation, so the cap never drops what a
    reader that honours generations shows. The count of those leading bodies is returned with
    them. Generation 0 is looked up for object-stream members whether or not a reference names
    it, and is not among them unless one does. The other raw definitions follow in the order
    of ``_likeliest``, then the other bodies of the lookup.
    """

    def __init__(self, data: bytes, objects: Lookup, budget: Budget) -> None:
        self._data = data
        self._objects = objects
        self._budget = budget
        self._check = budget.check
        self._starts: dict[int, list[tuple[int, int]]] = {}
        self._complete: dict[int, bool] = {}
        self._generations: dict[int, set[int]] = {}
        self._named: dict[int, set[int]] = {}
        self._long: dict[int, re.Match[bytes] | None] = {}
        self._read = 0
        # Bytes of font dictionaries read token by token (MIN_FONT_DICTIONARY_BYTES).
        self._lexed = 0
        # Bytes of them read with the lenient lexer (MAX_LOOSE_FONT_BYTES).
        self._loose = 0
        # Whether every reader finds this file's objects in the same places. It is asked only
        # when a font's own dictionary and the window after its header read differently.
        self.plain = PlainFile(data, objects, budget)
        # Set by ``_fonts`` when a /Font resource dictionary has definitions that were not read.
        self.resources_unread = False

    def prime(self, refs: Iterable[tuple[int, int]]) -> None:
        """Find every header of the referenced object numbers in one pass over the file."""
        keys = set(refs)
        for number, generation in keys:
            self._generations.setdefault(number, {0}).add(generation)
            self._named.setdefault(number, set()).add(generation)
        wanted = {number for number, _ in keys if number not in self._starts}
        if wanted:
            found: dict[int, list[tuple[int, int]]] = {number: [] for number in wanted}
            last: dict[int, tuple[int, int]] = {}
            for count, match in enumerate(_PDF_HEADER.finditer(self._data)):
                if count % 4096 == 0:
                    self._check()
                key = _pdf_header_key(match.group(1), match.group(2))
                if key is None or key[0] not in found:
                    continue
                if len(found[key[0]]) < MAX_FONT_DEFINITIONS:
                    found[key[0]].append((match.end(), key[1]))
                else:
                    last[key[0]] = (match.end(), key[1])
            for number, slot in found.items():
                self._complete[number] = number not in last
                if number in last:
                    slot[-1:] = [last[number]]
            self._starts.update(found)
        _prime(self._objects, keys | {(number, 0) for number, _ in keys})

    def __call__(
        self, number: int, looks: Callable[[bytes], bool] | None = None
    ) -> tuple[list[tuple[bytes, int | None]], bool, int]:
        """Each definition's body with its file offset (None when only the lookup has it),
        whether that is all of them (False when a cap left some unread), and how many of the
        leading bodies are the ones a generation-exact lookup reads."""
        if number not in self._starts:
            self.prime([(number, 0)])
        complete = self._complete[number]
        raw = [
            (self._data[start : start + _PDF_VALUE_WINDOW], start, generation)
            for start, generation in self._starts[number]
        ]
        seen = {(generation, body) for body, _, generation in raw}
        extra: list[tuple[bytes, int | None, int]] = []
        for generation in sorted(self._generations.get(number, {0})):
            if len(extra) >= MAX_FONT_DEFINITIONS:
                complete = False
                break
            for body in self._objects(number, generation):
                if (generation, body) not in seen:
                    seen.add((generation, body))
                    extra.append((body, None, generation))
        if looks is None:
            return [(body, start) for body, start, _ in raw + extra], complete, 0
        if len(raw) == 1 and not extra and self._complete[number]:
            # The usual font: one definition, nothing to order.
            body, start, generation = raw[0]
            if not looks(body):
                return [], complete, 0
            return [(body, start)], complete, int(generation in self._named.get(number, ()))
        # Past the cap the last raw header is the file's last, later than any body of the lookup.
        cut = len(raw) if self._complete[number] else len(raw) - 1
        head = [entry for entry in raw[:cut] if looks(entry[0])]
        tail = [entry for entry in raw[cut:] if looks(entry[0])]
        extra = [entry for entry in extra if looks(entry[0])]
        exact: dict[int, tuple[bytes, int | None, int]] = {}
        for entry in head + extra + tail:
            if entry[2] in self._named.get(number, ()):
                exact.setdefault(entry[2], entry)
        first = [exact[generation] for generation in sorted(exact)]
        taken = {id(entry) for entry in first}
        ordered = first + [entry for entry in _likeliest(head + tail) if id(entry) not in taken]
        ordered += [entry for entry in extra if id(entry) not in taken]
        return [(body, start) for body, start, _ in ordered], complete, len(first)

    def exact(self, number: int, generation: int) -> bool:
        """Whether a font is defined under exactly this generation, as a lookup that compares
        generations finds it (an object-stream member counts as generation 0)."""
        return any(_looks_like_a_font(body) for body in self._objects(number, generation))

    def to_unicode(self, start: int) -> tuple[re.Match[bytes] | None, bool]:
        """The /ToUnicode reference of the raw definition at ``start``, read to its ``endobj``,
        and whether it was read: False once ``MAX_FONT_OBJECT_BYTES`` are spent.

        Each definition is read once. Objects that do not overlap add up to the file's size at
        most; headers with no ``endobj`` between them would each be read for 1 MiB.
        """
        if start not in self._long:
            if self._read > MAX_FONT_OBJECT_BYTES:
                return None, False
            self._check()
            end = self._data.find(b"endobj", start, start + _MAX_OBJECT_BYTES)
            end = end if end >= 0 else min(len(self._data), start + _MAX_OBJECT_BYTES)
            self._read += end - start
            self._long[start] = _TO_UNICODE.search(self._data, start, end)
        return self._long[start], True

    def ways(self, body: bytes, start: int | None) -> tuple[list[_Way], bool]:
        """How one definition can be read, and whether all of it was read: False when an
        allowance ran out or the definition has more ways than ``MAX_FONT_WAYS``.

        The window after a header runs into the objects that follow, so its first
        ``/ToUnicode`` or ``/Type0`` can belong to the next font, or sit in a string, a
        comment, or a nested dictionary of this one. That reading comes first wherever a
        reader could give it: poppler reads on into the next object when a dictionary's
        ``>>`` is missing, PDFium reads a string's bytes as tokens where a key belongs, and
        a cross-reference entry can send a reader to the next object's header. After it come
        the readings of the definition's own dictionary, one for each value a repeated key
        has (``_ways``), so a font with no map of its own is also read with none.

        The window's map is dropped only when the dictionary is one plainly written value
        whose reading is settled (``_own``) and the file is written plainly throughout
        (``PlainFile``). Every reader then finds the same dictionary at the same place, and
        nothing outside it is part of the font. The window's word that the font is composite
        is kept for each map the font itself names: a map with no codespace range is read by
        the font's kind, and PDFium and poppler look a simple font's codes up in one written
        for two-byte codes, which the composite reading decodes when the string is two-byte.

        What is dropped is a map from outside the dictionary, never the reading with no
        map. Where the search found no map and the dictionary names one, the key is written
        as the search does not read it (a comment before its value, or bytes that end the
        search early), and a reader may not read it either, so the font is read both ways.

        One font is not read with none beside the window's map: a composite font whose
        dictionary names no map. It keeps the window's reading alone, as it was read before
        its dictionary was. The reading with no map decodes nothing, so the text would be
        reported as unmapped, and that report would be new on ordinary documents a tool
        rewrote: pypdf and pdfseparate write a font of reportlab's Adobe CJK set, which has
        a predefined CMap and no map, before a font that has one. When that CMap is a
        Unicode one, the font's own dictionary gives it a UTF-16BE reading instead (backlog
        B8), and the window's reading with no map is dropped; any other such font standing
        alone is reported.
        """
        composite = bool(_TYPE0.search(body) or _IDENTITY.search(body))
        mapping = _TO_UNICODE.search(body)
        read = True
        if mapping is None and start is not None and len(body) >= _LOOKUP_WINDOW:
            # The object lookup returns a 4 KB window; a Type0 font that embeds its descendant
            # font and a long /W widths array puts /ToUnicode past it. Read the whole object.
            mapping, read = self.to_unicode(start)
        wide: _Way = (None if mapping is None else int(mapping.group(1)), composite)
        if wide == (None, False):
            # The usual font with no map, and every object that is not a font: when nothing
            # before its ``endobj`` could spell a map or a composite font, its own dictionary
            # reads the same and is not parsed. A member's body is its own place already.
            end = _ENDOBJ.search(body) if start is not None else None
            stop = len(body) if start is None else -1 if end is None else end.start()
            if stop >= 0 and _FONT_CUES.search(body, 0, stop) is None:
                return [wide], read
        if self._lexed > max(MIN_FONT_DICTIONARY_BYTES, len(self._data) // 2):
            return [wide], False
        self._check()
        own, sure, more = self._own(body, start)
        if own is None:
            return [wide], read and not more
        if wide in own:
            return [wide, *(way for way in own if way != wide)], not more
        if wide[0] is None and own and all(each == _UTF16_MAP for each, _ in own):
            # A Type0 font whose own dictionary names a predefined Unicode CMap and no map:
            # every reading is UTF-16BE (backlog B8). The window only added "no map".
            return own, read and not more
        if wide[0] is not None and own == [(None, True)]:
            # A composite font that names no map, with a map in the bytes after its header:
            # it keeps that one reading. With the reading that has no map beside it, its
            # text would be reported as unmapped, which is new on merged benign documents
            # (backlog B8; a Unicode predefined CMap is read as UTF-16BE above).
            return [wide], read and not more
        both = [wide, *own]
        if sure and (wide[0] is not None or all(each is None for each, _ in own)):
            kept = [(each, True) for each, _ in own if each is not None] if wide[1] else []
            alone = list(dict.fromkeys([*(way for way in kept if way == wide), *own, *kept]))
            # The file is read for its layout only when that decides something.
            if alone == both or self.plain.get() is not None:
                return alone, not more
        return both, read and not more

    def _own(self, body: bytes, start: int | None) -> tuple[list[_Way] | None, bool, bool]:
        """The ways readers take the definition's own dictionary (``_ways``), whether that
        settles how the font is read, and whether there are more ways than were read. The
        ways are None when the definition does not open with a dictionary, its end was not
        reached, or the allowance for lenient reading is spent.

        It is settled when the dictionary is written plainly (``plain_dictionary``), no
        ``#`` escape is in a key or in a /Subtype or /Encoding value, is one readers do not
        all decode alike, or spells a byte outside printable ASCII (``_ODD_ESCAPE``), and
        ``_ways`` finds a simple font this reader decodes as readers do. Anything else that
        is plain is some readers' reading and not every reader's, and a dictionary that is
        not plain is read with the lenient lexer.
        """
        if start is None:
            source, begin, stop = body, 0, len(body)
        else:
            # A dictionary longer than the window is read to its end while the allowance for
            # long font objects lasts, and inside the window after that.
            room = _MAX_OBJECT_BYTES if self._read <= MAX_FONT_OBJECT_BYTES else len(body)
            source, begin, stop = self._data, start, min(len(self._data), start + room)
        entries, end = plain_dictionary(source, begin, stop, self._budget)
        self._spend(end - begin)
        if entries is not None:
            sure = source.find(b"#", begin, end) < 0 or not (
                _ODD_ESCAPE.search(source, begin, end)
                or any(b"#" in key for key, _, _ in entries)
                or any(
                    isinstance(value, bytes) and b"#" in value
                    for key, value, _ in entries
                    if key in (b"/Subtype", b"/Encoding")
                )
            )
            ways, more, settled = _ways(
                (_spellings(key), _spellings(value) if isinstance(value, bytes) else value, exact)
                for key, value, exact in entries
            )
            return ways, sure and settled, more
        if self._loose > MAX_LOOSE_FONT_BYTES:
            return None, False, True
        view = body if start is None else memoryview(self._data)[start:stop]
        tokens, used, short = _loose_dictionary(view, self._budget)
        self._spend(used)
        self._loose += used
        if tokens is None or short:
            # Not a dictionary, or one whose end was not reached: its keys are not known.
            return None, False, False
        # The lenient lexer drops comments, and a comment inside a reference (``9 %c`` and
        # then ``0 R`` on the next line) leaves a number to pypdf and a reference to the
        # others. With a ``%`` anywhere in the dictionary no reference is one every reader
        # takes, so a font that names a map there is read with none as well.
        first = start or 0
        noted = (body if start is None else self._data).find(b"%", first, first + used) >= 0
        ways, more, _ = _ways(
            (_cut(key), _cut(value) if isinstance(value, bytes) else value, exact and not noted)
            for key, value, exact in _loose_entries(tokens)
        )
        return ways, False, more

    def _spend(self, count: int) -> None:
        self._lexed += count
        if count > _PDF_VALUE_WINDOW:
            # A long font object, counted as ``to_unicode`` counts one.
            self._read += count


def _spellings(name: bytes) -> tuple[bytes, ...]:
    """The names readers make of one written with ``#`` escapes.

    Every reader decodes ``#`` and two hex digits. poppler then ends the name at a decoded
    NUL, so ``/ToUnicode#00x`` is its /ToUnicode. pdfminer.six drops a ``#`` that no hex
    digit follows and reads one digit as that digit's byte, so ``/ToUnicode#`` is its
    /ToUnicode.
    """
    if b"#" not in name:
        return (name,)
    decoded = _ESCAPE.sub(_escaped, name)
    return tuple(dict.fromkeys((decoded, *_cut(decoded), _LOOSE_ESCAPE.sub(_escaped, name))))


def _escaped(match: re.Match[bytes]) -> bytes:
    return bytes((int(match.group(1), 16),)) if match.group(1) else b""


def _cut(name: bytes) -> tuple[bytes, ...]:
    """A name the lenient lexer already unescaped, and as poppler cuts it at a NUL."""
    return tuple(dict.fromkeys((name, name.split(b"\x00", 1)[0])))


def _ways(entries: Iterable[_Entry]) -> tuple[list[_Way], bool, bool]:
    """Every way readers take one font dictionary, the likeliest first; whether there are
    more than ``MAX_FONT_WAYS``; and whether the dictionary alone settles how readers show
    the font's text.

    A reader keeps one value of a key that is written more than once: pypdf the first,
    PDFium and pdfminer.six the last, poppler the last in a dictionary of fewer than 32
    entries and, where it sorts a longer one, whichever the sort leaves first. So every
    /ToUnicode value is a map the font may be read through, in the order of ``_likeliest``,
    and a value that is not a reference (``null``) is the font with no map. The font is
    composite when its /Subtype is /Type0 or its /Encoding an Identity CMap, as each
    repeat of those keys has it. A key or value only some readers take for one of these
    names (``_spellings``) counts both ways, and so does a /ToUnicode value that is not
    written as every reader takes a reference (``10 0R``, which PDFium and pypdf read as a
    number, or more digits than the search of the window reads): the font is read through
    that map and with none, as it was read before its dictionary was.

    The dictionary settles the reading of a simple font: each /Subtype it has is a name
    other than /Type0, and it has one. pdf.js looks for a composite font's map in its
    descendant font's dictionary before the font's own, so a composite font's reading is
    not settled here. A simple font with no map is settled only when this reader decodes
    its bytes as readers do: its /Encoding is /WinAnsiEncoding or /MacRomanEncoding, or it
    has neither an /Encoding nor a /FontDescriptor, which is a standard font. A
    /Differences array or a font program's own encoding can show other text.
    """
    maps: list[int | None] = []
    type0: list[bool] = []
    identity: list[bool] = []
    unicode: list[bool] = []
    unsure = False
    named = latin = True
    encoded = described = False
    for keys, value, exact in entries:
        names = value if isinstance(value, tuple) else ()
        if b"/ToUnicode" in keys:
            maps.append(value if isinstance(value, int) else None)
            unsure = unsure or len(keys) > 1 or not exact
        if b"/Subtype" in keys:
            named = named and bool(names)
            type0.extend(dict.fromkeys(name == b"/Type0" for name in names) or [False])
            if len(keys) > 1:
                type0.append(False)
        if b"/Encoding" in keys:
            encoded = True
            latin = latin and bool(names) and all(name in _LATIN_ENCODINGS for name in names)
            identity.extend(dict.fromkeys(name in _IDENTITY_NAMES for name in names) or [False])
            unicode.extend(
                dict.fromkeys(_UNICODE_CMAP.fullmatch(name) is not None for name in names)
                or [False]
            )
            if len(keys) > 1:
                identity.append(False)
                unicode.append(False)
        if b"/FontDescriptor" in keys:
            described = True
    if unsure or not maps:
        # No /ToUnicode key, or one that only some readers take for it.
        maps.append(None)
    # A key can be written any number of times: each list is cut to its distinct values, in
    # the order of ``_likeliest``, before any two are combined.
    kinds = list(dict.fromkeys(_likeliest(type0 or [False])))
    codes = list(dict.fromkeys(_likeliest(identity or [False])))
    composites = list(dict.fromkeys(a or b for a in kinds for b in codes))
    ways = list(
        dict.fromkeys(
            (each, composite)
            for each in dict.fromkeys(_likeliest(maps))
            for composite in composites
        )
    )
    if any(unicode) and True in kinds:
        # A Type0 font with no map and a predefined Unicode CMap is read as UTF-16BE: in place
        # of the reading with no map when every /Encoding value is one, beside it otherwise.
        only = all(unicode)
        ways = list(
            dict.fromkeys(
                way
                for each, composite in ways
                for way in (
                    [(_UTF16_MAP, True)]
                    if each is None and composite and only
                    else [(each, composite), (_UTF16_MAP, True)]
                    if each is None and composite
                    else [(each, composite)]
                )
            )
        )
    simple = bool(type0) and named and composites == [False]
    decoded = None not in maps or (latin if encoded else not described)
    return ways[:MAX_FONT_WAYS], len(ways) > MAX_FONT_WAYS, simple and decoded


def _loose_dictionary(
    source: bytes | memoryview, budget: Budget
) -> tuple[list[bytes] | None, int, bool]:
    """The tokens of the dictionary ``source`` opens with, through the bracket that closes
    it, as the lenient lexer reads them; how many bytes that took; and whether the bytes
    ended first. The tokens are None when ``source`` does not open with a dictionary. A
    dictionary that ``endobj``, ``stream``, or the next header's ``obj`` cuts off ends there.
    A string is listed as ``()``: no key is read from one.
    """
    # The annotation reader imports this module.
    from yara_gate.pdfannotations import _tokens

    tokens: list[bytes] = []
    depth = position = 0
    # The lexer only indexes, slices, and matches its data, so a view of the file serves.
    for token, position in _tokens(source, budget):  # type: ignore[arg-type]
        if token in (b"endobj", b"stream", b"obj") or (not tokens and token != b"<<"):
            return tokens or None, position, False
        tokens.append(token if isinstance(token, bytes) else b"()")
        if token in (b"<<", b"["):
            depth += 1
        elif token in (b">>", b"]"):
            depth -= 1
            if depth <= 0:
                return tokens, position, False
    return tokens or None, position, True


def _loose_entries(tokens: list[bytes]) -> Iterator[tuple[bytes, bytes | int | None, bool]]:
    """Each key of the dictionary ``tokens`` opens with; the name its value is, the object
    number its value refers to, or None; and whether the value is written as every reader
    takes it. A token that is not a name where a key belongs is skipped, as the lenient
    readers skip it.

    A reference with more digits than the search of the window reads (``_TO_UNICODE``) is
    not, and its number is bounded before it is converted: a run of digits can be any
    length, and Python refuses to convert one of more than 4,300.
    """
    index = 1
    while index + 1 < len(tokens) and tokens[index] != b">>":
        key, value = tokens[index], tokens[index + 1]
        if not key.startswith(b"/"):
            index += 1
            continue
        if _pdf_reference(tokens[index + 1 : index + 4]):
            target = _pdf_header_key(value, tokens[index + 2])
            exact = len(value) <= 10 and len(tokens[index + 2]) <= 5
            yield key, None if target is None else target[0], exact
        else:
            yield key, value if value.startswith(b"/") else None, True
        index = _pdf_value_end(tokens, index + 1)


def _looks_like_a_font(body: bytes) -> bool:
    return b"/Font" in body or b"/Subtype" in body


def _likeliest[T](definitions: Sequence[T]) -> list[T]:
    """Definitions in file order, reordered by how likely a reader is to use each.

    The last comes first: an ordinary incremental update leaves it in use, and a reader that
    rebuilds a table keeps the later of two headers. The first is next: a table can still name
    it, and pdf.js keeps the first header's generation when a later one differs. The ones
    between follow, latest first. The order only matters past ``MAX_FONT_VARIANTS`` readings,
    where the rest are reported instead of decoded.
    """
    if len(definitions) < 3:
        return list(reversed(definitions))
    return [definitions[-1], definitions[0], *reversed(definitions[1:-1])]


class _Readings(list[Font]):
    """One font's readings (``_font``), with the readings of its further ways kept apart."""

    def __init__(self, readings: Iterable[Font], further: Iterable[Font] = ()) -> None:
        super().__init__(readings)
        self.further = list(further)


def _font(number: int, definitions: _Definitions, cmaps: _Cmaps) -> _Readings:
    """The font's readings: one for each definition of the object and of its ToUnicode map,
    then the second reading of each map that has an overflowing range. The readings of the
    definition under each generation a reference names, through the last definition of its
    map, come before the rest, so the cap on readings never drops them.

    Text is decoded through each, because a reader uses one definition and this reader does not
    know which (see ``_Definitions``). Equal readings count once. A font with more readings
    than a string is decoded with, or more definitions than are read, also gets an unresolved
    reading, so text shown in it is reported as unmapped instead of passing unread.

    A definition can itself be read more than one way (``_Definitions.ways``): a /ToUnicode
    key written twice, or a map the window after the header holds and the font's own
    dictionary does not. The readings above are those of each definition's first way. The
    readings of the other ways are returned apart (``further``), for the caller to put after
    every reading of every font a name means, so a further way never takes the place of a
    reading a first way gives. Each further way's reading through the last definition of
    its map comes first, then its others. One that decodes every string as an earlier
    reading does (``_same_text``) is not a reading of its own. A way that definitions share
    is read once, and a font with more than ``MAX_FONT_WAYS`` further ways, or more than
    ``MAX_FURTHER_READINGS`` readings of them, also gets the unresolved reading: no string
    is decoded through that many, and a font can be defined 64 times with keys of its own
    in each. The unresolved reading decodes nothing, so it stands after the further
    readings where there are any and takes no place among those decoded.
    """
    bodies, complete, exact = definitions(number, _looks_like_a_font)
    kept: list[Font] = []
    kept_carried: list[Font] = []
    first: list[Font] = []
    second: list[Font] = []
    seen: set[_Way] = set()
    lead: list[Font] = []
    rest: list[Font] = []
    for index, (body, start) in enumerate(bodies):
        cmaps.check()
        ways, read = definitions.ways(body, start)
        complete = complete and read
        for way in ways[1:]:
            if way in seen:
                continue
            if len(seen) >= MAX_FONT_WAYS:
                complete = False
                break
            seen.add(way)
            mapped, carried, likeliest = cmaps.fonts(*way)
            lead.extend(likeliest[:1])
            rest.extend((*mapped, *likeliest[1:], *carried))
        mapped, carried, likeliest = cmaps.fonts(*ways[0])
        if index < exact:
            # A definition under a generation a reference names, read through the last
            # definition of its map: the reading a lookup that takes one of each gives. Its
            # carried reading follows every such first reading.
            kept.extend(each for each in likeliest[:1] if each not in kept)
            kept_carried.extend(each for each in likeliest[1:] if each not in kept_carried)
        first.extend(each for each in mapped if each not in first)
        second.extend(each for each in carried if each not in second)
        if len(first) > MAX_FONT_VARIANTS and index + 1 >= exact:
            break
    found = kept + [each for each in kept_carried if each not in kept]
    found += [each for each in first if each not in found]
    found += [each for each in second if each not in found]
    further: list[Font] = []
    held: set[int] = set()
    for each in (*lead, *rest):
        if id(each) in held:
            continue
        if len(held) >= MAX_FURTHER_READINGS:
            complete = False
            break
        held.add(id(each))
        if not any(_same_text(each, have) for have in (*found, *further)):
            further.append(each)
    if len(found) > MAX_FONT_VARIANTS or not complete:
        found = found[:MAX_FONT_VARIANTS]
        unresolved = Font(True, None, (2,))
        if unresolved not in found and unresolved not in further:
            (further if further else found).append(unresolved)
    return _Readings(found, further)


# A simple font with no map, read as WinAnsi bytes.
_WINANSI = Font(False)
# A Type0 font with no map and a predefined Unicode CMap, read as UTF-16BE.
_UTF16 = Font(True, None, (2,), utf16=True)


def _same_text(one: Font, other: Font) -> bool:
    """True when two readings are known to decode every string alike: both have no map and
    are the same kind of font, or they share one map, the very object, and its code
    lengths, where being composite changes nothing.

    Two maps are never compared entry by entry here. A file can name thousands of fonts and
    a font several further ways in a few bytes each, so a walk of two maps for each pair
    would be most of a scan; two maps that happen to be equal are two readings.
    """
    if (
        one.cmap is not other.cmap
        or one.lengths != other.lengths
        or one.missing != other.missing
        or one.utf16 != other.utf16
    ):
        return False
    return bool(one.cmap) or one.composite == other.composite


_ParsedCmap = tuple[dict[bytes, str], tuple[int, ...], dict[bytes, str]]


class _Cmaps:
    """A file's ToUnicode maps by object number, each parsed once however many fonts share it.

    A stream number defined more than once has one map per definition, in the order of
    ``_likeliest``; a reader uses one of them (see ``_Definitions``). Every token lexed counts
    toward ``MAX_CMAP_TOKENS`` and every entry written into any map, overwrites included,
    toward ``MAX_CMAP_TOTAL``. Keys and decoded string storage are charged before allocation.
    Exhaustion leaves the scan incomplete.
    """

    def __init__(self, streams: dict[int, list[bytes | None]], budget: Budget) -> None:
        self._streams = streams
        self._budget = budget
        self.check = budget.check
        self._parsed: dict[int, list[_ParsedCmap | None]] = {}
        self._fonts: dict[tuple[int | None, bool], tuple[list[Font], list[Font], list[Font]]] = {}
        self.written = 0
        self.lexed = 0
        self.expanded = 0

    def get(self, number: int) -> list[_ParsedCmap | None]:
        """One entry per definition of the stream: its map, or None when it holds no text.
        A stream the file does not define is one None."""
        if number not in self._parsed:
            parsed: list[_ParsedCmap | None] = []
            self._parsed[number] = parsed
            for data in _likeliest(self._streams.get(number) or [None]):
                if not data:
                    if None not in parsed:
                        parsed.append(None)
                    continue
                mapping, lengths, carried = _cmap(data, self._budget, self)
                if carried:
                    self.spend(len(mapping))
                    carried = {**mapping, **carried}
                parsed.append((mapping, lengths, carried))
        return self._parsed[number]

    def fonts(
        self, number: int | None, composite: bool
    ) -> tuple[list[Font], list[Font], list[Font]]:
        """What a font dictionary with this ToUnicode reference can be: a font per definition
        of the map, the carried reading of each map with an overflowing range, and the one or
        two readings through the map's last definition alone.

        The answer is kept, so every font dictionary that shares a map gets the same objects
        and comparing them is cheap. Collection stops once a string could not be decoded
        through them all; the caller reports that.
        """
        key = (number, composite)
        if key not in self._fonts:
            default = (2,) if composite else (1,)
            first: list[Font] = []
            second: list[Font] = []
            likeliest: list[Font] = []
            utf16 = number == _UTF16_MAP
            listed = [None] if number is None or utf16 else self.get(number)
            for index, parsed in enumerate(listed):
                self.check()
                readings: list[Font] = []
                if parsed is None:
                    readings.append(Font(composite, None, default, utf16=utf16))
                else:
                    cmap, lengths, alternate = parsed
                    readings.append(Font(composite, cmap or None, lengths or default))
                    if alternate:
                        readings.append(Font(composite, alternate, lengths or default))
                if index == 0:
                    likeliest = readings
                if readings[0] not in first:
                    first.append(readings[0])
                second.extend(each for each in readings[1:] if each not in second)
                if len(first) > MAX_FONT_VARIANTS:
                    break
            self._fonts[key] = first, second, likeliest
        return self._fonts[key]

    def spend(self, entries: int, expanded: int = 0) -> None:
        self._budget.check()
        self.expanded += expanded
        if self.expanded > MAX_CMAP_BYTES:
            raise ContentLimit(f"pdf cmap expanded bytes exceed {MAX_CMAP_BYTES}")
        self.written += entries
        if self.written > MAX_CMAP_TOTAL:
            raise ContentLimit(f"pdf cmap entries exceed {MAX_CMAP_TOTAL}")

    def lex(self, body: bytes) -> None:
        # Every _CMAP_TOKEN match starts with one of these bytes, so this bounds the matches.
        self.lexed += body.count(b"<") + body.count(b"[") + body.count(b"]")
        if self.lexed > MAX_CMAP_TOKENS:
            raise ContentLimit(f"pdf cmap tokens exceed {MAX_CMAP_TOKENS}")


_LOOKUP_WINDOW = 4000
_MAX_OBJECT_BYTES = 1 << 20


def _prime(objects: Lookup, keys: set[tuple[int, int]]) -> None:
    prime = getattr(objects, "prime", None)
    if keys and callable(prime):
        prime(keys)


def _cmap(
    data: bytes, budget: Budget, work: _Cmaps
) -> tuple[dict[bytes, str], tuple[int, ...], dict[bytes, str]]:
    """bfchar and bfrange entries of a ToUnicode CMap, its code lengths in bytes, and the
    codes an overflowing bfrange gives a second reading (see ``_cmap_ranges``)."""
    mapping: dict[bytes, str] = {}
    carried: dict[bytes, str] = {}
    lengths: set[int] = set()
    for kind, body in _cmap_sections(data, budget):
        work.lex(body)
        items = [
            _hex_bytes(token.group(1)) if token.group(1) is not None else token.group()
            for token in _CMAP_TOKEN.finditer(body)
        ]
        if kind == b"codespacerange":
            if any(len(item) > _MAX_CMAP_CODE_BYTES for item in items):
                raise ContentLimit("pdf cmap source code exceeds four bytes")
            lengths.update(len(item) for item in items[0::2] if item)
        elif kind == b"bfchar":
            work.spend(len(items) // 2)
            for source, target in zip(items[0::2], items[1::2], strict=False):
                if len(mapping) >= MAX_CMAP_ENTRIES:
                    break
                if len(source) > _MAX_CMAP_CODE_BYTES:
                    raise ContentLimit("pdf cmap source code exceeds four bytes")
                if source and target not in (b"[", b"]"):
                    work.spend(0, len(source) + 2 * len(target))
                    mapping[source] = _utf16(target)
                    if carried:
                        # A later entry replaces the code in every reader.
                        carried.pop(source, None)
        else:
            _cmap_ranges(items, mapping, carried, work)
    return mapping, tuple(sorted(lengths, reverse=True)), carried


def _cmap_sections(data: bytes, budget: Budget) -> Iterator[tuple[bytes, bytes]]:
    """Each ``begin<kind> ... end<kind>`` section's kind and body, in order, in linear time.

    A ``begin`` with no later ``end`` of its kind is skipped, and the search goes on after it,
    as a lazy ``begin(kind)(.*?)end(kind)`` regex would. That regex rescans to the end of the
    data from every unclosed ``begin``, quadratic in their number and with no deadline check
    inside one search. Here a kind with no ``end`` left is never searched for again.
    """
    unclosed: set[bytes] = set()
    position = 0
    while len(unclosed) < 3 and (begin := _CMAP_BEGIN.search(data, position)) is not None:
        budget.check()
        kind = begin.group(1)
        position = begin.end()
        if kind in unclosed:
            continue
        end = data.find(b"end" + kind, position)
        if end < 0:
            unclosed.add(kind)
            continue
        yield kind, data[position:end]
        position = end + len(b"end") + len(kind)


def _cmap_ranges(
    items: list[bytes], mapping: dict[bytes, str], carried: dict[bytes, str], work: _Cmaps
) -> None:
    """Add bfrange entries to ``mapping``.

    ``<lo> <hi> <dst>`` maps each code to ``dst`` plus its offset in the range, carrying into
    the higher byte. ISO 32000-1 9.10.3 increments only the last byte, but for a one-unit
    destination PDFium, PDFBox, pdfminer.six, pdf.js, and MuPDF all carry. When the sum no
    longer fits in ``dst``'s width (``<0000> <00FF> <FFFF>``), they split: PDFium, PDFBox,
    and pdfminer.six wrap it to that width, while pdf.js and MuPDF keep the untruncated last
    UTF-16 unit, a code point from U+10000. ``mapping`` gets the wrapped reading and
    ``carried`` the other one for those codes only, so the text is read both ways
    (docs/verification/2026-11-07-cmap-range-overflow.md).
    """
    index = 0
    while index + 2 < len(items) and len(mapping) < MAX_CMAP_ENTRIES:
        low, high, target = items[index], items[index + 1], items[index + 2]
        index += 3
        if not low or len(low) != len(high) or low in (b"[", b"]") or high in (b"[", b"]"):
            continue
        if len(low) > _MAX_CMAP_CODE_BYTES:
            raise ContentLimit("pdf cmap source code exceeds four bytes")
        first, last = int.from_bytes(low, "big"), int.from_bytes(high, "big")
        if last < first or last - first > 0xFFFF:
            continue
        if target == b"[":
            # <lo> <hi> [<dst> <dst> ...]: one target per code.
            targets: list[bytes] = []
            while index < len(items) and items[index] != b"]":
                targets.append(items[index])
                index += 1
            index += 1
            targets = targets[: last - first + 1]
            work.spend(len(targets), sum(len(low) + 2 * len(each) for each in targets))
            for offset, each in enumerate(targets):
                code = (first + offset).to_bytes(len(low), "big")
                mapping[code] = _utf16(each)
                carried.pop(code, None)
            continue
        if target == b"]":
            continue
        width = max(len(target), 2)
        count = last - first + 1
        work.spend(count, count * (len(low) + 2 * width))
        base = int.from_bytes(target, "big")
        limit = (1 << (8 * width)) - 1
        # The destination as whole UTF-16 units: the units before the last, and the last.
        units = base.to_bytes(width + width % 2, "big")
        prefix, unit = _utf16(units[:-2]), int.from_bytes(units[-2:], "big")
        overflow = max(0, base + count - 1 - limit)
        if overflow:
            work.spend(overflow, overflow * (len(low) + 2 * width + 4))
        for offset in range(last - first + 1):
            if len(mapping) >= MAX_CMAP_ENTRIES:
                return
            code = (first + offset).to_bytes(len(low), "big")
            value = base + offset
            mapping[code] = _utf16((value & limit).to_bytes(width, "big"))
            if value > limit:
                # Only a destination already at its width's maximum prefix overflows, so
                # unit + offset is from 0x10000 to 0x1FFFE: never a surrogate.
                carried[code] = prefix + chr(unit + offset)
            elif carried:
                carried.pop(code, None)


Matrix = tuple[float, float, float, float, float, float]
_IDENTITY_MATRIX: Matrix = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)
# Baselines closer than this share a line; up to _LINE_STEP font sizes apart is the next line of
# the same paragraph; farther, or a jump back up the page, starts a new paragraph.
_SAME_LINE = 0.3
_LINE_STEP = 1.7


def _multiply(left: Matrix, right: Matrix) -> Matrix:
    a, b, c, d, e, f = left
    g, h, i, j, k, m = right
    return (
        a * g + b * i,
        a * h + b * j,
        c * g + d * i,
        c * h + d * j,
        e * g + f * i + k,
        e * h + f * j + m,
    )


class _Paragraphs:
    """Text shown in one content stream, grouped into paragraphs by baseline position.

    With ``hidden``, the text goes to ``result.hidden_blocks`` and ``hidden_paragraphs``; it is
    placed with ``add`` from the readings the visible grouping already decoded.
    """

    def __init__(self, result: PdfText, budget: Budget, *, hidden: bool = False) -> None:
        self.result = result
        self.budget = budget
        self.hidden = hidden
        self.blocks = result.hidden_blocks if hidden else result.blocks
        self.paragraphs = result.hidden_paragraphs if hidden else result.paragraphs
        self.variants: list[list[str]] = []
        self.baseline: float | None = None
        self.size = 0.0
        # Where the current block starts in each variant, and how many block pieces with text
        # this paragraph holds.
        self.block_start = 0
        self.pieces = 0
        # Whether the last font list shown had an unreadable font: a name's list is fixed, and
        # consecutive strings nearly always share it, so a name of 64 fonts is checked once.
        self.checked: list[Font] | None = None
        self.unreadable = False
        self.missing = False
        self.limit = MAX_FONT_VARIANTS
        self.winansi = False
        self.utf16 = False

    def show(
        self, fonts: list[Font], strings: Iterable[object], baseline: float, size: float
    ) -> tuple[list[str], bool] | None:
        """Add one text-showing operator's strings.

        Return the operator's text in each font reading, and whether any of it is more than
        whitespace once decoded (text a font cannot decode counts as more), or None when the
        strings cannot be read at all.
        """
        strings = list(strings)
        variants = fonts or [Font(False)]
        if variants is not self.checked:
            self.checked = variants
            self.unreadable = any(font.unreadable for font in variants)
            self.missing = not fonts or any(font.missing for font in variants)
            # The no-font reading is one WinAnsi pass and does not take a font's place.
            self.limit = MAX_FONT_VARIANTS + (self.missing and bool(fonts))
            self.winansi = _WINANSI in variants[self.limit :]
            self.utf16 = _UTF16 in variants[self.limit :]
        limit = self.limit
        if self.unreadable:
            self.result.unmapped = True
        if self.missing and _two_byte(strings):
            # A font the file never resolves, whose codes are two bytes wide: decoding them as
            # WinAnsi would yield noise, so the text counts as unread in that reading.
            self.result.unmapped = True
            variants = [font for font in variants if not font.missing]
            limit = MAX_FONT_VARIANTS
            if not variants:
                return None
        shown = variants[:limit]
        if self.winansi and _WINANSI not in shown:
            # Nor does the reading of a font with no map: every such font a name means
            # shares it, and it is what a font read through its own dictionary adds beside
            # a map the bytes after it lent it, so it is decoded wherever it stands.
            shown.append(_WINANSI)
        if self.utf16 and _UTF16 not in shown:
            # The same holds for the UTF-16BE reading of a predefined Unicode CMap: every
            # such font gives this one reading, so it is one more pass at most (backlog B8).
            shown.append(_UTF16)
        if (
            len(variants) > len(shown)
            and not self.result.unmapped
            and any(isinstance(item, bytes) and item for item in strings)
        ):
            # The readings past the cap are not decoded, so text only they show goes unread.
            self.result.unmapped = True
        readings: list[str] = []
        printed = False
        check = self.budget.check
        used = self.result.decoded_chars
        for font in shown:
            parts: list[str] = []
            for item in strings:
                if isinstance(item, bytes):
                    # A subset font numbers its glyphs from the bytes up, so b" " can be a letter.
                    decoded = _decode(item, font, MAX_PDF_DECODED_CHARS - used, check)
                    used += len(decoded)
                    printed = printed or bool(decoded.strip()) or (font.unreadable and bool(item))
                    parts.append(decoded)
                elif isinstance(item, float) and item <= _SPACE_ADJUST:
                    parts.append(" ")
            readings.append("".join(parts))
        self.result.decoded_chars = used
        self.add(readings, baseline, size)
        return readings, printed

    def add(self, readings: list[str], baseline: float, size: float) -> None:
        """Place one operator's already decoded text, one string per font reading."""
        separator = ""
        if self.baseline is not None:
            step = abs(baseline - self.baseline)
            unit = max(self.size, size, 1e-6)
            if step > _LINE_STEP * unit:
                self.flush()
            elif step > _SAME_LINE * unit:
                separator = "\n"
        self.baseline, self.size = baseline, size
        if not self.variants:
            self.variants = [[]]
        if self.block_start > len(self.variants[0]):
            self.block_start = len(self.variants[0])
        while len(self.variants) < len(readings):
            # A name that means different fonts on different pages: one reading per font.
            self.variants.append(list(self.variants[0]))
        for index, variant in enumerate(self.variants):
            if separator and variant:
                variant.append(separator)
            variant.append(readings[index % len(readings)])

    def end_block(self) -> None:
        """Close the current text object's piece of this paragraph and emit it as a block."""
        found = False
        for variant in self.variants:
            text = "".join(variant[self.block_start :]).strip()
            if text:
                found = True
                self._emit(self.blocks, text)
        if found:
            self.pieces += 1
        self.block_start = len(self.variants[0]) if self.variants else 0

    def flush(self) -> None:
        self.end_block()
        if self.pieces > 1:
            for variant in self.variants:
                text = "".join(variant).strip()
                if text:
                    self._emit(self.paragraphs, text)
        self.variants = []
        self.baseline = None
        self.block_start = 0
        self.pieces = 0

    def _emit(self, target: list[str], text: str) -> None:
        if len(self.blocks) + len(self.paragraphs) >= MAX_TEXT_BLOCKS:
            raise ContentLimit("pdf text blocks exceed 20000")
        # Longer text is scanned in overlapping chunks, so nothing past the cap goes unread.
        step = MAX_BLOCK_CHARS - _CHUNK_OVERLAP
        for start in range(0, max(len(text) - _CHUNK_OVERLAP, 1), step):
            if len(self.blocks) + len(self.paragraphs) >= MAX_TEXT_BLOCKS:
                raise ContentLimit("pdf text blocks exceed 20000")
            target.append(text[start : start + MAX_BLOCK_CHARS])


@dataclass
class _TextState:
    """The selected font and size, render mode, and fill colour, which outlive one stream."""

    fonts: list[Font] = field(default_factory=list)
    # The resource name ``fonts`` was selected by, so the next stream can look it up again.
    name: bytes | None = None
    size: float = 0.0
    selected: bool = False
    render: int = 0
    white: bool = False
    white_stroke: bool = False


# Render modes that paint nothing: 3 is invisible, 7 only adds the glyphs to the clipping path.
_INVISIBLE_MODES = frozenset({3, 7})
# Text whose glyphs are smaller than this in default user space (1/72 inch) is not legible.
_LEGIBLE_SIZE = 1.0
_WHITE_LEVEL = 0.95
_FILL_OPERATORS = frozenset({b"g", b"rg", b"k", b"sc", b"scn", b"cs"})
_STROKE_OPERATORS = frozenset(op.upper() for op in _FILL_OPERATORS)


def _white_color(op: bytes, operands: list[object]) -> bool:
    """True when a colour operator selects a near-white colour.

    Gray (``g``) and RGB (``rg``) at 0.95 or more per component, and CMYK (``k``) at 0.05 or
    less, are white. ``sc`` and ``scn`` are read by their component count, three as RGB and
    four as CMYK; one component is a gray, a separation tint, or an index, so it is not judged.
    ``cs`` resets the fill to its colour space's initial colour, which is never white.
    """
    if op == b"cs":
        return False
    values = [value for value in operands if isinstance(value, float)]
    if op in (b"sc", b"scn"):
        if len(values) == 3:
            op = b"rg"
        elif len(values) == 4:
            op = b"k"
        else:
            return False
    expected = {b"g": 1, b"rg": 3, b"k": 4}[op]
    if len(values) < expected:
        return False
    values = values[-expected:]
    if op == b"k":
        return all(value <= 1.0 - _WHITE_LEVEL for value in values)
    return all(value >= _WHITE_LEVEL for value in values)


_FILL_PAINT = frozenset({b"f", b"F", b"f*", b"B", b"B*", b"b", b"b*"})
_PATH_END = _FILL_PAINT | {b"S", b"s", b"n"}
# Painted areas kept per content stream. Later areas are ignored, so the check stays bounded
# and white text over them counts as hidden: a few dots cannot widen a box over the page.
MAX_PAINTED_AREAS = 32
_EVERYWHERE: Box = (-1e300, -1e300, 1e300, 1e300)


class _Painted:
    """Device-space boxes a content stream painted in a colour other than near-white.

    White text over one of them (a dark table header, a slide background, a photo) is shown.
    A box is the bounding box of the filled path, image, or shading, so it may be larger than
    what was painted, which can only make text count as shown. The last answer is kept until
    the point or the boxes change: string advances are not tracked, so the strings of one line
    share a point.
    """

    def __init__(self) -> None:
        self.boxes: list[Box] = []
        self.union: Box | None = None
        self.asked: tuple[float, float] | None = None
        self.answer = False

    def add(self, box: Box) -> None:
        if len(self.boxes) >= MAX_PAINTED_AREAS:
            return
        self.boxes.append(box)
        self.union = box if self.union is None else _merge(self.union, box)
        self.asked = None

    def covers(self, x: float, y: float) -> bool:
        if self.union is None or not _inside(self.union, x, y):
            return False
        if self.asked != (x, y):
            self.asked = (x, y)
            self.answer = any(_inside(box, x, y) for box in self.boxes)
        return self.answer


def _merge(left: Box, right: Box) -> Box:
    return (
        min(left[0], right[0]),
        min(left[1], right[1]),
        max(left[2], right[2]),
        max(left[3], right[3]),
    )


def _inside(box: Box, x: float, y: float) -> bool:
    return box[0] <= x <= box[2] and box[1] <= y <= box[3]


def _intersect(left: Box, right: Box) -> Box:
    return (
        max(left[0], right[0]),
        max(left[1], right[1]),
        min(left[2], right[2]),
        min(left[3], right[3]),
    )


def _off_page(device: Matrix, size: float, strings: list[object], box: Box) -> bool:
    """True when text starting at ``device``'s origin lies wholly outside ``box``.

    The run's width is not known without font metrics; one em per byte is taken as an upper
    bound, so text that may reach the page is never called off-page.
    """
    x, y = device[4], device[5]
    width = size * sum(len(item) for item in strings if isinstance(item, bytes))
    low_x, low_y, high_x, high_y = box
    return (
        x > high_x + size or y > high_y + size or y < low_y - 2 * size or x + width < low_x - size
    )


def _blocks(
    body: bytes,
    fonts: Mapping[bytes, list[Font]],
    result: PdfText,
    budget: Budget,
    tokens: int,
    state: _TextState,
    box: Box | None = None,
    page: bool = False,
) -> int:
    """Append the paragraphs of one content stream to ``result``; return the token count.

    The CTM (cm, q, Q) and the text matrix (Tm, Td, TD, T*, TL, ', ") are followed so each
    string's baseline is known in device space; text objects (BT ... ET) do not split text,
    because generators start a new one at every font change or line. The render mode (Tr) and
    fill colour are followed too, and a string drawn so that it is not seen also goes to the
    hidden grouping: render mode 3 or 7, or near-white text over nothing this stream painted
    in another colour. In ``page`` content, text under 1 pt or outside ``box`` is not seen
    either. A hidden stretch ends at the next string that is seen.
    """
    operands: list[object] = []
    current: list[Font] = state.fonts
    name = state.name
    size = state.size
    sized = state.selected
    render = state.render
    white = state.white
    white_stroke = state.white_stroke
    leading = 0.0
    ctm = _IDENTITY_MATRIX
    painted = _Painted()
    path: Box | None = None
    clip: Box | None = None
    clipping = False
    # q saves, and Q restores, the whole graphics state: the CTM, the clip, and the text state.
    saved: list[
        tuple[Matrix, list[Font], bytes | None, float, float, int, bool, bool, Box | None]
    ] = []
    line = _IDENTITY_MATRIX
    paragraphs = _Paragraphs(result, budget)
    hidden = _Paragraphs(result, budget, hidden=True)

    def extend(points: list[float]) -> None:
        nonlocal path
        a, b, c, d, e, f = ctm
        for index in range(0, len(points) - 1, 2):
            px, py = points[index], points[index + 1]
            x, y = a * px + c * py + e, b * px + d * py + f
            path = (x, y, x, y) if path is None else _merge(path, (x, y, x, y))

    def numbers(count: int) -> list[float] | None:
        values = operands[-count:]
        if len(values) != count or not all(isinstance(value, float) for value in values):
            return None
        return [float(value) for value in values]  # type: ignore[arg-type]

    def move(tx: float, ty: float) -> None:
        nonlocal line
        line = _multiply((1.0, 0.0, 0.0, 1.0, tx, ty), line)

    def show(strings: list[object]) -> None:
        device = _multiply(line, ctm)
        scale = max(abs(device[1]), abs(device[3]), 1e-6)
        shown = abs(size) * scale
        decoded = paragraphs.show(current, strings, device[5], shown)
        if decoded is None:
            # Unread text is reported by the coverage note; it still ends a hidden stretch.
            hidden.flush()
            return
        readings, printed = decoded
        unseen = render in _INVISIBLE_MODES
        white_text = (
            (render in (0, 4) and white)
            or (render in (1, 5) and white_stroke)
            or (render in (2, 6) and white and white_stroke)
        )
        height = abs(size) * math.hypot(device[2], device[3])
        if white_text:
            # A point inside the first glyph, above the baseline.
            quarter = 0.25 * height
            unseen = not painted.covers(device[4] + quarter, device[5] + quarter)
        if page and sized and not unseen:
            unseen = height < _LEGIBLE_SIZE or (
                box is not None and _off_page(device, height, strings, box)
            )
        if unseen or not printed:
            # A shown space between two hidden strings is part of the hidden text; a stretch
            # of only spaces is dropped when the block ends.
            hidden.add(readings, device[5], shown)
        else:
            hidden.flush()

    def tick() -> None:
        # Every token counts, elements of a TJ array included, so one huge array cannot
        # outrun the deadline or the token cap before it is yielded.
        nonlocal tokens
        tokens += 1
        if tokens % 4096 == 0:
            budget.check()
        if tokens > MAX_TOKENS:
            raise ContentLimit("pdf content exceeds token limit")

    for token in _tokens(body, tick):
        if not isinstance(token, _Operator):
            operands.append(token)
            continue
        op = token.value
        if op == b"BT":
            paragraphs.end_block()
            hidden.end_block()
            line = _IDENTITY_MATRIX
        elif op == b"ET":
            paragraphs.end_block()
            hidden.end_block()
        elif op == b"q":
            if len(saved) < 64:
                saved.append((ctm, current, name, size, leading, render, white, white_stroke, clip))
        elif op == b"Q":
            if saved:
                ctm, current, name, size, leading, render, white, white_stroke, clip = saved.pop()
                state.fonts, state.size, state.render, state.white = current, size, render, white
                state.name, state.white_stroke = name, white_stroke
        elif op in (b"m", b"l") and (values := numbers(2)) is not None:
            extend(values)
        elif op == b"c" and (values := numbers(6)) is not None:
            extend(values)
        elif op in (b"v", b"y") and (values := numbers(4)) is not None:
            extend(values)
        elif op == b"re" and (values := numbers(4)) is not None:
            x, y, width, height = values
            extend([x, y, x + width, y, x, y + height, x + width, y + height])
        elif op in (b"W", b"W*"):
            clipping = True
        elif op in _PATH_END:
            if path is not None and op in _FILL_PAINT and not white:
                painted.add(path)
            if clipping and path is not None:
                clip = path if clip is None else _intersect(clip, path)
            path, clipping = None, False
        elif op == b"Do":
            # An image fills the unit square under the CTM; a form XObject's own fills are in
            # its stream, so its square here is only a lower bound.
            extend([0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 1.0, 1.0])
            if path is not None:
                painted.add(path)
            path = None
        elif op == b"sh":
            painted.add(clip or box or _EVERYWHERE)
        elif op == b"cm" and (values := numbers(6)) is not None:
            ctm = _multiply((values[0], values[1], values[2], values[3], values[4], values[5]), ctm)
        elif op == b"Tf" and len(operands) >= 2 and isinstance(operands[-2], _Name):
            name = operands[-2].value
            current = fonts.get(name, [])
            size = operands[-1] if isinstance(operands[-1], float) else size
            sized = True
            state.fonts, state.name, state.size, state.selected = current, name, size, True
        elif op == b"Tr" and (values := numbers(1)) is not None:
            render = int(values[0]) if values[0].is_integer() else 0
            state.render = render
        elif op in _FILL_OPERATORS:
            white = _white_color(op, operands)
            state.white = white
        elif op in _STROKE_OPERATORS:
            white_stroke = _white_color(op.lower(), operands)
            state.white_stroke = white_stroke
        elif op == b"TL" and (values := numbers(1)) is not None:
            leading = values[0]
        elif op == b"Tm" and (values := numbers(6)) is not None:
            line = (values[0], values[1], values[2], values[3], values[4], values[5])
        elif op in (b"Td", b"TD") and (values := numbers(2)) is not None:
            if op == b"TD":
                leading = -values[1]
            move(values[0], values[1])
        elif op == b"T*":
            move(0.0, -leading)
        elif op == b"Tj" and operands and isinstance(operands[-1], bytes):
            show([operands[-1]])
        elif op in (b"'", b'"') and operands and isinstance(operands[-1], bytes):
            move(0.0, -leading)
            show([operands[-1]])
        elif op == b"TJ" and operands and isinstance(operands[-1], list):
            show(operands[-1])
        operands = []
    paragraphs.flush()
    hidden.flush()
    return tokens


@dataclass(frozen=True)
class _Operator:
    value: bytes


@dataclass(frozen=True)
class _Name:
    value: bytes


# One token per match, after any whitespace: a comment, a literal string's opening parenthesis,
# a dictionary bracket, a hex string, an array bracket, a name, or a bare word (number or
# operator). Anything else is a stray delimiter and is skipped.
_TOKEN = re.compile(
    rb"[\x00\t\n\f\r ]*(?:"
    rb"(%[^\r\n]*)"
    rb"|(\()"
    rb"|(<<|>>)"
    rb"|<([^>]*)>"
    rb"|(\[)"
    rb"|(\])"
    rb"|/([^\x00\t\n\f\r ()<>\[\]{}/%]*)"
    rb"|([^\x00\t\n\f\r ()<>\[\]{}/%]+)"
    rb"|(.))",
    re.DOTALL,
)


def _tokens(data: bytes, tick: Callable[[], None] = lambda: None) -> Iterable[object]:
    """Content-stream tokens: bytes for a string, float, _Name, list for an array, _Operator."""
    position = 0
    size = len(data)
    stack: list[list[object]] = []
    match_at = _TOKEN.match
    while position < size:
        match = match_at(data, position)
        if match is None or match.end() == position:
            break
        position = match.end()
        tick()
        group = match.lastindex
        item: object
        if group == 1 or group == 9 or group is None:
            continue
        if group == 2:
            item, position = _literal(data, position - 1)
        elif group == 3:
            item = _Operator(match.group(3))
        elif group == 4:
            item = _hex_bytes(match.group(4))
        elif group == 5:
            stack.append([])
            continue
        elif group == 6:
            if not stack:
                continue
            item = stack.pop()
        elif group == 7:
            item = _Name(_name(match.group(7)))
        else:
            word = match.group(8)
            if _NUMBER.match(word):
                item = float(word)
            elif stack:
                # An operator inside an array is malformed; keep the array, drop the word.
                continue
            elif word == b"ID":
                # Inline image data is binary up to EI; skip it without tokenizing.
                found = _INLINE_IMAGE_END.search(data, position)
                position = found.end() if found else size
                continue
            else:
                item = _Operator(word)
        if stack:
            stack[-1].append(item)
            if len(stack[-1]) > MAX_ARRAY_ITEMS:
                raise ContentLimit("pdf array exceeds 100000 items")
        else:
            yield item
    while stack:
        array = stack.pop()
        if stack:
            stack[-1].append(array)
        else:
            yield array


def _literal(data: bytes, position: int) -> tuple[bytes, int]:
    """A literal string starting at ``(``: balanced parentheses, escapes decoded."""
    output = bytearray()
    depth = 1
    index = position + 1
    size = len(data)
    while index < size:
        char = data[index]
        if char == 0x5C and index + 1 < size:  # backslash
            following = data[index + 1]
            if following in _LITERAL_ESCAPES:
                output += _LITERAL_ESCAPES[following]
                index += 2
            elif 0x30 <= following <= 0x37:
                digits = data[index + 1 : index + 4]
                count = 0
                while count < len(digits) and 0x30 <= digits[count] <= 0x37:
                    count += 1
                output.append(int(digits[:count], 8) & 0xFF)
                index += 1 + count
            elif following in (0x0D, 0x0A):
                # A backslash at a line end continues the string.
                index += 2
                if following == 0x0D and data[index : index + 1] == b"\n":
                    index += 1
            else:
                index += 1
            continue
        if char == 0x28:
            depth += 1
        elif char == 0x29:
            depth -= 1
            if depth == 0:
                return bytes(output), index + 1
        output.append(char)
        index += 1
    return bytes(output), size


def _two_byte(strings: list[object]) -> bool:
    raw = b"".join(item for item in strings if isinstance(item, bytes))
    return len(raw) >= 4 and raw[0::2].count(0) * 10 >= (len(raw) // 2) * 6


def _hex_bytes(raw: bytes) -> bytes:
    digits = raw.translate(None, _HEX_WHITESPACE)
    if len(digits) % 2:
        digits += b"0"
    try:
        return binascii.unhexlify(digits)
    except binascii.Error:
        # A content-stream hex string can hold any byte. Skip what is not a hex digit, as
        # readers do, rather than fail the scan.
        digits = _NOT_HEX.sub(b"", raw)
        if len(digits) % 2:
            digits += b"0"
        return binascii.unhexlify(digits)


def _utf16(raw: bytes) -> str:
    if len(raw) % 2:
        raw = b"\x00" + raw
    return raw.decode("utf-16-be", errors="replace")


_DECODE_CHUNK = 8192


# What a font read as UTF-16BE keeps: characters drawn as text. A name a merged file gives
# several fonts reads each string through all of them, and glyph ids read as UTF-16 land on
# any code point, so format controls, combining marks, private use, unassigned code points,
# separators other than a space, and the Hangul fillers are dropped: they would otherwise
# look like the invisible-character and bidi tricks the Unicode rules report.
_DRAWN_CATEGORIES = frozenset({"L", "N", "P", "S"})
_FILLERS = frozenset({0x115F, 0x1160, 0x3164, 0xFFA0})
_UNDRAWN: dict[int, None] | None = None


def _drawn(text: str) -> str:
    global _UNDRAWN
    if _UNDRAWN is None:
        _UNDRAWN = {
            code: None
            for code in range(0x10000)
            if code in _FILLERS
            or (
                unicodedata.category(chr(code))[0] not in _DRAWN_CATEGORIES
                and unicodedata.category(chr(code)) != "Zs"
                and code not in (0x09, 0x0A)
            )
        }
    text = text.translate(_UNDRAWN)
    if any(ord(char) > 0xFFFF for char in text):
        text = "".join(
            char
            for char in text
            if ord(char) <= 0xFFFF or unicodedata.category(char)[0] in _DRAWN_CATEGORIES
        )
    return text


def _decode(raw: bytes, font: Font, remaining: int, check: Callable[[], None]) -> str:
    too_large = "pdf decoded text exceeds character limit"
    if font.cmap is None:
        if font.utf16:
            if len(raw) > 2 * remaining:
                raise ContentLimit(too_large)
            check()
            return _drawn(raw[: len(raw) & ~1].decode("utf-16-be", errors="replace"))
        if font.composite:
            return ""
        if len(raw) > remaining:
            raise ContentLimit(too_large)
        check()
        return raw.decode("cp1252", errors="replace")
    cmap = font.cmap
    # A short string that cannot pass the limit is decoded in one pass, as before the limit
    # existed. The content-stream token loop checks the deadline between strings.
    size = len(raw)
    if size <= _DECODE_CHUNK:
        lengths = font.lengths
        if lengths == (2,):
            if (size >> 1) * font.widest <= remaining:
                return "".join([cmap.get(raw[i : i + 2], "") for i in range(0, size - 1, 2)])
        elif lengths == (1,) and size * font.widest <= remaining:
            return "".join([cmap.get(raw[i : i + 1]) or _CP1252[raw[i]] for i in range(size)])
    output: list[str] = []

    def append(text: str) -> None:
        nonlocal remaining
        remaining -= len(text)
        if remaining < 0:
            raise ContentLimit(too_large)
        if text:
            output.append(text)

    if font.lengths == (2,):
        for index in range(0, len(raw) - 1, 2):
            if index % 8192 == 0:
                check()
            append(cmap.get(raw[index : index + 2], ""))
    elif font.lengths == (1,):
        for index in range(len(raw)):
            if index % 8192 == 0:
                check()
            append(cmap.get(raw[index : index + 1]) or _CP1252[raw[index]])
    else:
        index = next_check = 0
        while index < len(raw):
            if index >= next_check:
                check()
                next_check = index + 8192
            for length in font.lengths:
                code = raw[index : index + length]
                if len(code) == length and code in cmap:
                    append(cmap[code])
                    index += length
                    break
            else:
                # A simple font falls back to its byte. A composite font has no text.
                if not font.composite:
                    append(_CP1252[raw[index]])
                index += font.lengths[-1] if font.composite else 1
    return "".join(output)


def _name(raw: bytes) -> bytes:
    """A PDF name with #xx escapes decoded, so /F#31 and /F1 compare equal."""
    if b"#" not in raw:
        return raw
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda match: bytes.fromhex(match.group(1).decode()), raw)
