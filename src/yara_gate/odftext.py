"""OpenDocument paragraph text, joined across the markup that splits it."""

import html
import re
from collections.abc import Iterator
from dataclasses import dataclass, field

from yara_gate.content import Budget, ContentLimit, _with_folded, plain_xml, utf8_xml, xml_text

# The text namespace of OpenDocument 1.0 to 1.4 (OASIS, ISO/IEC 26300). A part that does not
# declare it holds no paragraph: this is the format check, so a flat document (.fodt), a
# header in styles.xml, and an embedded object's content.xml are read like content.xml itself.
_TEXT_NAMESPACE = b"urn:oasis:names:tc:opendocument:xmlns:text:1.0"
# Every prefix the part binds to that namespace; no prefix is the default namespace. Producers
# write ``text``, but XML lets an author choose, so the prefix is read, not assumed.
_BINDING = re.compile(
    rb"""xmlns(?::([A-Za-z_][\w.-]{0,32}+))?\s*+=\s*+["']"""
    + re.escape(_TEXT_NAMESPACE)
    + rb"""["']"""
)
# One tag (closing slash, prefix, local name, attributes) or character data, after
# ``plain_xml`` has removed comments, CDATA wrappers, and ">" from attribute values. Every
# quantifier is possessive, so a tag that never closes costs one attempt at its "<".
_TOKEN = re.compile(
    rb"<(/?)(?:([A-Za-z_][\w.-]{0,32}+):)?([A-Za-z_][\w.-]{0,64}+)([^<>]*+)>|([^<]++)"
)
_SPACE_COUNT = re.compile(rb"""(?:^|[\s:])c\s*+=\s*+["']([0-9]{1,9})["']""")
# White space in character data collapses to one space, and none is kept at the start of a
# paragraph (OpenDocument 1.2 part 1, 6.1.2). ``text:s`` is how a second space is written.
_WHITESPACE = re.compile(r"[ \t\r\n]+")
_PARAGRAPHS = frozenset({b"p", b"h"})
# The inline text elements whose content every reader shows in place.
_ALWAYS_SHOWN = frozenset({b"span", b"a"})
# Elements LibreOffice does not lay out in the line: the reading above a ruby base, a
# comment's author and date, and a frame's title and description. Text they show elsewhere
# stands in paragraphs of its own.
_NOT_IN_THE_LINE = frozenset({b"ruby-text", b"annotation", b"frame"})
# An embedded image's base64, which no reading of a paragraph holds.
_NEVER_TEXT = b"binary-data"
# Spaces one ``text:s`` may add. Its tag is longer than that, so the view never outgrows the part.
_MAX_SPACES = 16
# A UTF-8 byte order mark and white space, which may stand before a part's first tag.
_BEFORE_XML = b"\xef\xbb\xbf \t\r\n"
_MAX_NESTING = 64

# One stretch of a paragraph: its text, and whether it is written out (``text:s``, a tab, a
# line break) and so exempt from white-space collapsing.
_Chunk = tuple[str, bool]


@dataclass
class _Paragraph:
    """An open paragraph in the readings its markup allows.

    Readers agree on character data that stands in the paragraph itself, in a span, or in a
    link. They differ on every other element. pandoc drops one it does not read (a ruby
    base, a footnote mark, an element the schema does not define); LibreOffice shows the
    character data of any element it does not handle itself; a converter that strips tags
    shows all of it. ``minimal`` is the first reading, ``shown`` the second, ``every`` the
    third; the last two stay None until they differ. Reading only one would let another
    hide a word, or a break between two words.
    """

    minimal: list[_Chunk] = field(default_factory=list)
    shown: list[_Chunk] | None = None
    every: list[_Chunk] | None = None
    other: int = 0
    not_in_line: int = 0

    def add(self, chunk: _Chunk) -> None:
        if self.not_in_line:
            if self.every is None:
                self.every = list(self.minimal if self.shown is None else self.shown)
            self.every.append(chunk)
            return
        if self.every is not None:
            self.every.append(chunk)
        if self.other:
            if self.shown is None:
                self.shown = list(self.minimal)
            self.shown.append(chunk)
            return
        if self.shown is not None:
            self.shown.append(chunk)
        self.minimal.append(chunk)

    def enter(self, local: bytes, closing: bool) -> None:
        step = -1 if closing else 1
        self.other = max(0, self.other + step)
        if local in _NOT_IN_THE_LINE:
            self.not_in_line = max(0, self.not_in_line + step)


def _line(chunks: list[_Chunk]) -> tuple[str, bool]:
    """The chunks as a reader lays them out, and whether collapsing changed any of them."""
    parts: list[str] = []
    after_space = True
    changed = False
    for text, written_out in chunks:
        if written_out:
            parts.append(text)
            after_space = False
            continue
        collapsed = _WHITESPACE.sub(" ", text)
        if after_space and collapsed.startswith(" "):
            collapsed = collapsed[1:]
        changed = changed or collapsed != text
        if collapsed:
            parts.append(collapsed)
            after_space = collapsed.endswith(" ")
    return "".join(parts), changed


def odf_text_views(data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    """Join the text of each OpenDocument paragraph into one ``odf-text`` view.

    A paragraph or heading (``text:p``, ``text:h``) is one line. Inline markup inside it
    joins: a span, a link, a comment, and a CDATA section leave the words adjacent,
    ``text:s`` is its spaces, ``text:tab`` a tab, and ``text:line-break`` a line break. A
    paragraph nested in another (a footnote body, a comment, a text box) is a line of its
    own between blank lines, and a blank line follows each table cell, so two cells never
    form one phrase. A paragraph holding an element that readers treat differently is read
    each way (see ``_Paragraph``); the further readings follow the part's lines.

    One linear pass over the tokens. No XML parser runs; ``plain_xml`` first removes what
    one would, and nothing external is read. A prefix is matched by its name, so one bound
    to two namespaces in a part is read as the text namespace throughout. A part with fewer
    than two stretches of text is left to the raw and HTML-unescaped views of the member.
    """
    data = utf8_xml(data)
    # A part is XML from its first byte. An uncompressed package holds the same namespace
    # in its own bytes; its content.xml is read as a member, not a second time from outside.
    if _TEXT_NAMESPACE not in data or data[:64].lstrip(_BEFORE_XML)[:1] != b"<":
        return
    prefixes = frozenset(match.group(1) or b"" for match in _BINDING.finditer(data))
    if not prefixes:
        return
    data = plain_xml(data, budget)
    lines: list[str] = []
    alternates: list[str] = []
    enclosing: list[_Paragraph] = []
    paragraph: _Paragraph | None = None
    never_text = 0
    stretches = 0
    collapsed_any = False

    def close_paragraph(closed: _Paragraph) -> None:
        nonlocal paragraph, stretches, collapsed_any
        paragraph = enclosing.pop() if enclosing else None
        line, changed = _line(closed.minimal)
        stretches += len(closed.minimal)
        collapsed_any = collapsed_any or changed
        if paragraph is None:
            lines.append(line + "\n")
        elif line.strip():
            lines.append("\n" + line + "\n\n")
        seen = {line}
        for chunks in (closed.shown, closed.every):
            if chunks is None:
                continue
            other, _ = _line(chunks)
            if other not in seen and other.strip():
                seen.add(other)
                stretches += 2
                alternates.append("\n" + other + "\n")

    for count, match in enumerate(_TOKEN.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        text = match.group(5)
        if text is not None:
            if paragraph is not None and not never_text:
                text, joined = xml_text(text)
                # Text that markup had split is not contiguous in the raw bytes.
                collapsed_any = collapsed_any or joined
                paragraph.add((html.unescape(text.decode("utf-8", errors="replace")), False))
            continue
        local = match.group(3)
        closing = bool(match.group(1))
        empty = match.group(4).endswith(b"/")
        in_text = (match.group(2) or b"") in prefixes
        if local == _NEVER_TEXT:
            if not empty:
                never_text = max(0, never_text - 1) if closing else never_text + 1
        elif in_text and local in _PARAGRAPHS:
            if closing:
                if paragraph is not None:
                    close_paragraph(paragraph)
            elif empty:
                if paragraph is None:
                    lines.append("\n")
            else:
                if paragraph is not None:
                    if len(enclosing) >= _MAX_NESTING:
                        raise ContentLimit("odf paragraph nesting exceeds 64")
                    enclosing.append(paragraph)
                paragraph = _Paragraph()
        elif paragraph is None:
            if closing and not in_text and local == b"table-cell":
                lines.append("\n")
        elif empty:
            if not in_text:
                continue
            if local == b"s":
                found = _SPACE_COUNT.search(match.group(4))
                spaces = min(int(found.group(1)) if found else 1, _MAX_SPACES)
                paragraph.add((" " * spaces, True))
            elif local == b"tab":
                paragraph.add(("\t", True))
            elif local == b"line-break":
                paragraph.add(("\n", True))
        elif not (in_text and local in _ALWAYS_SHOWN):
            paragraph.enter(local, closing)
    while paragraph is not None:
        # The part ended inside a paragraph: its words are still text some reader shows.
        close_paragraph(paragraph)
    if stretches >= 2 or collapsed_any:
        yield from _with_folded("odf-text", "".join(lines + alternates), budget)
