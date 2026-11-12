"""Bounded in-memory content views. Member names are never extracted to disk."""

import base64
import binascii
import bz2
import codecs
import email
import email.errors
import email.header
import email.message
import email.policy
import functools
import gzip
import html
import io
import json
import lzma
import re
import stat
import tarfile
import time
import unicodedata
import urllib.parse
import zipfile
import zlib
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from yara_gate.filetype import sniff, utf16_encoding
from yara_gate.heuristics import (
    _PDF_LEX,
    _PDF_VALUE_WINDOW,
    MAX_PDF_DEFINITIONS,
    PdfRawObjects,
    _decode_pdf_name,
)

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_EXTRACT_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
MAX_MEMBERS = 1000
MAX_PDF_STREAMS = 2000
# A zip entry's Unix file type: none recorded, a regular file, or a directory. Anything else (a
# symlink, device, or FIFO) is what tar already refuses as an unsupported member.
_ZIP_PLAIN_MODES = frozenset((0, stat.S_IFREG, stat.S_IFDIR))
_DRIVE = re.compile(r"[A-Za-z]:")

# JSON string escapes. A surrogate pair is decoded as one character; a lone surrogate stays escaped.
_JSON_ESCAPE = re.compile(
    r"\\u[dD][89abAB][0-9a-fA-F]{2}\\u[dD][c-fC-F][0-9a-fA-F]{2}"
    r"|\\u[0-9a-fA-F]{4}|\\[\"\\/bfnrt]"
)
_JSON_SIMPLE = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
# Letters that render like Latin letters (Unicode TR39 confusables for Cyrillic and Greek). They are
# folded only inside a token that already mixes Latin with another script, so Russian or Greek
# prose is left alone and "Ign\u043ere" (Cyrillic o) becomes "Ignore".
_CONFUSABLES = str.maketrans(
    {
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0443": "y",
        "\u0445": "x",
        "\u0456": "i",
        "\u0458": "j",
        "\u0455": "s",
        "\u04bb": "h",
        "\u0410": "A",
        "\u0412": "B",
        "\u0415": "E",
        "\u041a": "K",
        "\u041c": "M",
        "\u041d": "H",
        "\u041e": "O",
        "\u0420": "P",
        "\u0421": "C",
        "\u0422": "T",
        "\u0425": "X",
        "\u03b1": "a",
        "\u03b5": "e",
        "\u03b9": "i",
        "\u03ba": "k",
        "\u03bd": "v",
        "\u03bf": "o",
        "\u03c1": "p",
        "\u03c4": "t",
        "\u03c5": "u",
        "\u0391": "A",
        "\u0392": "B",
        "\u0395": "E",
        "\u0397": "H",
        "\u0399": "I",
        "\u039a": "K",
        "\u039c": "M",
        "\u039d": "N",
        "\u039f": "O",
        "\u03a1": "P",
        "\u03a4": "T",
        "\u03a7": "X",
        "\u03a5": "Y",
        "\u0396": "Z",
    }
)
# Digits and symbols that stand in for letters, folded only inside a token that also has letters.
_LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"}
)
# Unambiguous Latin small capitals used by small-text generators; phonetic variants stay put.
_SMALL_CAPS = str.maketrans(
    "\u1d00\u0299\u1d04\u1d05\u1d07\ua730\u0262\u029c\u026a\u1d0a\u1d0b\u029f"
    "\u1d0d\u0274\u1d0f\u1d18\u0280\ua731\u1d1b\u1d1c\u1d20\u1d21\u028f\u1d22",
    "abcdefghijklmnoprstuvwyz",
)
# A whole word that holds a non-ASCII letter or digit: eligible for script or Cyrillic case
# folding. An ASCII word fails at its first character after the lazy prefix, so this is linear.
_NON_ASCII_WORD = re.compile(r"(?<![^\W_])[^\W_]*?[^\W_\x00-\x7f][^\W_]*")
# A maximal run of letters, digits, @, and $ that holds at least one of 0134578@$. The match
# starts only at a run's first character, so a run is read from one start and not rescanned from
# every position inside it. Every repeat is a single character class: the regex engine runs
# those in constant memory, whereas a repeated group with an alternation saves backtracking state
# per character (about 114 bytes each, over 7 GB for a 67-million-character token).
_LEET_TOKEN = re.compile(r"(?<![^\W_])[^\W_]*[0134578@$][^\W_@$]*(?:[0134578@$][^\W_@$]*)*")
# Four or more single letters separated by one space, dot, dash, underscore, or asterisk.
_SPACED = re.compile(r"(?<![^\W_])(?:[^\W\d_][ .\-_*]){3,}[^\W\d_](?![^\W_])")
_SPACERS = re.compile(r"[ .\-_*]")
# A hyphen after a letter at a line end, before a lowercase letter on the next line.
_HYPHEN_WRAP = re.compile(r"(?<=[A-Za-z])-[ \t]*+\r?\n[ \t]*+(?=[a-z])")
# Control characters other than tab, CR, and LF, which is what the Cc filter removes from ASCII.
_ASCII_CONTROL = re.compile(r"[\x00-\x1f]")
_ASCII_CONTROL_DELETE = dict.fromkeys([*range(0, 9), 11, 12, *range(14, 32), 127])
# Every format (Cf) and control (Cc) character other than tab, LF, and CR, plus the variation
# selectors U+FE00-FE0F, in Unicode 15.0 (Python 3.12): what text-folded removes. One
# str.translate replaces a per-character category lookup; tests/test_text_fast_paths.py
# compares the table with unicodedata for every code point.
_FOLD_DELETE_RANGES = (
    (0x0, 0x8), (0xB, 0xC), (0xE, 0x1F), (0x7F, 0x9F), (0xAD, 0xAD), (0x600, 0x605),
    (0x61C, 0x61C), (0x6DD, 0x6DD), (0x70F, 0x70F), (0x890, 0x891), (0x8E2, 0x8E2),
    (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x2064), (0x2066, 0x206F),
    (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD), (0x110CD, 0x110CD),
    (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
)  # fmt: skip
FOLD_DELETE = dict.fromkeys(
    code for start, stop in _FOLD_DELETE_RANGES for code in range(start, stop + 1)
)

# Office XML parts whose text a reader sees, by the name an office suite gives them. Word splits
# a sentence across runs on any formatting or proofing boundary, so the joined text is what the
# lexical rules need. A package may name a part anything ([Content_Types].xml and the
# relationships say what it is), so a part these names do not know is read by its root element
# (``_OOXML_ROOT_ROLE``).
_OOXML_TEXT_PART = re.compile(
    r"(?i)^(word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
    r"|xl/sharedStrings\.xml|ppt/(slides|notesSlides)/[^/]+\.xml)$"
)
# Parts whose runs are joined but whose hidden runs are not read: text a renderer draws on a
# slide from its layout and master, a SmartArt diagram's and a chart's text, a text box on a
# worksheet, and Word's building blocks. The hidden-text reader resolves a run's own
# properties in the body parts above; these inherit theirs from places it does not follow.
_OOXML_DRAWN_PART = re.compile(
    r"(?i)^(ppt/(slideLayouts|slideMasters)/[^/]+\.xml"
    r"|(word|xl|ppt)/(charts/chart|diagrams/(data|drawing))[^/]*\.xml"
    r"|xl/drawings/drawing[^/]*\.xml|word/glossary/document\.xml)$"
)
# A text run (its prefix and text), a paragraph or shared-string end, a Word or DrawingML
# break, a Word tab, a phonetic run's start or end, or a paragraph or shared-string start, in
# document order, after ``_office_prefixes`` has written every element of an Office namespace
# under the prefix matched here. Attributes are possessive and
# never cross a "<" or a ">": a run tag that does not close costs one attempt that ends at the
# next tag, where an open-ended ``[^>]*`` rescanned the rest of the part from every such tag.
# ``plain_xml`` has already taken ">" out of attribute values. An end tag may hold white space
# before its ">" (XML 1.0, production 42), and every parser reads through it.
_OOXML_TOKEN = re.compile(
    rb"<((?:w:|a:)?)t(?:\s[^<>]*+)?>([^<]*+)</(?:w:|a:)?t\s*+>"
    rb"|</(?:w:p|a:p|si)\s*+>"
    rb"|<(?:w:(?:br|cr)|a:br)\b[^<>]*+>"
    rb"|<w:tab\b[^<>]*+>"
    rb"|<(/?)rPh\b[^<>]*+>"
    rb"|<((?:w:|a:)p|si)(?=[\s/>])[^<>]*+>"
)
# Paragraphs open inside one another whose runs are told apart: a text box in a table cell in
# a text box is four. Deeper ones are joined as they always were.
_MAX_PARAGRAPH_NESTING = 64

_PDF_STREAM = re.compile(rb"stream\r?\n")
_PDF_END = re.compile(rb"\r?\n?endstream")
# An indirect object header. The stream dictionary is the one value between it and ``stream``.
_PDF_OBJ = re.compile(
    rb"(?<![0-9])[0-9]+[\x00\t\n\f\r ]+[0-9]+[\x00\t\n\f\r ]+obj(?![^\x00\t\n\f\r /<>\[\]()%{}])"
)
_PDF_DICT_WINDOW = 4096
# Keywords that end an object; matched as whole tokens, never inside a comment, string, or name.
_PDF_OBJ_END = frozenset((b"endobj", b"stream"))
_PDF_MAX_NESTING = 64
_PDF_INT = re.compile(rb"[+-]?[0-9]+")
MAX_OBJSTM_OBJECTS = 100_000
# Filter names, including the inline-image abbreviations readers also accept in a stream.
_PDF_FLATE_NAMES = frozenset({b"/FlateDecode", b"/Fl"})
_PDF_ASCII_STAGES = frozenset({b"/ASCIIHexDecode", b"/AHx", b"/ASCII85Decode", b"/A85"})
# The deadline is checked after this many bytes of predictor work, inside rows as well.
_PREDICTOR_CHECK = 1 << 16
# Stream filters this view decodes, by full name and by the abbreviation readers also accept.
# LZWDecode and RunLengthDecode are left out: no stdlib decoder, and a pure-Python one cannot
# cover a 100 MB stream within the deadline. A chain that needs either stays out of the view.
_PDF_FLATE = b"/FlateDecode"
_PDF_HEX = b"/ASCIIHexDecode"
_PDF_A85 = b"/ASCII85Decode"
_PDF_FILTERS = {
    _PDF_FLATE: _PDF_FLATE,
    b"/Fl": _PDF_FLATE,
    _PDF_HEX: _PDF_HEX,
    b"/AHx": _PDF_HEX,
    _PDF_A85: _PDF_A85,
    b"/A85": _PDF_A85,
}
_PDF_WHITESPACE = b"\x00\t\n\f\r "
_PDF_NOT_HEX = re.compile(rb"[^0-9A-Fa-f]+")
# Whole ASCII85 groups, up to 64 KB of output: ``z`` where a group starts, otherwise five bytes.
_PDF_A85_GROUPS = re.compile(rb"(?:z|[^z][\x00-\xff]{4}){1,16384}")
_PDF_A85_DIGITS = re.compile(rb"[!-uz]*")
_PDF_CHUNK = 64 * 1024
# A parsed PDF object: a token, an array, a dictionary keyed by decoded name, or a reference.
type PdfValue = bytes | list[PdfValue] | dict[bytes, PdfValue] | tuple[int, int]

# A mail message: header lines, a Content-Type, and one more message header. It is opened when
# a mail reader shows something other than its bytes: a multipart body, a body in a transfer
# encoding, an HTML body, or a text body in a charset other than UTF-8. A reader's mail client
# shows the decoded parts, so they are scanned as members; the raw message is scanned as well.
_MIME_FIRST_LINE = re.compile(rb"\A(?:[A-Za-z][A-Za-z0-9-]*:[ \t]|From )")
_MIME_HEADER_NAME = re.compile(rb"(?m)^([A-Za-z][A-Za-z0-9-]*):")
_MIME_BLANK = re.compile(rb"\r?\n\r?\n")
_MIME_ENCODED = re.compile(rb"content-transfer-encoding:[ \t]*(base64|quoted-printable)")
_MIME_MESSAGE_HEADERS = frozenset(
    {b"mime-version", b"from", b"subject", b"message-id", b"received"}
)
_MIME_PART_SUFFIX = {"text/plain": ".txt", "text/html": ".html", "text/csv": ".csv"}
# The header block is read this far. Relay, ARC, and DKIM headers put the Content-Type of
# ordinary mail past 8 KiB, and a mail reader has no such limit.
_MIME_HEADER_BYTES = 64 * 1024
# The header block as Python's mail parser reads it: lines that start with a field name and a
# colon, a ``From `` envelope line, or folding white space. It ends at the first other line,
# which is the blank line (CRLF, LF, or CR alone) or, in a message with none, the body's first
# line. Possessive, and a line that fails ends the match, so the window is read once.
_MIME_HEADER_BLOCK = re.compile(rb"(?:(?:From |[!-9;-~]*:|[ \t])[^\r\n]*(?:\r\n?|\n|\Z))*+")
# A field name at the start of a line, where a line may end with CR alone.
_MIME_BLOCK_NAME = re.compile(rb"(?:\A|[\r\n])([a-z][a-z0-9-]*):")
# A message whose first 8 KiB names a multipart body or an encoded part holds its base64 as
# parts, which are decoded as members; ``text_views`` leaves the raw base64 runs to them.
_MIME_PARTS_BYTES = 8192
# The transfer encodings Python's email package decodes; a body under any other name is read
# as written.
_MIME_DECODED = frozenset({"base64", "quoted-printable", "x-uuencode", "uuencode", "uue", "x-uue"})
# A Content-Transfer-Encoding token ends at white space or an RFC 2045 special character.
_MIME_TOKEN = re.compile(r"[^ \t()<>@,;:\\\"/\[\]?=]*")
# A media type past any comment, in quotes or not: ``text/html (x)`` and ``"text/html"``.
_MIME_MEDIA_TYPE = re.compile(r"\"?([^ \t()<>@,;:\\\"/\[\]?=]+/[^ \t()<>@,;:\\\"/\[\]?=]+)")
# Inside an RFC 5322 comment only these characters change where it ends.
_MIME_COMMENT_MARK = re.compile(r"[()\\]")
# The charsets a part is kept in: what the lexical rules read, and UTF-16, which a unit that
# starts with a byte order mark is decoded from.
_MIME_KEPT_CHARSETS = frozenset(
    {"", "utf-8", "utf8", "us-ascii", "ascii", "utf-16", "utf-16le", "utf-16be"}
)
# Codecs whose text is already what the lexical rules read, and none.
_MIME_UTF8_CODECS = frozenset({"", "utf-8", "ascii"})
# Text codecs Python has that are not charsets. No mail client reads a body through one, so
# none is a reason to open a message.
_MIME_NOT_CHARSETS = frozenset(
    {"punycode", "idna", "unicode-escape", "raw-unicode-escape", "undefined"}
)
# Python decodes punycode in quadratic time (256 KiB: 3 s). A part declared in it is read
# through it up to this size; a larger one is unread, which is incomplete.
_MIME_PUNYCODE_BYTES = 16 * 1024
# The single-byte charsets that hold a directional mark (and windows-1256 the zero-width
# joiners) as one byte. Ordinary Hebrew, Arabic, and Persian mail carries those marks. In
# the message as written they are not the invisible characters the rules note; in a part
# transcoded whole they would be, on mail whose text is ordinary. So ``_mime_newly_read``
# transcodes without them: they have no width, and the words either side of one stay apart.
_MIME_MARK_CODECS = frozenset({"cp1255", "cp1256", "iso8859-8"})
_MIME_MARKS = dict.fromkeys((0x200C, 0x200D, 0x200E, 0x200F))
# A unit that starts with a byte order mark and then does not decode makes the scan
# incomplete, and Python's own mail generator writes such bodies (it joins the encoded lines
# with ASCII line ends). ``_mime_members`` says what a part in one of these is read as.
_MIME_WIDE_CODECS = ("utf-16", "utf-32")


class ContentLimit(Exception):
    """Inspection did not cover all required content."""


@dataclass(frozen=True)
class _OfficeReadings:
    """One part as the Office readers take it (``_office_readings``)."""

    # Every element of an Office namespace under the prefix the readers' patterns match.
    resolved: bytes
    # The part as it is written, or None where that is the same bytes.
    written: bytes | None
    # True when the two differ only in SpreadsheetML elements moved from ``x:`` to no prefix.
    moved_from_x_only: bool


@dataclass
class _OfficePart:
    """What the Office readers worked out about one unit. Four readers ask about each unit in
    turn; the part is resolved once and each of them reads the same bytes."""

    name: str
    # The unit's bytes are held, not their id, so the answer is never another part's.
    data: bytes
    roles: tuple[str, ...]
    utf8: bytes | None = None
    readings: _OfficeReadings | None = None


@dataclass
class Budget:
    deadline: float
    expanded: int = 0
    members: int = 0
    # The last part the Office readers looked at. It is kept until the next unit is asked about.
    office_part: _OfficePart | None = field(default=None, repr=False, compare=False)

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise ContentLimit("timeout")

    def member(self) -> None:
        self.check()
        self.members += 1
        if self.members > MAX_MEMBERS:
            raise ContentLimit("archive members exceed 1000")

    def read(self, stream: IO[bytes] | gzip.GzipFile) -> bytes:
        output = bytearray()
        while True:
            self.check()
            remaining = min(MAX_FILE_BYTES - len(output), MAX_EXTRACT_BYTES - self.expanded)
            chunk = stream.read(min(64 * 1024, remaining + 1))
            if not chunk:
                return bytes(output)
            self.expanded += len(chunk)
            if self.expanded > MAX_EXTRACT_BYTES:
                raise ContentLimit("extracted size exceeds 500MB")
            output.extend(chunk)
            if len(output) > MAX_FILE_BYTES:
                raise ContentLimit("archive member exceeds 100MB")


@dataclass(frozen=True)
class ContentUnit:
    name: str
    data: bytes
    # Ordinals identify members without exposing their potentially sensitive names.
    member_path: tuple[str, ...] = ()
    # True for the body of a mail message opened only for that body: the bytes the parent unit
    # holds, read a second time, so a finding both readings share is reported once.
    reread: bool = False


# A bzip2 stream: the header, then the first block's magic or the empty-stream end marker.
_BZIP2 = re.compile(rb"BZh[1-9](?:1AY&SY|\x17rE8P\x90)")
# A newc or crc cpio header: the magic and thirteen 8-digit hex fields.
_CPIO_NEWC = re.compile(rb"07070[12][0-9A-Fa-f]{104}")
_CPIO_PADDING = re.compile(rb"\0*")
_AR_MAGIC = b"!<arch>\n"


def archive_kind(data: bytes) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if _BZIP2.match(data):
        return "bzip2"
    if data.startswith(_AR_MAGIC):
        return "ar"
    if _CPIO_NEWC.match(data):
        return "cpio"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    # A unit has one kind. A message that names its parts in its first 8 KiB is mail even with
    # a zip archive appended. A message opened for longer headers or for its one body is the
    # archive when one ends it: an unzip tool opens that archive whatever precedes it, and its
    # members must not go unread because the bytes in front of them are also mail.
    if _mime_parts_are_members(data):
        return "mime"
    if _trailing_zip(data):
        return "zip"
    if _mime_message(data):
        return "mime"
    return None


_ZIP_END = b"PK\x05\x06"
_ZIP_END_SIZE = 22
_ZIP_LOCAL_SIZE = 30
MAX_ZIP_ARCHIVES = 16
MAX_ZIP_END_RECORDS = 64


def _trailing_zip(data: bytes) -> bool:
    """True when a zip archive ends ``data`` that does not start with one.

    A PDF, image, or script with an archive appended is still a zip to an unzip tool, and a
    Python zipapp starts with a ``#!`` line. Only the members are read; the shape itself is not
    a finding.
    """
    if _ZIP_END not in data[-(0xFFFF + _ZIP_END_SIZE) :]:
        return False
    # Not readable as a zip, so not one: the bytes stay a single unit, as before.
    opened = _open_zip(data)
    if opened is None:
        return False
    with opened:
        return bool(opened.infolist())


def _zip_archives(data: bytes, budget: Budget) -> Iterator[zipfile.ZipFile]:
    """Each zip archive in ``data``, open while its members are read.

    ``zipfile`` reads the archive whose end record comes last. Concatenated archives put
    another before it, and 7-Zip opens the first, so every earlier end record outside the
    members already read is tried as an archive of its own. A record inside a member's bytes
    belongs to a stored nested zip, which is read as that member. The main archive's errors
    propagate as before; an earlier record that does not open is ignored.
    """
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        covered = _zip_spans(data, archive)
        position = archive.start_dir
        yield archive
    starts = {position}
    tried = 0
    while True:
        position = data.rfind(_ZIP_END, 0, position)
        if position < 0:
            return
        budget.check()
        span = next((start for start, stop in covered if start <= position < stop), None)
        if span is not None:
            position = span
            continue
        tried += 1
        if tried > MAX_ZIP_END_RECORDS:
            raise ContentLimit("zip end records exceed 64")
        comment = int.from_bytes(data[position + 20 : position + 22], "little")
        end = position + _ZIP_END_SIZE + comment
        if end > len(data):
            continue
        earlier = _open_zip(data[:end])
        if earlier is None:
            continue
        with earlier:
            if not earlier.infolist() or earlier.start_dir in starts:
                continue
            if len(starts) >= MAX_ZIP_ARCHIVES:
                raise ContentLimit("zip archives exceed 16")
            starts.add(earlier.start_dir)
            covered.extend(_zip_spans(data, earlier))
            yield earlier


def _open_zip(data: bytes) -> zipfile.ZipFile | None:
    """``data`` as a zip archive, or None when it does not open as one."""
    try:
        return zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        return None


def _zip_spans(data: bytes, archive: zipfile.ZipFile) -> list[tuple[int, int]]:
    """The byte ranges of each member (local header through its data) and of the directory."""
    spans = [(archive.start_dir, len(data))]
    for info in archive.infolist():
        start = info.header_offset
        header = data[start : start + _ZIP_LOCAL_SIZE]
        extra = 0
        if len(header) == _ZIP_LOCAL_SIZE:
            extra = int.from_bytes(header[26:28], "little") + int.from_bytes(
                header[28:30], "little"
            )
        spans.append((start, start + _ZIP_LOCAL_SIZE + extra + info.compress_size))
    return spans


def _mime_headers(data: bytes) -> bytes | None:
    """The header block in the first 8 KiB of a mail message, in lower case, or None.

    None when ``data`` does not start like a message. A block with no blank line inside the
    8 KiB is read to their end.
    """
    head = data[:_MIME_PARTS_BYTES]
    if not _MIME_FIRST_LINE.match(head):
        return None
    blank = _MIME_BLANK.search(head)
    headers = (head[: blank.start()] if blank else head).lower()
    names = {match.group(1) for match in _MIME_HEADER_NAME.finditer(headers)}
    if b"content-type" not in names or not names & _MIME_MESSAGE_HEADERS:
        return None
    return headers


def _mime_names_parts(lowered: bytes) -> bool:
    return b"multipart/" in lowered or _MIME_ENCODED.search(lowered) is not None


def _mime_parts_are_members(data: bytes) -> bool:
    """True when the first 8 KiB of a message names a multipart body or an encoded part."""
    headers = _mime_headers(data)
    return headers is not None and _mime_names_parts(headers)


def _mime_header_block(data: bytes) -> bytes | None:
    """A mail message's whole header block, when it ends inside 64 KiB, or None.

    The block ends where the mail parser ends it, which needs no blank line: a line that is
    CR alone ends it, and so does a first body line that follows the last header directly.
    A block that runs past the window is not read: the mail library reads a long folded
    Content-Type in quadratic time, and a block that long is not ordinary mail.
    """
    head = data[:_MIME_HEADER_BYTES]
    if not _MIME_FIRST_LINE.match(head):
        return None
    block = _MIME_HEADER_BLOCK.match(head)
    if block is None or (block.end() == len(head) and len(data) > len(head)):
        return None
    written = head[: block.end()]
    names = {match.group(1) for match in _MIME_BLOCK_NAME.finditer(written.lower())}
    if b"content-type" not in names or not names & _MIME_MESSAGE_HEADERS:
        return None
    return written


def _mime_message(data: bytes) -> bool:
    """True for a mail message a mail reader shows as something other than its bytes.

    The first 8 KiB decides for a message that names its parts there. Past that the header
    block has to end inside 64 KiB, and the message either names its parts further down or
    has one body that is decoded. A single ``text/plain`` part in UTF-8 or ASCII with no
    transfer encoding reads the same in a mail reader and in a text editor, so that message
    stays one unit and is not a container.
    """
    if _mime_parts_are_members(data):
        return True
    block = _mime_header_block(data)
    return block is not None and (_mime_names_parts(block.lower()) or _mime_body_decoded(block))


def _mime_one_body(data: bytes) -> bool:
    """True for a message opened only because its one body is decoded before it is shown.

    Unopened, such a message is one unit of text. Its body is a second reading of that unit
    and not another file, which is what the callers act on: the body is not counted as an
    archive member, and the message is not opened where that would cost a level of depth.
    """
    if _mime_parts_are_members(data):
        return False
    block = _mime_header_block(data)
    return block is not None and not _mime_names_parts(block.lower()) and _mime_body_decoded(block)


# A unit is asked more than once (to open it, to count it, to choose its text views); the
# answer for the last few header blocks is kept so the headers are parsed once.
@functools.lru_cache(maxsize=8)
def _mime_body_decoded(headers: bytes) -> bool:
    """True when the one body under ``headers`` is decoded before a mail reader shows it.

    The block goes through the parser that reads the parts, so a folded line, a quoted
    parameter, or an RFC 2231 charset means here what it means there. The body is decoded when
    its transfer encoding is one the parser decodes, when it is HTML (a mail reader renders
    it, so a sentence split by inline tags is one sentence), and when it is text in a legacy
    charset.
    """
    part = email.message_from_bytes(headers, policy=email.policy.compat32)
    # The two answers that need no parameter come first: the mail library reads a parameter
    # in time quadratic in the header's length.
    if _mime_transfer_encoding(part) in _MIME_DECODED or _mime_media_type(part) == "text/html":
        return True
    try:
        codec = _mime_codec(_mime_charset(part))
    except (TypeError, ValueError):
        # Python 3.12.3 raises on some parameters other mail readers read past: a TypeError
        # on mixed RFC 2231 continuations, a ValueError on a NUL in the charset. The charset
        # is then unknown, so the message is opened. The part reader raises on the same
        # header, and the scan is incomplete as it is for that part in a multipart message,
        # where staying one unit would leave it clean with the body unread.
        return True
    return codec not in _MIME_UTF8_CODECS | _MIME_NOT_CHARSETS


def _mime_past_comments(value: str) -> int:
    """Where ``value`` starts after leading white space and RFC 5322 comments.

    A comment nests, and a backslash quotes the character after it. A comment that never
    closes runs to the end of the value, as it does in the mail library. Every step moves
    forward, so a value of any length is read once and needs no cap.
    """
    position = depth = 0
    while position < len(value):
        if depth:
            mark = _MIME_COMMENT_MARK.search(value, position)
            if mark is None:
                return len(value)
            position = mark.end()
            if mark.group() == "\\":
                position += 1
            else:
                depth += 1 if mark.group() == "(" else -1
        elif value[position] == "(":
            depth, position = 1, position + 1
        elif value[position] in " \t":
            position += 1
        else:
            break
    return min(position, len(value))


def _mime_transfer_encoding(part: email.message.Message) -> str:
    """The transfer encoding a current mail library decodes ``part`` with, in lower case.

    Python 3.13 under its default policy takes the first token of the value: past white space
    and comments, up to white space or a special character. So ``base64`` with a trailing
    space, a value folded onto the next line, ``quoted-printable (x)``, and ``base64; x=y``
    are each decoded. Its compat32 policy strips the value instead, and Python 3.12.3 compares
    it as written and decodes none of the four. Reading the value here keeps the result from
    depending on the interpreter that runs the scan.
    """
    written = str(part.get("content-transfer-encoding", ""))
    stripped = written.strip().lower()
    if stripped in _MIME_DECODED:
        return stripped
    value = written.replace("\r", "").replace("\n", "")
    token = _MIME_TOKEN.match(value, _mime_past_comments(value))
    return token.group().strip().lower() if token else ""


def _mime_media_type(part: email.message.Message) -> str:
    """The part's media type in lower case, read past comments and quotes.

    The mail library gives ``text/html (x)`` back whole and reads ``(x) text/html`` and
    ``"text/html"`` as text/plain, while other mail readers render all three as HTML. The
    library's own reading is kept when it is a type this module already names.
    """
    declared = part.get_content_type()
    if declared in _MIME_PART_SUFFIX:
        return declared
    value = str(part.get("content-type", "")).replace("\r", "").replace("\n", "")
    media = _MIME_MEDIA_TYPE.match(value, _mime_past_comments(value))
    return media.group(1).lower() if media else declared


def _mime_charset(part: email.message.Message) -> str | None:
    """A text part's declared charset in lower case, "" for none, and None for a part that is
    not text.

    The mail library reads a parameter in time quadratic in the header's length, so a part's
    charset is asked for once and handed on.
    """
    if part.get_content_maintype() != "text":
        return None
    return (part.get_content_charset() or "").lower()


def _mime_codec(charset: str | None) -> str:
    """The codec ``charset`` names, or "" for no charset and for one with no decoder.

    The codec's own name, so ANSI_X3.4-1968 (ASCII by its registered name, which cron writes
    on ordinary mail) and utf_8 are the codecs they mean.
    """
    try:
        return codecs.lookup(charset).name if charset else ""
    except LookupError:
        # The part's bytes are kept as written, so nothing would differ.
        return ""


# Containers recognized from their header that the scanner cannot open. Their members are
# compressed, encrypted, or stored by reference, so a clean verdict would describe only the
# outer bytes. Each prefix is the format's full fixed header, not a 2-byte guess, so ordinary
# binaries and text that name a format stay readable.
_UNSUPPORTED_PREFIXES = (
    b"7z\xbc\xaf\x27\x1c",  # 7-Zip
    b"Rar!\x1a\x07",  # RAR 1.5 to 5
    b"\x28\xb5\x2f\xfd",  # Zstandard frame
    b"\x04\x22\x4d\x18",  # LZ4 frame
    b"\x02\x21\x4c\x18",  # LZ4 legacy frame
    b"MSCF\x00\x00\x00\x00",  # Windows cabinet
    b"ITSF\x02\x00\x00\x00",  # Compiled HTML Help 2
    b"ITSF\x03\x00\x00\x00",  # Compiled HTML Help 3
    b"MSWIM\x00\x00\x00",  # Windows imaging
    b"xar!\x00\x1c",  # xar, as in macOS .pkg installers
    b"!<thin>\n",  # thin ar: its members are other files
)
# A Zstandard skippable frame, an odc cpio header, an ACE header, and an LHA level 0-2 header.
_UNSUPPORTED_PATTERN = re.compile(
    rb"[\x50-\x5f]\x2a\x4d\x18|070707[0-7]{70}|.{7}\*\*ACE\*\*|..-lh[0-7d]-", re.DOTALL
)


def unsupported_container(data: bytes) -> bool:
    """True for a container format the scanner recognizes but cannot open."""
    return data.startswith(_UNSUPPORTED_PREFIXES) or _UNSUPPORTED_PATTERN.match(data) is not None


def content_units(
    unit: ContentUnit, budget: Budget, depth: int = 0, *, inside_body: bool = False
) -> Iterator[ContentUnit]:
    budget.check()
    if unsupported_container(unit.data):
        raise ContentLimit("unsupported archive")
    kind = archive_kind(unit.data)
    one_body = kind == "mime" and _mime_one_body(unit.data)
    # A message opened for its one body is text, read as one unit when it is not opened. It
    # stays that unit where opening it would cost more than a second reading: at the depth
    # limit, where an archive of ordinary HTML mail would turn incomplete, and as the body of
    # another such message, where each level would decode the same bytes again.
    if one_body and (inside_body or depth >= MAX_ARCHIVE_DEPTH):
        kind = None
    if kind is None:
        yield unit
        return
    if depth >= MAX_ARCHIVE_DEPTH:
        raise ContentLimit("archive depth exceeds 3")
    try:
        for index, name, data in _members(unit, kind, budget):
            member = ContentUnit(name, data, (*unit.member_path, f"{kind}:{index}"), one_body)
            yield from content_units(member, budget, depth + 1, inside_body=one_body)
    except (
        OSError,
        EOFError,
        RuntimeError,
        ValueError,
        zipfile.BadZipFile,
        tarfile.TarError,
        email.errors.MessageError,
        lzma.LZMAError,
    ):
        raise ContentLimit("archive unreadable or encrypted") from None
    yield unit


def _members(unit: ContentUnit, kind: str, budget: Budget) -> Iterator[tuple[int, str, bytes]]:
    if kind == "zip":
        base = 0
        for opened in _zip_archives(unit.data, budget):
            entries = opened.infolist()
            if len(entries) + budget.members > MAX_MEMBERS:
                raise ContentLimit("archive members exceed 1000")
            for index, info in enumerate(entries, base):
                budget.member()
                # orig_filename keeps the NUL and backslashes that ZipInfo.filename rewrites.
                _check_member_name(info.orig_filename)
                if stat.S_IFMT(info.external_attr >> 16) not in _ZIP_PLAIN_MODES:
                    raise ContentLimit("archive contains unsupported member")
                if info.is_dir():
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    raise ContentLimit("archive member exceeds 100MB")
                if info.flag_bits & 1:
                    raise ContentLimit("archive unreadable or encrypted")
                with opened.open(info) as stream:
                    yield index, info.filename, budget.read(stream)
            base += len(entries)
    elif kind == "mime":
        yield from _mime_members(unit, budget)
    elif kind == "tar":
        # Stream mode avoids collecting all member metadata before enforcing the count cap.
        with tarfile.open(fileobj=io.BytesIO(unit.data), mode="r|") as archive:
            for index, entry in enumerate(archive):
                budget.member()
                _check_member_name(entry.name)
                if entry.isdir():
                    continue
                if not entry.isfile():
                    raise ContentLimit("archive contains unsupported member")
                if entry.size > MAX_FILE_BYTES:
                    raise ContentLimit("archive member exceeds 100MB")
                extracted = archive.extractfile(entry)
                if extracted is None:
                    raise ContentLimit("archive member unreadable")
                with extracted:
                    yield index, entry.name, budget.read(extracted)
    elif kind == "ar":
        yield from _ar_members(unit, budget)
    elif kind == "cpio":
        yield from _cpio_members(unit, budget)
    else:
        # gzip, xz, and bzip2 hold one stream; a .tar.gz names its member by the stem.
        budget.member()
        name = Path(unit.name).stem
        if unit.name.lower().endswith((".tgz", ".txz", ".tbz", ".tbz2")):
            name += ".tar"
        stream = io.BytesIO(unit.data)
        compressed: IO[bytes] | gzip.GzipFile
        if kind == "gzip":
            compressed = gzip.GzipFile(fileobj=stream)
        elif kind == "xz":
            compressed = lzma.LZMAFile(stream)
        else:
            compressed = bz2.BZ2File(stream)
        with compressed:
            yield 0, name, budget.read(compressed)


def _ar_members(unit: ContentUnit, budget: Budget) -> Iterator[tuple[int, str, bytes]]:
    """Members of a System V or BSD ar archive (a .deb's outer layer, a static library).

    Members are stored, not compressed. The symbol table and GNU long-name table are read as
    metadata; a malformed header or a size past the end is an unreadable archive.
    """
    data = unit.data
    position = len(_AR_MAGIC)
    names = b""
    index = 0
    while position < len(data):
        budget.check()
        header = data[position : position + 60]
        if len(header) < 60 or header[58:60] != b"`\n":
            raise ValueError("ar header")
        size = int(header[48:58].strip() or b"0")
        start = position + 60
        end = start + size
        if size < 0 or end > len(data):
            raise ValueError("ar member size")
        position = end + (end & 1)
        raw = header[:16].rstrip(b" ")
        body = data[start:end]
        if raw == b"//":
            names = body
            continue
        if raw in (b"/", b"/SYM64/"):
            continue
        if raw.startswith(b"#1/"):
            length = int(raw[3:])
            if not 0 <= length <= len(body):
                raise ValueError("ar member name")
            raw, body = body[:length].rstrip(b"\0"), body[length:]
        elif raw.startswith(b"/") and raw[1:].isdigit():
            raw = names[int(raw[1:]) :].split(b"\n", 1)[0].removesuffix(b"/")
        else:
            raw = raw.removesuffix(b"/")
        budget.member()
        name = raw.decode("utf-8", errors="replace")
        _check_member_name(name)
        if size > MAX_FILE_BYTES:
            raise ContentLimit("archive member exceeds 100MB")
        yield index, name, budget.read(io.BytesIO(body))
        index += 1


def _cpio_members(unit: ContentUnit, budget: Budget) -> Iterator[tuple[int, str, bytes]]:
    """Regular-file members of a newc or crc cpio archive (an initramfs, an RPM payload).

    Directories are skipped; a symlink, device, or other special member is unsupported, as in
    tar. Hard links store their data once, on the last link, so earlier links are empty. The
    walk goes on past each trailer, as the kernel reads a concatenated initramfs.
    """
    data = unit.data
    position = 0
    index = 0
    while True:
        budget.check()
        header = data[position : position + 110]
        if _CPIO_NEWC.fullmatch(header) is None:
            raise ValueError("cpio header")
        fields = [int(header[6 + 8 * slot : 14 + 8 * slot], 16) for slot in range(13)]
        mode, size, name_size = fields[1], fields[6], fields[11]
        name_start = position + 110
        start = (name_start + name_size + 3) & ~3
        end = start + size
        if name_size < 1 or end > len(data):
            raise ValueError("cpio member size")
        raw = data[name_start : name_start + name_size].rstrip(b"\0")
        position = (end + 3) & ~3
        if raw == b"TRAILER!!!":
            # An initramfs concatenates archives: early microcode, then a compressed main
            # archive, or two archives after one xz stream decodes. Padding zeros are skipped;
            # another header continues the walk, and any other tail is a member of its own.
            position = _CPIO_PADDING.match(data, position).end()  # type: ignore[union-attr]
            if position >= len(data):
                return
            if _CPIO_NEWC.match(data, position) is not None:
                continue
            budget.member()
            yield index, "cpio-tail", budget.read(io.BytesIO(data[position:]))
            return
        budget.member()
        name = raw.decode("utf-8", errors="replace")
        _check_member_name(name)
        kind = stat.S_IFMT(mode)
        if kind == stat.S_IFDIR:
            index += 1
            continue
        if kind != stat.S_IFREG:
            raise ContentLimit("archive contains unsupported member")
        if size > MAX_FILE_BYTES:
            raise ContentLimit("archive member exceeds 100MB")
        yield index, name, budget.read(io.BytesIO(data[start:end]))
        index += 1


def _check_member_name(name: str) -> None:
    """Refuse a member name that another unpacker would write outside its target directory.

    Nothing here extracts to disk, but a clean verdict would tell a consumer that unpacks the
    archive later that it is safe. ``./a`` and ``notes..txt`` stay in the tree. The reason never
    carries the name, because reports identify members by ordinal only.
    """
    path = name.replace("\\", "/")
    if (
        "\x00" in path
        or path.startswith("/")
        or _DRIVE.match(path) is not None
        or ".." in path.split("/")
    ):
        raise ContentLimit("archive member escapes the archive")


def _mime_members(unit: ContentUnit, budget: Budget) -> Iterator[tuple[int, str, bytes]]:
    """Decode each leaf part of a mail message: bodies, attachments, and nested messages' leaves.

    The ordinal is the part's position in the message walk, so a report never carries a part
    name. The member name is the attachment's final path component, or a suffix from the part
    type, so the name checks and the ``yara_gate_ext`` global see what a reader would save. Mail
    has no directory tree, so a filename such as ``../x`` is reduced to ``x`` rather than refused.
    """
    budget.check()
    message = email.message_from_bytes(unit.data, policy=email.policy.compat32)
    # The body of a message opened for that body is the unit read again, not another file. It
    # is not counted as a member, so an archive of 600 HTML messages is 600 members and not
    # 1,200; its bytes count against the size limits like any part's.
    one_body = _mime_one_body(unit.data)
    newly_opened = not _mime_parts_are_members(unit.data)
    for index, part in enumerate(message.walk()):
        if part.is_multipart():
            continue
        if one_body:
            budget.check()
        else:
            budget.member()
        payloads = _mime_part_payloads(part)
        if not payloads:
            continue
        # The body of a message opened for it takes its suffix from the media type read past
        # comments and quotes, which is why it was opened. Any other part keeps the name the
        # mail library's reading of its type gives it.
        name = _mime_part_name(part, index, _mime_media_type(part) if one_body else None)
        charset = _mime_charset(part)
        for payload in payloads:
            if len(payload) > MAX_FILE_BYTES:
                raise ContentLimit("archive member exceeds 100MB")
            budget.expanded += len(payload)
            if budget.expanded > MAX_EXTRACT_BYTES:
                raise ContentLimit("extracted size exceeds 500MB")
            if newly_opened:
                text = _mime_newly_read(charset, payload, one_body)
                if text is not None:
                    yield index, name, text
            else:
                yield index, name, _mime_part_text(charset, payload)


def _mime_newly_read(charset: str | None, payload: bytes, one_body: bool) -> bytes | None:
    """The text of a part of a message opened for its long header block or for its one body,
    or None to leave the part to the raw message.

    A message whose first 8 KiB names its parts keeps the reading ``_mime_part_text`` gives.
    Ordinary mail of the kinds read here is clean as one unit of text, and each case below
    keeps it clean.
    """
    codec = _mime_codec(charset)
    if codec.startswith(_MIME_WIDE_CODECS):
        # Kept in its encoding, a UTF-16 or UTF-32 part is an incomplete scan when it does
        # not decode (Python's mail generator writes such bodies) and a file type mismatch
        # when it has no byte order mark. Here the part is the text it decodes to, and one
        # that does not decode is not a unit.
        try:
            return payload.decode(codec).encode("utf-8")
        except UnicodeError:
            return None
    if one_body and codec in _MIME_NOT_CHARSETS:
        return payload
    if codec in _MIME_MARK_CODECS:
        try:
            return payload.decode(codec).translate(_MIME_MARKS).encode("utf-8")
        except UnicodeError:
            return payload
    return _mime_part_text(charset, payload)


def _mime_part_payloads(part: email.message.Message) -> list[bytes]:
    """A part's body in each reading a mail library gives it, the decoded one first.

    One reading when the transfer encoding is written as its bare name, or is not one the
    library decodes. A value that names an encoding with anything around it (a trailing space,
    a fold, a comment, a parameter) is decoded by Python 3.13 and left as written by 3.12.3,
    and other mail readers side with either, so both bodies are members under the part's one
    ordinal. The header is rewritten before the library is asked, so the interpreter that
    runs the scan does not choose between them.
    """
    header = part.get("content-transfer-encoding")
    encoding = _mime_transfer_encoding(part)
    if header is None or encoding not in _MIME_DECODED or str(header).lower() == encoding:
        readings = [part.get_payload(decode=True)]
    else:
        del part["content-transfer-encoding"]
        written = part.get_payload(decode=True)
        part["Content-Transfer-Encoding"] = encoding
        readings = [part.get_payload(decode=True), written]
    payloads: list[bytes] = []
    for payload in readings:
        if isinstance(payload, bytes) and payload and payload not in payloads:
            payloads.append(payload)
    return payloads


def _mime_part_name(part: email.message.Message, index: int, media: str | None = None) -> str:
    filename = part.get_filename()
    if filename:
        name = Path(filename.replace("\\", "/")).name
        if name:
            return name
    return f"part-{index}{_MIME_PART_SUFFIX.get(media or part.get_content_type(), '')}"


def _mime_part_text(charset: str | None, payload: bytes) -> bytes:
    """Transcode a text part declared in a legacy charset to UTF-8 so the lexical rules read it.

    ``charset`` is what ``_mime_charset`` gives for the part.
    """
    if charset is None or charset in _MIME_KEPT_CHARSETS:
        return payload
    try:
        # A part is read through whichever codec its charset names, so one too large to
        # decode in bounded time is unread, and not text as written. Punycode is the only
        # codec measured that is slower than linear.
        if codecs.lookup(charset).name == "punycode" and len(payload) > _MIME_PUNYCODE_BYTES:
            raise ContentLimit("archive unreadable or encrypted")
        return payload.decode(charset).encode("utf-8")
    except (LookupError, UnicodeError):
        return payload


_JSON_START = re.compile(r"[\[{]\s*(?:[\"{\[\]}\d-]|(?:true|false|null)\b)")


# A base64 token long enough to hold a sentence (12 bytes), standard or URL-safe, optionally
# wrapped at line ends the way mail and PEM-style tools wrap it. Possessive, so ordinary words
# fail fast and a long run is read once.
_B64_TOKEN = re.compile(
    r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}+(?:\r?\n[A-Za-z0-9+/_-]{4,}+)*+=*+"
)
_B64_WRAP = re.compile(r"\r?\n")
# Readable decoded runs, each scanned on its own; more is incomplete, never dropped.
MAX_B64_TEXTS = 1024
_ENCODED_WORD = re.compile(r"=\?[^?\s]{1,40}\?[BbQq]\?[^?\s]*\?=")
_B64_PROBE = 256
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_PERCENT_MIN = 3
# A query string that encodes spaces as + needs no %XX escape at all. The literal + leads, so
# the search skips ahead to each + instead of trying every position.
_PLUS_RUN = re.compile(r"\+[A-Za-z]{1,64}\+[A-Za-z]{1,64}\+")
# The characters a base64 token is made of, less = (a query writes q=word+word).
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


def base64_texts(text: str, budget: Budget) -> list[str]:
    """Base64 runs in ``text`` that decode to readable text, each as its own string.

    A reader or model decodes an encoded instruction as easily as it reads a plain one, so each
    run that decodes to UTF-8, or to UTF-16LE (PowerShell's -EncodedCommand form), and reads as
    text with at least one space is kept. Images, keys, hashes, and identifiers decode to
    binary and are dropped after a short probe. The caller scans each run apart, so two runs
    cannot form one phrase. Every candidate is read, under the scan deadline; more than
    ``MAX_B64_TEXTS`` readable runs is incomplete. A wrapped run that does not decode whole is
    tried line by line, because a following line of ordinary text can join the token.
    """
    pieces: list[str] = []
    for count, match in enumerate(_B64_TOKEN.finditer(text)):
        if count % 256 == 255:
            budget.check()
        token = match.group()
        decoded = _b64_token_text(_B64_WRAP.sub("", token))
        found = [decoded] if decoded is not None else []
        if decoded is None and "\n" in token:
            for line in token.splitlines():
                if len(line) >= 16 and (each := _b64_token_text(line)) is not None:
                    found.append(each)
        for piece in found:
            pieces.append(piece)
            if len(pieces) > MAX_B64_TEXTS:
                raise ContentLimit("base64 text runs exceed 1024")
    return pieces


def _b64_token_text(run: str) -> str | None:
    urlsafe = "-" in run or "_" in run
    if urlsafe and ("+" in run or "/" in run):
        return None  # Neither alphabet: a path, a slug, or an identifier.
    return _b64_readable(run, b"-_" if urlsafe else None)


def mime_header_text(data: bytes) -> str | None:
    """A MIME message's headers with RFC 2047 encoded words decoded, when it has any."""
    head = data[:_MIME_HEADER_BYTES]
    blank = _MIME_BLANK.search(head)
    raw = (head[: blank.start()] if blank else head).decode("latin-1")
    unfolded = re.sub(r"\r?\n[ \t]+", " ", raw)
    if _ENCODED_WORD.search(unfolded) is None:
        return None
    lines = []
    for line in unfolded.splitlines():
        try:
            lines.append(str(email.header.make_header(email.header.decode_header(line))))
        except (LookupError, ValueError, UnicodeError, email.errors.HeaderParseError):
            lines.append(line)
    decoded = "\n".join(lines)
    return decoded if decoded != unfolded else None


def _b64_readable(run: str, altchars: bytes | None) -> str | None:
    run = run.rstrip("=")
    run = run[: len(run) - len(run) % 4] if len(run) % 4 == 1 else run
    padded = run + "=" * (-len(run) % 4)
    try:
        head = base64.b64decode(padded[:_B64_PROBE], altchars=altchars, validate=True)
    except (ValueError, binascii.Error):
        return None
    if _b64_decode_text(head, probe=True) is None:
        return None
    try:
        raw = base64.b64decode(padded, altchars=altchars, validate=True)
    except (ValueError, binascii.Error):
        return None
    return _b64_decode_text(raw, probe=False)


def _b64_decode_text(raw: bytes, *, probe: bool) -> str | None:
    """Decoded text when ``raw`` reads as text; a probe tolerates a sequence cut at its end."""
    if len(raw) >= 4 and raw[1::2].count(0) * 10 >= (len(raw) // 2) * 9:
        encoding = "utf-16-le"
        raw = raw[: len(raw) - len(raw) % 2]
    else:
        encoding = "utf-8"
    try:
        decoded = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        if not probe or exc.start < len(raw) - 3:
            return None
        decoded = raw[: exc.start].decode(encoding)
    if not decoded:
        return None
    readable = sum(1 for char in decoded if char.isprintable() or char in "\t\r\n")
    if readable * 20 < len(decoded) * 19:
        return None
    if not probe and not any(char.isspace() for char in decoded):
        # One encoded word is an identifier or token, not an instruction.
        return None
    return decoded


def percent_text(text: str) -> str | None:
    """``text`` with %XX escapes and + spaces decoded, when it holds three escapes or a +-joined
    run of four words; otherwise None."""
    head = text[: 1 << 20]
    if len(_PERCENT.findall(head)) < _PERCENT_MIN and not _plus_words(head):
        return None
    decoded = urllib.parse.unquote_plus(text, errors="replace")
    return decoded if decoded != text else None


def _plus_words(text: str) -> bool:
    """True when a whole token is four or more letter words joined by +, as a query writes
    spaces; a base64 run that happens to hold +abc+def+ also holds digits or a slash."""
    for count, match in enumerate(_PLUS_RUN.finditer(text)):
        if count >= 64:
            return False
        start, end = match.start(), match.end()
        # A query token is short; walking further would read a whole base64 run char by char.
        low, high = max(0, start - 512), min(len(text), end + 512)
        while start > low and text[start - 1] in _B64_CHARS:
            start -= 1
        while end < high and text[end] in _B64_CHARS:
            end += 1
        if (start == low and low > 0) or (end == high and high < len(text)):
            continue
        words = text[start:end].split("+")
        if len(words) >= 4 and all(word.isascii() and word.isalpha() for word in words):
            return True
    return False


def _json_shaped(text: str) -> bool:
    """True when text opens like JSON, so an INI header such as [Section] is not decoded."""
    return _JSON_START.match(text) is not None


def text_views(data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    """Return UTF-8 derived views, keeping their offsets separate from raw bytes."""
    if sniff(data) != "text":
        return
    encoding = utf16_encoding(data) or "utf-8"
    try:
        text = data.decode(encoding)
    except UnicodeError:
        if encoding != "utf-8":
            raise ContentLimit("invalid UTF-16 text") from None
        # One stray byte must not switch off every derived view.
        text = data.decode("utf-8", errors="replace")
    if encoding != "utf-8":
        yield "decoded-utf16", _derived(text, budget)
    unescaped = html.unescape(text)
    if unescaped != text:
        yield "html-unescaped", _derived(unescaped, budget)
    # A chat body, webhook payload, or tool result arrives as JSON; the reader sees \u0049 as I.
    stripped = text.lstrip()
    if _json_shaped(stripped) and "\\" in stripped:
        decoded = _JSON_ESCAPE.sub(_json_escape, text)
        if decoded != text:
            yield from _with_folded("json-unescaped", decoded, budget)
    # An instruction a reader decodes first: base64 (UTF-8, or UTF-16LE as PowerShell writes
    # it) and percent-encoding. Each is one labeled view of the same bytes, not a recursion.
    # A mail message's headers hold RFC 2047 encoded words, which are not parts, so they get
    # their own view. Its base64 parts are decoded as its members, so the runs are left to
    # them where the top of the message names those parts; in any other message (headers past
    # 8 KiB, or one body that is not encoded) a run is read here as in any text file.
    if _mime_message(data):
        headers = mime_header_text(data)
        if headers is not None:
            yield from _with_folded("mime-headers-decoded", headers, budget)
    if not _mime_parts_are_members(data):
        for encoded in base64_texts(text, budget):
            yield from _with_folded("base64-decoded", encoded, budget)
    unquoted = percent_text(text)
    if unquoted is not None:
        yield from _with_folded("percent-decoded", unquoted, budget)
    # ASCII cannot contain Cf characters or Unicode variation selectors.
    # Check after unescaping: an ASCII entity can introduce either one.
    normalized = unescaped
    if not unescaped.isascii():
        # Inspect hidden formatting without modifying the original or interpreting it as authority.
        normalized = "".join(
            char
            for char in unescaped
            if unicodedata.category(char) != "Cf" and not 0xFE00 <= ord(char) <= 0xFE0F
        )
        if normalized != unescaped:
            yield "format-controls-removed", _derived(normalized, budget)
    # A reader sees "Ign\u043ere", fullwidth letters, "1gn0r3", or "i g n o r e" as the word; the
    # lexical rules do not. Fold those spellings into one more labeled view of the same bytes.
    folded = folded_text(unescaped)
    if folded != unescaped and folded != normalized:
        yield "text-folded", _derived(folded, budget)


FOLDED_SUFFIX = "+text-folded"


def _with_folded(view: str, text: str, budget: Budget) -> Iterator[tuple[str, bytes]]:
    """``view`` itself, then its folded spelling as ``<view>+text-folded`` when that differs.

    Obfuscations stack: an escape or an encoding hides a word whose letters are also swapped
    for look-alikes. Folding once more is one step deeper, not a recursion.
    """
    yield view, _derived(text, budget)
    folded = folded_text(text)
    if folded != text:
        budget.check()
        yield view + FOLDED_SUFFIX, _derived(folded, budget)


# ECMA-48 control sequences: CSI (7-bit or C1), an intermediate escape such as ESC ( B, and a
# two-byte escape, which includes the openers of OSC, DCS, and APC strings. A terminal draws
# none of them, so ESC [ 1 m before a word is not a separate word to the reader.
_ANSI = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|\x1b[ -/]+[0-~]|\x1b[@-_]")


def folded_text(text: str) -> str:
    """Return ``text`` with look-alike spellings folded to plain letters, for a derived view.

    Terminal control sequences removed whole (``ESC [ 1 m``), NFKC compatibility normalization
    (fullwidth and other presentation forms), removal of format controls and of control
    characters other than tab, CR, and LF, Latin small capitals folded to ASCII, and Cyrillic
    and Greek look-alikes folded to Latin inside mixed-script tokens, Cyrillic-only words
    lowercased for the multilingual rule, a word hyphenated at a line end rejoined
    (``previ-`` then ``ous``),
    letters spaced one apart rejoined, and digit or symbol stand-ins folded inside tokens that
    mix them with letters. Native scripts and ordinary numbers are preserved. The result is a
    view; the original bytes are scanned unchanged.
    """
    if not text.strip(" \t\r\n"):
        return text
    if "\x1b" in text or "\x9b" in text:
        text = _ANSI.sub("", text)
    folded = unicodedata.normalize("NFKC", text)
    if folded.isascii():
        # Same result as the per-character filter below, without a Python loop over every
        # character of a large ASCII body; every multi-line file has a CR or LF.
        if _ASCII_CONTROL.search(folded) is not None:
            folded = folded.translate(_ASCII_CONTROL_DELETE)
    else:
        folded = folded.translate(FOLD_DELETE)
        folded = folded.translate(_SMALL_CAPS)
    if not folded.isascii():
        folded = _NON_ASCII_WORD.sub(_fold_confusables, folded)
    if "-" in folded:
        # A word hyphenated at a line end (previ-, ous) reads as one word.
        folded = _HYPHEN_WRAP.sub("", folded)
    folded = _SPACED.sub(lambda match: _SPACERS.sub("", match.group()), folded)
    return _LEET_TOKEN.sub(_fold_leet, folded)


def _fold_confusables(match: re.Match[str]) -> str:
    word = match.group()
    if word.isascii():
        return word
    scripts = {_script(char) for char in word if char.isalpha()}
    if "LATIN" in scripts and len(scripts) > 1:
        return word.translate(_CONFUSABLES)
    if scripts == {"CYRILLIC"}:
        # YARA's nocase is ASCII-only; preserve Latin case for case-sensitive rules such as DAN.
        return word.lower()
    return word


def _script(char: str) -> str:
    name = unicodedata.name(char, "")
    return name.partition(" ")[0]


def _fold_leet(match: re.Match[str]) -> str:
    word = match.group()
    # A number such as 1337 or the 4 in 3.4.5 has no letter to fold.
    if not word.isdecimal() and any(char.isalpha() for char in word):
        return word.translate(_LEET)
    return word


def _json_escape(match: re.Match[str]) -> str:
    token = match.group()
    if len(token) == 12:
        high = int(token[2:6], 16)
        low = int(token[8:12], 16)
        return chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
    if len(token) == 6:
        code = int(token[2:], 16)
        # A lone surrogate cannot be encoded as UTF-8; keep the escape text.
        return token if 0xD800 <= code <= 0xDFFF else chr(code)
    return _JSON_SIMPLE[token[1]]


# What an XML parser removes or rewrites before any text reaches a reader: a comment, a
# processing instruction, a DOCTYPE, a CDATA section, and (last) one whole tag, whose quoted
# attribute values may hold ">". A tag is whatever opens with "<" and a name character: an
# element name need not be ASCII, and a tag left out here keeps a ">" that every reader's
# pattern takes for its end. Quantifiers are possessive or run to a literal, so each byte
# is read once; a comment or section that never closes runs to the end of the part.
_XML_NOISE = re.compile(
    rb"<!--.*?(?:-->|\Z)"
    rb"|<\?.*?(?:\?>|\Z)"
    rb"|<!DOCTYPE[^<>\[]*+(?:\[.*?(?:\]|\Z))?[^<>]*+>?"
    rb"|<!\[CDATA\[(.*?)(?:\]\]>|\Z)"
    rb"""|(<[^\s<>="'!?](?:[^<>"']++|"[^"<]*+"|'[^'<]*+')*+>)""",
    re.DOTALL,
)
# A quoted attribute value that holds ">": the one tag spelling the readers' own patterns
# cannot step over.
_XML_QUOTED_GT = re.compile(rb"""=\s*+(?:"[^"<>]*+>|'[^'<>]*+>)""")
_XML_DOCTYPE = re.compile(rb"<!DOCTYPE[^<>\[]*+\[(.*?)(?:\]|\Z)", re.DOTALL)
# An internal general entity with a literal value. Parameter entities (``%``) and external
# ones (SYSTEM, PUBLIC) have no literal here and are never read or fetched.
_XML_ENTITY = re.compile(
    rb"""<!ENTITY\s++([A-Za-z_:][\w.:-]{0,63}+)\s++(?:"([^"]{0,4096}+)"|'([^']{0,4096}+)')\s*+>"""
)
_XML_ENTITY_REF = re.compile(rb"&([A-Za-z_:][\w.:-]{0,63}+);")
_XML_CHAR_REF = re.compile(rb"&#(?:x([0-9A-Fa-f]{1,6})|([0-9]{1,7}));")
_XML_PREDEFINED = frozenset({b"amp", b"lt", b"gt", b"quot", b"apos"})
_XML_PROLOG_WINDOW = 64 * 1024
# Left where ``plain_xml`` took markup out of character data. U+0001 cannot occur in an XML
# 1.0 document, so a reader that finds it between two stretches of one text element knows the
# element was not contiguous in the part's raw bytes.
_XML_JOIN = b"\x01"
_MAX_XML_ENTITIES = 64
# Entity references may nest; a parser expands them all. Eight rounds is deeper than any text
# needs, and the growth cap ends a document written to expand without end.
_MAX_XML_ENTITY_ROUNDS = 8
_MAX_XML_ENTITY_GROWTH = 1024 * 1024


def _xml_char(match: re.Match[bytes]) -> bytes:
    code = int(match.group(1), 16) if match.group(1) else int(match.group(2))
    if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
        return match.group()
    return chr(code).encode("utf-8")


def _xml_entities(data: bytes) -> dict[bytes, bytes]:
    """The internal general entities a part declares, each as its replacement text.

    A character reference in a declared value is resolved when the entity is declared, so
    ``&#60;`` there is markup where the entity is used (XML 1.0, 4.4.5). The first declaration
    of a name is the binding one (4.2).
    """
    doctype = _XML_DOCTYPE.search(data, 0, _XML_PROLOG_WINDOW)
    if doctype is None:
        return {}
    entities: dict[bytes, bytes] = {}
    for match in _XML_ENTITY.finditer(doctype.group(1)):
        name = match.group(1)
        if name in _XML_PREDEFINED or name in entities:
            continue
        if len(entities) >= _MAX_XML_ENTITIES:
            raise ContentLimit("xml entities exceed 64")
        value = match.group(2) if match.group(2) is not None else match.group(3)
        entities[name] = _XML_CHAR_REF.sub(_xml_char, value)
    return entities


def utf8_xml(data: bytes) -> bytes:
    """A UTF-16 part as UTF-8; any other part as it is.

    An Office part may be UTF-8 or UTF-16 (ECMA-376 part 2), and a parser reads both alike,
    while the readers here match UTF-8 bytes. UTF-16 is known by its byte order mark or by
    the two-byte ``<?`` that opens an XML declaration without one.
    """
    if data[:2] == b"\xff\xfe" or data[:4] == b"<\x00?\x00":
        encoding = "utf-16-le"
    elif data[:2] == b"\xfe\xff" or data[:4] == b"\x00<\x00?":
        encoding = "utf-16-be"
    else:
        return data
    return data.decode(encoding, errors="replace").lstrip("\ufeff").encode("utf-8")


def xml_text(text: bytes) -> tuple[bytes, bool]:
    """Character data from ``plain_xml`` without its join marks, and whether one stood between
    two stretches of it: text that was split by markup and is contiguous only now."""
    if _XML_JOIN not in text:
        return text, False
    return text.replace(_XML_JOIN, b""), _XML_JOIN in text.strip(_XML_JOIN)


def plain_xml(data: bytes, budget: Budget) -> bytes:
    """``data`` as an XML parser hands its text on, for the readers that match tags by pattern.

    Comments, processing instructions, and the DOCTYPE are removed; a CDATA section becomes
    the escaped text it holds; ``>`` inside a quoted attribute value becomes ``&gt;``; and a
    reference to an entity the part's own DOCTYPE declares becomes that entity's text. So
    ``Ignore all <!-- -->previous``, ``<![CDATA[previous]]>``, and ``&w;`` are the words a
    parser gives pandoc, LibreOffice, or any library built on one. Each removal leaves
    ``_XML_JOIN``, which ``xml_text`` takes out again.

    A part that uses none of these is returned as it is, which is every part an office suite
    writes. Nothing external is read: an entity with a system or public identifier has no
    literal value and stays a reference.
    """
    if b"<!" not in data and data.find(b"<?", 1) < 0 and not _XML_QUOTED_GT.search(data):
        return data
    budget.check()
    entities = _xml_entities(data) if b"<!ENTITY" in data[:_XML_PROLOG_WINDOW] else {}
    for _ in range(_MAX_XML_ENTITY_ROUNDS if entities else 0):
        growth = sum(
            len(entities[match.group(1)]) + 2 - len(match.group())
            for match in _XML_ENTITY_REF.finditer(data)
            if match.group(1) in entities
        )
        if growth > _MAX_XML_ENTITY_GROWTH:
            raise ContentLimit("xml entity expansion exceeds 1MB")
        budget.check()
        expanded = _XML_ENTITY_REF.sub(
            lambda match: (
                _XML_JOIN + entities[match.group(1)] + _XML_JOIN
                if match.group(1) in entities
                else match.group()
            ),
            data,
        )
        if expanded == data:
            break
        if len(expanded) > len(data) + _MAX_XML_ENTITY_GROWTH:
            raise ContentLimit("xml entity expansion exceeds 1MB")
        data = expanded
    output = bytearray()
    position = 0
    for count, match in enumerate(_XML_NOISE.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        tag = match.group(2)
        if tag is not None and b">" not in tag[:-1]:
            continue
        output += data[position : match.start()]
        position = match.end()
        if tag is not None:
            output += tag[:-1].replace(b">", b"&gt;") + b">"
            continue
        output += _XML_JOIN
        if match.group(1) is not None:
            output += (
                match.group(1).replace(b"&", b"&amp;").replace(b"<", b"&lt;").replace(b">", b"&gt;")
            )
            output += _XML_JOIN
    output += data[position:]
    return bytes(output)


# A worksheet part, where Excel and streaming writers keep inline strings (t="inlineStr").
_SHEET_PART = re.compile(r"(?i)^xl/worksheets/[^/]+\.xml$")
_COMMENT_PART = re.compile(r"(?i)^(xl/comments\d*\.xml|ppt/comments/[^/]+\.xml)$")

# The namespaces the Office readers read, each in its transitional and its strict (ISO/IEC
# 29500, purl.oclc.org) spelling; the three Microsoft extensions have one. All but the last
# extension are the strings LibreOffice 24.2's own filter carries. The 2018 comment namespace
# is the one PowerPoint's modern comments declare (``p188``), which that filter does not read.
_WORD_NS = (
    b"http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    b"http://purl.oclc.org/ooxml/wordprocessingml/main",
)
_DRAWING_NS = (
    b"http://schemas.openxmlformats.org/drawingml/2006/main",
    b"http://purl.oclc.org/ooxml/drawingml/main",
)
_SHEET_NS = (
    b"http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    b"http://purl.oclc.org/ooxml/spreadsheetml/main",
)
_SLIDE_NS = (
    b"http://schemas.openxmlformats.org/presentationml/2006/main",
    b"http://purl.oclc.org/ooxml/presentationml/main",
)
_WORD_DRAWING_NS = (
    b"http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    b"http://purl.oclc.org/ooxml/drawingml/wordprocessingDrawing",
)
_SLIDE_2012_NS = (b"http://schemas.microsoft.com/office/powerpoint/2012/main",)
_SLIDE_COMMENT_NS = (b"http://schemas.microsoft.com/office/powerpoint/2018/8/main",)
_CHART_NS = (
    b"http://schemas.openxmlformats.org/drawingml/2006/chart",
    b"http://purl.oclc.org/ooxml/drawingml/chart",
)
_DIAGRAM_NS = (
    b"http://schemas.openxmlformats.org/drawingml/2006/diagram",
    b"http://purl.oclc.org/ooxml/drawingml/diagram",
)
_DIAGRAM_DRAWING_NS = (b"http://schemas.microsoft.com/office/drawing/2008/diagram",)
_SHEET_DRAWING_NS = (
    b"http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing",
    b"http://purl.oclc.org/ooxml/drawingml/spreadsheetDrawing",
)
# The prefix the readers' patterns match for each namespace: what Word, Excel, and PowerPoint
# write. SpreadsheetML is the default namespace there, so its elements carry no prefix. A
# parser resolves the namespace and never looks at the prefix, which is the writer's choice:
# ElementTree writes ``ns0:``, and the Open XML SDK writes SpreadsheetML under ``x:``.
_OOXML_PREFIX = {
    uri: prefix
    for prefix, namespace in (
        (b"w", _WORD_NS),
        (b"a", _DRAWING_NS),
        (b"", _SHEET_NS),
        (b"p", _SLIDE_NS),
        (b"wp", _WORD_DRAWING_NS),
        (b"p15", _SLIDE_2012_NS),
        (b"p188", _SLIDE_COMMENT_NS),
    )
    for uri in namespace
}
# Prefixes the readers take as an Office namespace by their spelling alone. ``x`` is one the
# hidden-text reader has always read as SpreadsheetML.
_OOXML_PREFIXES = frozenset(_OOXML_PREFIX.values()) | {b"x"}
# What ``_office_prefixes`` writes for an element that is spelled with one of those prefixes
# and is in some other namespace. No reader's pattern starts a prefix with "_".
_NOT_OFFICE = b"_"

# What a part is to the four readers. ``word``, ``strings``, and ``slide`` are the body text of
# each application; ``drawn`` is text a renderer draws from another part, whose runs are joined
# and whose hidden runs are not read; a ``sheet`` holds inline-string cells; and the two
# comment roles are read one comment at a time.
_TEXT_ROLES = frozenset({"word", "strings", "slide", "drawn"})
# The vocabulary whose run properties the hidden-text reader resolves in each role.
_HIDDEN_FAMILY = {
    "word": b"w",
    "slide": b"a",
    "slide-comments": b"a",
    "strings": b"x",
    "sheet": b"x",
    "sheet-comments": b"x",
}
# The element that holds one comment in each comment role.
_COMMENT_ELEMENT = {"sheet-comments": b"comment", "slide-comments": b"cm"}
# A part's role by its root element and that element's namespace, which is how LibreOffice,
# pandoc, python-docx, openpyxl, and python-pptx know a part: they reach it through a
# relationship and never look at its name. The notes master, the handout master, themes,
# settings, and styles are absent on purpose: nothing draws their text on a page or a slide.
# A Word or SpreadsheetML root that is not listed is asked what it holds (``_held_roles``).
_OOXML_ROOT_ROLE = {
    (uri, element): role
    for namespace, roles in (
        (
            _WORD_NS,
            {
                b"document": "word",
                b"hdr": "word",
                b"ftr": "word",
                b"footnotes": "word",
                b"endnotes": "word",
                b"comments": "word",
                b"glossaryDocument": "drawn",
            },
        ),
        (_SHEET_NS, {b"sst": "strings", b"worksheet": "sheet", b"comments": "sheet-comments"}),
        (
            _SLIDE_NS,
            {
                b"sld": "slide",
                b"notes": "slide",
                b"cmLst": "slide-comments",
                b"sldLayout": "drawn",
                b"sldMaster": "drawn",
            },
        ),
        (_SLIDE_COMMENT_NS, {b"cmLst": "slide-comments"}),
        (_CHART_NS, {b"chartSpace": "drawn"}),
        (_DIAGRAM_NS, {b"dataModel": "drawn"}),
        (_DIAGRAM_DRAWING_NS, {b"drawing": "drawn"}),
        (_SHEET_DRAWING_NS, {b"wsDr": "drawn"}),
    )
    for uri in namespace
    for element, role in roles.items()
}
# A UTF-8 byte order mark and white space, which may stand before a part's first tag.
_BEFORE_XML = b"\xef\xbb\xbf \t\r\n"


def _holds_markup(data: bytes) -> bool:
    """True when a part can hold a tag: one stands in its first kilobyte, or the part opens
    with one after white space of any length, which a parser reads past."""
    return b"<" in data[:1024] or data.lstrip(_BEFORE_XML)[:1] == b"<"


# Everything that may stand before the root element: the byte order mark, white space, the
# marks ``plain_xml`` leaves, the XML declaration and other processing instructions, comments,
# and a DOCTYPE, whose quoted literals may hold "]" and ">". Every alternative consumes what
# it reads and one that never closes runs to the end, so the prolog is read once however
# long it is: 16 MiB of comments took 0.2 s.
_XML_PROLOG = re.compile(
    rb"(?:[\s\x01]++|\xef\xbb\xbf|<\?.*?(?:\?>|\Z)|<!--.*?(?:-->|\Z)"
    rb"""|<!DOCTYPE(?:[^<>\["']++|"[^"]*+"|'[^']*+')*+"""
    rb"""(?:\[(?:[^\]"'<]++|"[^"]*+"|'[^']*+'|<!--.*?(?:-->|\Z)|<\?.*?(?:\?>|\Z)|<)*+\])?"""
    rb"[^<>]*+>)*+",
    re.DOTALL,
)
# An XML name is not only ASCII letters, so a prefix or an element name is whatever stands
# between the delimiters; a pattern that listed letters would step over a prefix written in
# any other script, which a parser resolves like any other.
_XML_NAME = rb"""[^\s<>/:="'!?][^\s<>/:="']*+"""
# The root element's start tag: prefix, local name, and attributes, whose quoted values may
# hold ">" when ``plain_xml`` has not been over them.
_XML_ROOT = re.compile(
    rb"<(?:(" + _XML_NAME + rb"):)?(" + _XML_NAME + rb""")((?:[^<>"']++|"[^"<]*+"|'[^'<]*+')*+)>"""
)
# One tag of a part ``plain_xml`` has been over: closing slash, prefix, local name, attributes.
_XML_TAG = re.compile(rb"<(/?)(?:(" + _XML_NAME + rb"):)?(" + _XML_NAME + rb")([^<>]*+)>")
# One attribute name and the value it is given, if any. Matched one after another from the
# start of a tag's attributes, so text inside a quoted value is never taken for a second
# attribute. A name is consumed whether or not a value follows: were the value required, every
# byte of a long run of name characters would be a new start that reads to the end of the run.
_XML_ATTRIBUTE_PAIR = re.compile(rb"""([^\s=<>"'/]++)(?:\s*+=\s*+(?:"([^"<]*+)"|'([^'<]*+)'))?""")
# A namespace declaration wherever it stands in a part. Every real one is matched; text that
# only looks like one can do no more than send the part to the slower, exact pass.
_XMLNS = re.compile(rb"""xmlns(?::([^\s=<>"'/:]++))?\s*+=\s*+(?:"([^"<>]*+)"|'([^'<>]*+)')""")
# An attribute-list declaration in a DOCTYPE (element name, then its attribute definitions),
# and a namespace declaration given a default value there. libxml2 and expat add a defaulted
# attribute to every element of that name, so ``<!ATTLIST x:r xmlns:x CDATA "...">`` binds
# ``x`` on each ``<x:r>`` with nothing written on the tag: LibreOffice, python-docx, and
# mammoth read such a run.
_XML_ATTLIST = re.compile(
    rb"""<!ATTLIST\s++([^\s<>/="'!?][^\s<>/="']*+)((?:[^<>"']++|"[^"<]*+"|'[^'<]*+')*+)>"""
)
_XMLNS_DEFAULT = re.compile(
    rb"""(?<!\S)xmlns(?::([^\s=<>"'/:]++))?\s++[^\s"'<>]++\s++(?:#FIXED\s++)?"""
    rb"""(?:"([^"<]*+)"|'([^'<]*+)')"""
)
# Elements open at once that each rebind a prefix. Word redeclares ``a`` on every picture, one
# level deep; a part nested past this was written to exhaust the pass, which keeps what each
# open element replaced until it closes.
_MAX_NAMESPACE_SCOPES = 256
# Namespace declarations a DOCTYPE may give by default in a part the Office readers resolve.
# Each is bound again on every tag of its element, so the pass costs this many steps a tag.
# No office suite writes a DOCTYPE at all.
_MAX_NAMESPACE_DEFAULTS = 8
# The start of a tag whose element stands under no prefix, for the renaming that needs no
# scopes (``_moved_everywhere``): the tag ``_XML_TAG`` reads with its prefix group empty.
_XML_TAG_UNPREFIXED = re.compile(
    rb"<(/?)(?!" + _XML_NAME + rb""":[^\s<>/:="'!?])(?=""" + _XML_NAME + rb"[^<>]*+>)"
)
# Prefixes moved by one replacement each over the whole part; a part that needs more is
# walked once, tag by tag. The eight prefixes the readers know by their spelling all move
# when a part binds none of them, which leaves as many again for the part's own.
_MAX_PREFIX_MOVES = 16
# The longest attributes a text, break, or boundary tag could have, in bytes, while the
# readers bounded them. A tag past this, or a text or paragraph end tag that holds white
# space, was not matched then.
_EARLIER_TAG_ATTRIBUTES = 4096
# The last letter of a text element's name, which stands before the ">" of its end tag unless
# white space does.
_END_OF_TEXT_NAME = ord("t")
# An element by its local name under any prefix, for the parts known by what they hold
# (``_held_roles``).
_BODY_ELEMENT = re.compile(rb"<(?:" + _XML_NAME + rb":)?body(?=[\s/>])")
_STRING_ELEMENT = re.compile(rb"<(?:" + _XML_NAME + rb":)?si(?=[\s/>])")
_SHEET_DATA_ELEMENT = re.compile(rb"<(?:" + _XML_NAME + rb":)?sheetData(?=[\s/>])")


def _namespace(value: bytes) -> bytes:
    """A namespace name as a parser hands it on: character references resolved.

    ``mai&#110;`` is ``main`` to every parser, so the comparison is made after the same step.
    """
    if b"&" not in value and _XML_JOIN not in value:
        return value
    return html.unescape(value.replace(_XML_JOIN, b"").decode("utf-8", "replace")).encode("utf-8")


def _xmlns_defaults(data: bytes) -> dict[bytes, dict[bytes, bytes]]:
    """The namespace declarations a part's own DOCTYPE gives an element by default: element
    name to prefix to namespace. Empty for every part an office suite writes.

    The first declaration of an attribute is the binding one (XML 1.0, 3.3). Only the
    internal subset is read, within the window the entity declarations are read in.
    """
    if b"<!ATTLIST" not in data[:_XML_PROLOG_WINDOW]:
        return {}
    doctype = _XML_DOCTYPE.search(data, 0, _XML_PROLOG_WINDOW)
    if doctype is None:
        return {}
    defaults: dict[bytes, dict[bytes, bytes]] = {}
    for declared in _XML_ATTLIST.finditer(doctype.group(1)):
        for binding in _XMLNS_DEFAULT.finditer(declared.group(2)):
            value = binding.group(2) if binding.group(2) is not None else binding.group(3)
            bound = defaults.setdefault(declared.group(1), {})
            bound.setdefault(binding.group(1) or b"", _namespace(value))
    return defaults


def _declared(attributes: bytes) -> dict[bytes, bytes]:
    """The namespace declarations among a tag's attributes: prefix (empty for the default
    namespace) to namespace name. The last of two for one prefix stands."""
    declared: dict[bytes, bytes] = {}
    for attribute in _XML_ATTRIBUTE_PAIR.finditer(attributes):
        name = attribute.group(1)
        value = attribute.group(2) if attribute.group(2) is not None else attribute.group(3)
        if value is not None and (name == b"xmlns" or name.startswith(b"xmlns:")):
            declared[name[6:]] = _namespace(value)
    return declared


def _named_role(name: str) -> str | None:
    lowered = name.lower()
    if _OOXML_TEXT_PART.match(name):
        return (
            "word"
            if lowered.startswith("word/")
            else "slide"
            if lowered.startswith("ppt/")
            else "strings"
        )
    if _OOXML_DRAWN_PART.match(name):
        return "drawn"
    if _SHEET_PART.match(name):
        return "sheet"
    if _COMMENT_PART.match(name):
        return "sheet-comments" if lowered.startswith("xl/") else "slide-comments"
    return None


def _root_roles(data: bytes, budget: Budget) -> tuple[str, ...]:
    """The roles of a part by its root element; none for anything that is not an Office part.

    The first 64 KiB is read, and the whole part only when the prolog and the root tag do not
    end inside that: white space or a comment of any length may stand before the root, and
    every reader reads past it. The root's prefix is resolved through the declarations on the
    root tag itself, or the one its DOCTYPE gives it by default, as a parser resolves it.
    Anything whose first byte after white space is not "<" is turned away there.

    Every scanned unit comes through here, most of them no Office part at all, so nothing in
    it ends a scan: a limit met while the root is looked at leaves the unit without a role by
    its root, which is how it was read before parts were known by their roots.
    """
    head = b""
    root = None
    for window in (_XML_PROLOG_WINDOW, len(data)):
        whole = window >= len(data)
        head = utf8_xml(data if whole else data[:window])
        budget.check()
        prolog = _XML_PROLOG.match(head)
        start = prolog.end() if prolog else 0
        root = _XML_ROOT.match(head, start)
        # Read on only where the window ended inside the prolog or inside a tag.
        if root is not None or whole or head[start : start + 1] not in (b"<", b""):
            break
    if root is None:
        return ()
    prefix, element, attributes = root.group(1) or b"", root.group(2), root.group(3)
    given = _xmlns_defaults(head).get(prefix + b":" + element if prefix else element, {})
    if b"xmlns" not in attributes and not given:
        return ()
    if b"&" in attributes:
        # A namespace name may be written through the part's own entities; ``plain_xml``
        # expands them as a parser does. Its tag is then the first one left.
        try:
            again = _XML_ROOT.search(plain_xml(head[: root.end()], budget))
        except ContentLimit:
            budget.check()
            return ()
        if again is None:
            return ()
        attributes = again.group(3)
    namespace = _declared(attributes).get(prefix, given.get(prefix, b""))
    role = _OOXML_ROOT_ROLE.get((namespace, element))
    if role is not None:
        return (role,)
    return _held_roles(namespace, data, budget)


def _held_roles(namespace: bytes, data: bytes, budget: Budget) -> tuple[str, ...]:
    """The roles of a part whose root is a Word or SpreadsheetML element that
    ``_OOXML_ROOT_ROLE`` does not list, by what the part holds.

    pandoc and mammoth reach the document part through its relationship and look in it for
    ``w:body``; openpyxl and pandas reach the shared strings and a worksheet the same way and
    look for ``si`` and for the cells of ``sheetData``. None of them asks what the root is
    called, so a body inside ``<w:doc>`` or ``<w:settings>`` is the document to them. A
    settings, styles, or numbering part holds no body, and a workbook or a style sheet no
    string and no sheet data, so those stay without a role. PresentationML is not read this
    way: a slide and a notes master hold the same ``p:cSld``.

    One search of the part for each element, by local name under any prefix.
    """
    word = namespace in _WORD_NS
    if not word and namespace not in _SHEET_NS:
        return ()
    text = utf8_xml(data)
    budget.check()
    if b"<!ENTITY" in text[:_XML_PROLOG_WINDOW]:
        # The element may be written through the part's own entity.
        try:
            text = plain_xml(text, budget)
        except ContentLimit:
            budget.check()
            return ()
    if word:
        return ("word",) if _BODY_ELEMENT.search(text) else ()
    roles = []
    if _STRING_ELEMENT.search(text):
        roles.append("strings")
    if _SHEET_DATA_ELEMENT.search(text):
        roles.append("sheet")
    return tuple(roles)


def _office_part(name: str, data: bytes, budget: Budget) -> _OfficePart:
    """What the Office readers take a unit for: by its name, and by its root element.

    The names are what Word, Excel, and PowerPoint write. A package may name a part anything,
    so ``word/document2.xml``, ``xl/strings.xml``, ``xl/comments/comment1.xml`` (openpyxl's own
    spelling), and ``ppt/pages/one.xml`` are known by their root. Where the two differ the part
    is read both ways, so a slide stored under a worksheet's name is still a slide. A loose
    XML file whose root is an Office element has a role too: an unzipped shared-strings part
    in a directory scan is the text it was inside the workbook.
    """
    held = budget.office_part
    if held is not None and held.name == name and held.data is data:
        return held
    roles = dict.fromkeys(
        role for role in (_named_role(name), *_root_roles(data, budget)) if role is not None
    )
    budget.office_part = _OfficePart(name, data, tuple(roles))
    return budget.office_part


def _part_text(part: _OfficePart) -> bytes:
    """The part's bytes as UTF-8, transcoded once."""
    if part.utf8 is None:
        part.utf8 = utf8_xml(part.data)
    return part.utf8


def _usual_prefix(prefix: bytes, namespace: bytes) -> bytes:
    """The prefix the readers' patterns match for an element written under ``prefix`` in
    ``namespace``: the usual one of an Office namespace, ``_NOT_OFFICE`` where a prefix the
    readers know by its spelling is bound to anything else, and otherwise the one written."""
    wanted = _OOXML_PREFIX.get(namespace)
    if wanted is None:
        return _NOT_OFFICE if prefix in _OOXML_PREFIXES else prefix
    return wanted


def _moved_everywhere(
    data: bytes, bindings: dict[bytes, bytes], budget: Budget
) -> tuple[bytes, set[tuple[bytes, bytes]]] | None:
    """``data`` with its prefixes moved as ``bindings`` say, where those hold for every
    element: all of them are declared on the root. None where that takes the exact pass.

    One replacement over the part for each prefix that moves, with no step of Python for
    each tag: a workbook the Open XML SDK wrote holds millions of ``x:`` tags. Once
    ``plain_xml`` has been over a part, "<" stands only where a tag opens, so ``<x:`` and
    ``</x:`` are every tag under ``x``. A prefix is moved only once nothing else is still to
    be moved onto it, so two prefixes that trade places (which have no such order) are left
    to the exact pass.
    """
    moves = {}
    for prefix in _OOXML_PREFIXES | bindings.keys():
        wanted = _usual_prefix(prefix, bindings.get(prefix, b""))
        if wanted != prefix:
            moves[prefix] = wanted
    if len(moves) > _MAX_PREFIX_MOVES:
        return None
    moved: set[tuple[bytes, bytes]] = set()
    while moves:
        source = next((source for source, target in moves.items() if target not in moves), None)
        if source is None:
            return None
        target = moves.pop(source)
        budget.check()
        given = target + b":" if target else b""
        if source:
            written = source + b":"
            renamed = data.replace(b"<" + written, b"<" + given)
            renamed = renamed.replace(b"</" + written, b"</" + given)
        else:
            renamed = _XML_TAG_UNPREFIXED.sub(rb"<\g<1>" + given, data)
        if renamed != data:
            moved.add((source, target))
            data = renamed
    return data, moved


def _office_prefixes(
    data: bytes, budget: Budget, defaults: dict[bytes, dict[bytes, bytes]] | None = None
) -> tuple[bytes, set[tuple[bytes, bytes]]]:
    """``data`` with every element of an Office namespace under the prefix the readers match,
    and each move made (the prefix written, the prefix given).

    An element's namespace is the one its prefix is bound to where the element stands: a
    declaration holds for its element and what that element contains (Namespaces in XML,
    section 6). So ``<ns0:t>`` and ``<x:t>`` bound to WordprocessingML become ``<w:t>``, and a
    ``<w:t>`` inside ``<w:r xmlns:w="urn:example:other">`` becomes ``<_:t>``: it is not a Word
    run to any reader, and read as one it would stand between two words of a sentence.

    Returned unchanged, as the same object, when every prefix has one binding in the part and
    the Office namespaces are bound to their usual prefixes, which is every part an office
    suite writes. A part whose declarations all stand on its root is moved without a walk
    (``_moved_everywhere``). Any other takes the exact pass: one walk over the tags, each read
    once. ``defaults`` are the declarations the part's DOCTYPE gives an element with nothing
    written on its tag (``_xmlns_defaults``).
    """
    seen: dict[bytes, bytes] = {}
    usual = True
    first = last = -1
    for count, match in enumerate(_XMLNS.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        prefix = match.group(1) or b""
        uri = _namespace(match.group(2) if match.group(2) is not None else match.group(3))
        if seen.setdefault(prefix, uri) != uri or _usual_prefix(prefix, uri) != prefix:
            usual = False
        if first < 0:
            first = match.start()
        last = match.end()
    if usual and not defaults:
        return data, set()
    if not defaults:
        prolog = _XML_PROLOG.match(data)
        root = _XML_ROOT.match(data, prolog.end() if prolog else 0)
        if (
            root is not None
            and root.start() <= first
            and last <= root.end()
            and not root.group(3).endswith(b"/")
        ):
            everywhere = _moved_everywhere(data, _declared(root.group(3)), budget)
            if everywhere is not None:
                return everywhere
    bindings: dict[bytes, bytes] = {}
    # Each open element that declared a namespace: its depth, and what it replaced.
    scopes: list[tuple[int, dict[bytes, bytes | None]]] = []
    depth = 0
    output = bytearray()
    position = 0
    moved: set[tuple[bytes, bytes]] = set()
    for count, match in enumerate(_XML_TAG.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        closing = bool(match.group(1))
        prefix = match.group(2) or b""
        attributes = match.group(4)
        # What this tag declares: written on it, or given to its element by the DOCTYPE.
        declared: dict[bytes, bytes] = {}
        if not closing:
            if b"xmlns" in attributes:
                declared = _declared(attributes)
            if defaults:
                given = defaults.get(prefix + b":" + match.group(3) if prefix else match.group(3))
                if given:
                    declared = {**given, **declared} if declared else given
        wanted = _usual_prefix(
            prefix, declared[prefix] if prefix in declared else bindings.get(prefix, b"")
        )
        if wanted != prefix:
            output += data[position : match.end(1)]
            if wanted:
                output += wanted + b":"
            position = match.start(3)
            moved.add((prefix, wanted))
        if closing:
            depth = max(depth - 1, 0)
            while scopes and scopes[-1][0] >= depth:
                for bound, replaced in scopes.pop()[1].items():
                    if replaced is None:
                        bindings.pop(bound, None)
                    else:
                        bindings[bound] = replaced
        elif not attributes.endswith(b"/"):
            # An empty element holds nothing, so what it declares ends with its own tag.
            if declared:
                if len(scopes) >= _MAX_NAMESPACE_SCOPES:
                    raise ContentLimit("ooxml namespace scopes exceed 256")
                scopes.append((depth, {bound: bindings.get(bound) for bound in declared}))
                bindings.update(declared)
            depth += 1
    if not position:
        return data, set()
    output += data[position:]
    return bytes(output), moved


def _office_readings(part: _OfficePart, budget: Budget) -> _OfficeReadings:
    """A part as the readers should take it: under the usual prefixes, and as it is written.

    The first is what a parser sees. The second is what these readers took before they
    resolved a namespace, kept so that nothing they held is lost; it is absent when the two
    are the same bytes, which is nearly always. Worked out once for a part, whichever reader
    asks first.
    """
    if part.readings is None:
        data = _part_text(part)
        defaults = _xmlns_defaults(data)
        if sum(len(bound) for bound in defaults.values()) > _MAX_NAMESPACE_DEFAULTS:
            raise ContentLimit("xml namespace defaults exceed 8")
        data = plain_xml(data, budget)
        resolved, moved = _office_prefixes(data, budget, defaults)
        part.readings = _OfficeReadings(
            resolved, None if resolved is data else data, moved <= {(b"x", b"")}
        )
    return part.readings


def _text_tag_as_before(match: re.Match[bytes], name_end: int, text_start: int) -> bool:
    """True when a text element is spelled as the readers always matched it: its end tag
    holds no white space and its start tag at most 4,096 bytes of attributes.

    ``name_end`` is where the start tag's name ends and ``text_start`` where its text begins.
    The readers stepped over any other spelling as if the element were not there, so a
    reading that leaves such elements out is the reading they gave.
    """
    return (
        text_start - 1 - name_end <= _EARLIER_TAG_ATTRIBUTES + 1
        and not match.group()[-2:-1].isspace()
    )


def _joined_runs(data: bytes, budget: Budget) -> tuple[list[str], int]:
    """A part's runs in order, in each reading it has, and how many text elements it held.

    The first reading is the text as a reader lays it out. A DrawingML line break is a new
    line, as python-pptx, LibreOffice, and markitdown show it. A phonetic run's text (``rPh``,
    the furigana beside a cell's text) is no part of the string to openpyxl, pandas, or
    LibreOffice. A run belongs to its paragraph when both are of one vocabulary: a DrawingML
    or SpreadsheetML text element written between two Word runs, or one in no namespace, is
    no run of that paragraph to python-docx, pandoc, or LibreOffice.

    The readers here used to join the runs on both sides of a DrawingML break, to take
    every text element in turn, and to step over a text, break, or paragraph-end tag spelled
    with white space in an end tag or more than 4,096 bytes of attributes. A part where any
    of that differs is given a second time in that earlier reading, whole and in its own
    order, so a sentence it held is still held: a junk text element in a run's properties,
    which no reader shows, parts two words in the first reading whenever it is spelled as a
    tag these patterns now match. The two are scanned apart: laid end to end, the last line
    of one and the first of the other would be a sentence no reader shows.
    """
    shown: list[str] = []
    # The part as it was read before, from the first token that reads differently.
    earlier: list[str] | None = None
    # Where the text runs of the open paragraphs stand in ``shown``, each with its prefix, and
    # for each open paragraph how many of them stood before it opened.
    written: list[tuple[int, bytes]] = []
    opened: list[int] = []
    unmarked = 0
    runs = 0
    phonetic = False
    for count, match in enumerate(_OOXML_TOKEN.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        token = match.group()
        text = match.group(2)
        if text is not None:
            # A run that markup had split is two runs' worth: not contiguous in the raw bytes.
            text, joined = xml_text(text)
            runs += 2 if joined else 1
            piece = html.unescape(text.decode("utf-8", errors="replace"))
            start = match.start()
            before = (
                data[match.end() - 2] == _END_OF_TEXT_NAME
                and match.start(2) - start <= _EARLIER_TAG_ATTRIBUTES
            ) or _text_tag_as_before(match, start + len(match.group(1)) + 2, match.start(2))
            if (phonetic or not before) and earlier is None:
                earlier = list(shown)
            if not phonetic:
                if opened:
                    written.append((len(shown), match.group(1)))
                shown.append(piece)
            if earlier is not None and before:
                earlier.append(piece)
            continue
        if match.group(3) is not None:
            phonetic = not match.group(3) and not token.endswith(b"/>")
            continue
        if match.group(4) is not None:
            if token.endswith(b"/>"):
                continue
            if len(opened) < _MAX_PARAGRAPH_NESTING:
                opened.append(len(written))
            else:
                unmarked += 1
            continue
        if token.startswith(b"<a:"):
            if earlier is None:
                earlier = list(shown)
            shown.append("\n")
            continue
        # A paragraph end that holds white space, or a break or tab with longer attributes
        # than were read, is no token of the earlier reading.
        before = (
            not token[-2:-1].isspace()
            if token.startswith(b"</")
            else len(token) - len(b"<w:br>") - token.startswith(b"<w:tab")
            <= _EARLIER_TAG_ATTRIBUTES
        )
        if not before and earlier is None:
            earlier = list(shown)
        if token.startswith(b"</"):
            if unmarked:
                unmarked -= 1
            elif opened:
                # ``</w:p>`` ends a Word paragraph, ``</a:p>`` a DrawingML one, ``</si>`` a
                # string. A run of this paragraph under any other prefix is not one of its own.
                own = token[2:4] if token[3:4] == b":" else b""
                first = opened.pop()
                other = [index for index, prefix in written[first:] if prefix != own]
                if other:
                    if earlier is None:
                        earlier = list(shown)
                    for index in other:
                        shown[index] = ""
                del written[first:]
            phonetic = False
        piece = "\t" if token.startswith(b"<w:tab") else "\n"
        shown.append(piece)
        if earlier is not None and before:
            earlier.append(piece)
    readings = ["".join(shown)]
    if earlier is not None:
        readings.append("".join(earlier))
    return readings, runs


def ooxml_text_views(name: str, data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    """Join the text runs of a Word, Excel, or PowerPoint XML part into an ``ooxml-text`` view.

    Only the parts a reader sees are joined (document body, headers, footers, notes, comments,
    shared strings, slides, and the layout, master, diagram, chart, and drawing parts a
    renderer draws from), each known by its name or by its root element (``_office_part``).
    Runs are elements of the Office namespaces under any prefix (``_office_prefixes``). Runs
    inside one paragraph are joined without a separator, paragraphs end with a newline, breaks
    and tabs become whitespace, and XML entities are decoded. No XML parser runs; ``plain_xml``
    first removes what one would (comments, CDATA wrappers, the part's own internal entities),
    and nothing external is read. A part with fewer than two runs is left to the raw and
    HTML-unescaped views of the member itself.

    Nearly every part has one reading and so one view. A part that readers take differently
    (``_joined_runs``), or whose prefixes had to be resolved (``_office_readings``), gives one
    view for each distinct reading, all named ``ooxml-text``.
    """
    part = _office_part(name, data, budget)
    if not _TEXT_ROLES.intersection(part.roles) or not _holds_markup(_part_text(part)):
        return
    readings = _office_readings(part, budget)
    views: list[str] = []
    for reading in (readings.resolved, readings.written):
        if reading is not None:
            texts, runs = _joined_runs(reading, budget)
            if runs >= 2:
                views += [lines for lines in texts if lines not in views]
    for lines in views:
        yield from _with_folded("ooxml-text", lines, budget)


# Cell/comment boundaries, phonetic runs, paragraph breaks, and text runs (prefix and text), in
# order. Attributes are possessive and stop at the next tag, however long they are.
_CELL_TOKEN = re.compile(
    rb"<(/?)(?:[A-Za-z][\w.-]{0,32}+:)?(is|rPh|comment|cm|p|br)\b[^<>]*+>"
    rb"|<(?:([A-Za-z][\w.-]{0,32}+):)?t(?:\s[^<>]*+)?>([^<]*+)"
    rb"</(?:[A-Za-z][\w.-]{0,32}+:)?t\s*+>"
)
# The prefixes of a text run in a cell or a comment once ``_office_prefixes`` has resolved
# them: SpreadsheetML, DrawingML in a PowerPoint comment, and ``x`` as it is spelled.
_CELL_TEXT_PREFIXES = frozenset({None, b"a", b"x"})
# About 70 microseconds a piece, so the cap stays well inside the 30 s scan deadline.
MAX_TEXT_PIECES = 100_000


def _more_pieces(pieces: list[str], further: list[str]) -> list[str]:
    """``pieces``, then each of ``further`` that is not among them: a second reading of a part
    adds only what the first did not give."""
    if not pieces or not further:
        return pieces or further
    seen = set(pieces)
    pieces += [piece for piece in dict.fromkeys(further) if piece not in seen]
    if len(pieces) > MAX_TEXT_PIECES:
        raise ContentLimit("text pieces exceed 100000")
    return pieces


def _each_reading(
    readings: _OfficeReadings, read: Callable[[bytes, bool], tuple[list[str], bool]]
) -> list[str]:
    """The pieces ``read`` finds in every reading of a part, in the order found.

    ``read`` takes one reading and whether to read it as it was read before the tag spellings
    were widened, and says whether it met a tag that is read differently now. The part as
    written is read last, and once more that earlier way when it holds such a tag, so every
    piece these readers gave before is still given. It is left out when it differs from the
    resolved part only in ``x:`` for no prefix: these readers take both for SpreadsheetML, so
    it would give the same pieces at the cost of a second pass over a large workbook.
    """
    texts = [readings.resolved]
    if readings.written is not None and not readings.moved_from_x_only:
        texts.append(readings.written)
    pieces: list[str] = []
    respelled = False
    for text in texts:
        found, respelled = read(text, False)
        pieces = _more_pieces(pieces, found)
    if respelled:
        pieces = _more_pieces(pieces, read(texts[-1], True)[0])
    return pieces


def _pieces_each_way(part: _OfficePart, budget: Budget, elements: Iterable[bytes]) -> list[str]:
    """The pieces of every reading of a part, for each boundary element in turn."""
    readings = _office_readings(part, budget)
    pieces: list[str] = []
    for element in elements:

        def read(text: bytes, earlier: bool, element: bytes = element) -> tuple[list[str], bool]:
            return _ooxml_pieces(text, budget, element, earlier)

        pieces = _more_pieces(pieces, _each_reading(readings, read))
    return pieces


def ooxml_cell_texts(name: str, data: bytes, budget: Budget) -> list[str]:
    """The text of each worksheet inline-string cell that is split across two or more runs.

    A cell whose text sits in one run is contiguous in the part's raw bytes already. Each cell is
    its own piece, so text from two cells is never joined into one phrase. Phonetic runs (rPh,
    the furigana a Japanese cell carries) are not part of the shown text. One linear pass over
    the tags; no XML parser runs and no entity is expanded beyond the predefined and numeric
    ones.
    """
    part = _office_part(name, data, budget)
    if "sheet" not in part.roles:
        return []
    data = _part_text(part)
    # An inline string is an ``is`` element. The cell type that announces it (t="inlineStr")
    # can be written with a character reference, so the element itself is looked for; and
    # the element can come from the part's own entity, which only ``plain_xml`` writes out.
    if (
        b"<is" not in data
        and b":is" not in data
        and b"inlineStr" not in data
        and b"<!ENTITY" not in data[:_XML_PROLOG_WINDOW]
    ):
        return []
    return _pieces_each_way(part, budget, (b"is",))


def ooxml_comment_texts(name: str, data: bytes, budget: Budget) -> list[str]:
    """Join rich-text runs within each Excel or modern PowerPoint comment, never across comments."""
    part = _office_part(name, data, budget)
    elements = [_COMMENT_ELEMENT[role] for role in part.roles if role in _COMMENT_ELEMENT]
    if not elements:
        return []
    return _pieces_each_way(part, budget, elements)


# A whole text element (``<w:t>``, ``<a:t>``, ``<t>``: its prefix and text), or one other tag
# (closing slash, prefix, local name, and bounded attributes). Every quantifier is possessive
# and stops at the next "<" or ">", so a tag that never closes costs one attempt that ends
# where the next begins; text outside a text element is skipped by the regex engine. A text
# tag's attributes are not read and so not bounded, and its end tag may hold white space, as
# in ``_OOXML_TOKEN``. Any other tag's attributes are parsed, and stay within 4,096 bytes.
_XML_TOKEN = re.compile(
    rb"<!--.*?(?:-->|\Z)|"
    rb"<(?:([A-Za-z][\w.-]{0,32}+):)?t(?:\s[^<>]*+)?>([^<]*+)</(?:[A-Za-z][\w.-]{0,32}+:)?t\s*+>"
    rb"|<(/?)(?:([A-Za-z][\w.-]{0,32}+):)?([A-Za-z][\w.-]{0,64}+)([^<>]{0,4096}+)>",
    re.DOTALL,
)
# The text-element prefix each family reads: Word's own runs, DrawingML runs, SpreadsheetML.
# ``_office_prefixes`` has put every element of those namespaces under these prefixes.
_TEXT_PREFIXES = {b"w": (b"w",), b"a": (b"a",), b"x": (b"", b"x")}
_XML_ATTRIBUTE = re.compile(
    rb"""([\w.-]{1,32}+:)?([\w.-]{1,64}+)\s*+=\s*+(?:"([^"]{0,256}+)"|'([^']{0,256}+)')"""
)
_OFF = frozenset({b"0", b"false", b"off"})
# Word shading values that leave the background as it was.
_NO_PATTERN = frozenset({b"", b"clear", b"nil"})
# Shapes whose non-visual properties can carry hidden="1": every text frame inside one is hidden.
_PPT_SHAPES = frozenset({b"sp", b"grpSp", b"graphicFrame", b"cxnSp", b"pic", b"contentPart"})
# Substrings of every element or attribute name that can hide text: (spec)Vanish, webHidden,
# sz, color, hidden, and show.
_HIDING_NAMES = (b"anish", b"webHidden", b"sz", b"color", b"hidden", b"show")
# The run properties that can hide text or show white text; every other one is skipped unread.
_RUN_PROPERTIES = frozenset(
    {b"vanish", b"specVanish", b"webHidden", b"sz", b"color", b"shd", b"highlight"}
)
# Where a hidden piece ends regardless of what follows: a table cell, a text box or shape's text
# body, a shared or inline string, and a comment. Paragraph ends inside these join with a newline.
_HIDDEN_FRAME_ENDS = frozenset({b"tc", b"txbxContent", b"txBody", b"si", b"is", b"comment", b"cm"})


def _near_white(value: bytes | None) -> bool:
    """True for an RGB or ARGB hex colour whose every channel is at least 0xF0."""
    if value is None or len(value) not in (6, 8):
        return False
    try:
        channels = bytes.fromhex(value[-6:].decode("ascii"))
    except ValueError:
        return False
    return min(channels) >= 0xF0


def _int_value(value: bytes | None) -> int | None:
    if value is None or not value.isdigit() or len(value) > 9:
        return None
    return int(value)


@dataclass
class _Run:
    """The explicit properties of one OOXML text run that decide whether it is shown."""

    hidden: bool = False
    white: bool = False
    shaded: bool = False


def ooxml_hidden_texts(name: str, data: bytes, budget: Budget) -> list[str]:
    """The text of runs a reader does not show, one piece per stretch of hidden runs.

    Read from a run's own properties, a shape's, or a slide's: Word ``w:vanish``,
    ``w:specVanish``, and ``w:webHidden``, a ``w:sz`` of 1 pt or less, and a near-white
    ``w:color`` unless the run, paragraph, table cell, table, or page is shaded; DrawingML text
    of 1 pt or less (``a:rPr sz`` up to 100), every text frame of a PowerPoint shape or group
    marked ``hidden="1"``, and every frame of a slide with ``show="0"``; SpreadsheetML rich-text
    runs of 1 pt or less or in near-white (an RGB value, or theme colour 0, which Excel maps to
    the light background). A tracked change's earlier properties (``w:rPrChange``) and a
    paragraph mark's properties do not count. Styles, list styles, layouts, masters, cell
    formats, and hidden sheets, rows, and columns live in other parts and are not resolved.

    A piece ends at the next shown text that is not whitespace, at a table cell, text box,
    shape, string, or comment end, and at the end of the part; paragraph ends inside it are a
    newline. So hidden text on both sides of a shown word is never joined. A DrawingML line
    break inside a piece is a newline, and the piece is also given with its lines joined, as
    this reader gave it before the break was read. One linear pass over bounded tags; no XML
    parser runs and no entity is expanded beyond the predefined and numeric ones.

    The vocabulary read (Word, DrawingML, or SpreadsheetML) follows from what the part is
    (``_office_part``), not from the folder it is stored in, and elements are taken by their
    namespace under any prefix (``_office_prefixes``).
    """
    part = _office_part(name, data, budget)
    families = dict.fromkeys(_HIDDEN_FAMILY[role] for role in part.roles if role in _HIDDEN_FAMILY)
    if not families:
        return []
    data = _part_text(part)
    if not _holds_markup(data):
        return []
    # Every signal below needs one of these names in the part; without any, nothing is hidden.
    if not any(name in data for name in _HIDING_NAMES):
        return []
    readings = _office_readings(part, budget)
    pieces: list[str] = []
    for family in families:

        def read(text: bytes, earlier: bool, family: bytes = family) -> tuple[list[str], bool]:
            return _hidden_pieces(text, family, budget, earlier)

        pieces = _more_pieces(pieces, _each_reading(readings, read))
    return pieces


def _hidden_pieces(
    data: bytes, family: bytes, budget: Budget, earlier: bool = False
) -> tuple[list[str], bool]:
    """The hidden pieces of one reading of a part, in one vocabulary, and whether the part
    holds a text element spelled as this reader did not match it before (white space in its
    end tag, or long attributes). With ``earlier`` such an element is stepped over, as it
    was: hidden words on both sides of one are then one piece again."""
    pieces: list[str] = []
    respelled = False
    current: list[str] = []
    # Where ``current`` holds a DrawingML line break.
    drawn_breaks: list[int] = []
    hidden_chars = False
    runs: list[_Run] = []
    paragraphs: list[bool] = []
    containers: list[bool] = []
    shapes: list[bool] = []
    part_hidden = False
    page_shaded = False
    rpr = ppr = tcpr = tblpr = change = phonetic = 0

    def flush() -> None:
        nonlocal hidden_chars
        if hidden_chars:
            if len(pieces) >= MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")
            pieces.append("".join(current).strip())
            if drawn_breaks:
                # The same piece as it was read before a DrawingML break was a new line.
                for index in drawn_breaks:
                    current[index] = ""
                joined = "".join(current).strip()
                if joined != pieces[-1]:
                    pieces.append(joined)
        current.clear()
        drawn_breaks.clear()
        hidden_chars = False

    def attributes(raw: bytes) -> dict[bytes, bytes]:
        found: dict[bytes, bytes] = {}
        for match in _XML_ATTRIBUTE.finditer(raw):
            value = match.group(3) if match.group(3) is not None else match.group(4)
            found.setdefault(match.group(2), value or b"")
        return found

    def run_property(local: bytes, raw: bytes, run: _Run) -> None:
        if local not in _RUN_PROPERTIES:
            return
        values = attributes(raw)
        if family == b"w":
            if local in (b"vanish", b"specVanish", b"webHidden"):
                run.hidden = run.hidden or values.get(b"val", b"1").lower() not in _OFF
            elif local == b"sz":
                size = _int_value(values.get(b"val"))
                run.hidden = run.hidden or (size is not None and size <= 2)
            elif local == b"color":
                run.white = _near_white(values.get(b"val"))
            elif local == b"shd":
                run.shaded = run.shaded or _shaded(values)
            elif local == b"highlight":
                run.shaded = run.shaded or values.get(b"val", b"none") not in (b"none", b"white")
        elif family == b"x":
            if local == b"sz":
                size = _int_value(values.get(b"val", b"").split(b".")[0])
                run.hidden = run.hidden or (size is not None and size <= 1)
            elif local == b"color":
                theme = values.get(b"theme")
                tint = values.get(b"tint", b"0")
                light = theme == b"0" and not tint.startswith(b"-")
                run.white = _near_white(values.get(b"rgb")) or light

    text_prefixes = _TEXT_PREFIXES[family]
    for count, match in enumerate(_XML_TOKEN.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        text = match.group(2)
        if text is not None:
            name_end = match.end(1) + 2 if match.group(1) else match.start() + 2
            if not _text_tag_as_before(match, name_end, match.start(2)):
                respelled = True
                if earlier:
                    continue
            if phonetic or change or (match.group(1) or b"") not in text_prefixes:
                continue
            piece = html.unescape(xml_text(text)[0].decode("utf-8", errors="replace"))
            run = runs[-1] if runs else _Run()
            hidden = (
                part_hidden
                or (shapes and shapes[-1])
                or run.hidden
                or (
                    run.white
                    and not (
                        run.shaded
                        or (paragraphs and paragraphs[-1])
                        or (containers and containers[-1])
                    )
                    and not page_shaded
                )
            )
            if hidden:
                current.append(piece)
                hidden_chars = hidden_chars or bool(piece.strip())
            elif piece.strip():
                flush()
            elif hidden_chars:
                current.append(piece)
            continue
        closing = bool(match.group(3))
        prefix = match.group(4) or b""
        local = match.group(5)
        if local is None:
            continue  # XML comments do not change the document's formatting state.
        raw = match.group(6)
        empty = raw.endswith(b"/")
        if family == b"x" and prefix not in (b"", b"x"):
            continue
        if family in (b"w", b"a") and prefix not in (family, b"p", b"wp", b"p188", b"p15"):
            continue
        if local.endswith(b"PrChange") and not empty:
            change += -1 if closing else 1
            change = max(change, 0)
            continue
        if change or local == b"t":
            # An empty or unclosed text element holds no text this reader takes.
            continue
        if closing:
            if local in (b"r", b"fld") and runs:
                runs.pop()
            elif local == b"rPr":
                rpr = max(rpr - 1, 0)
            elif local == b"pPr":
                ppr = max(ppr - 1, 0)
            elif local == b"tcPr":
                tcpr = max(tcpr - 1, 0)
            elif local == b"tblPr":
                tblpr = max(tblpr - 1, 0)
            elif local == b"rPh":
                phonetic = max(phonetic - 1, 0)
            elif local == b"p" and prefix in (b"w", b"a"):
                if paragraphs:
                    paragraphs.pop()
                if hidden_chars:
                    current.append("\n")
            elif local in (b"tc", b"tbl") and prefix == b"w" and containers:
                containers.pop()
                if local == b"tc":
                    flush()
            elif local in _PPT_SHAPES and prefix == b"p" or local in (b"anchor", b"inline"):
                if shapes:
                    shapes.pop()
            if local in _HIDDEN_FRAME_ENDS:
                flush()
            continue
        if local in (b"r", b"fld") and prefix in (b"w", b"a", b"", b"x") and not empty:
            runs.append(_Run())
        elif local == b"rPr":
            if not empty:
                rpr += 1
            if family == b"a" and runs and not ppr:
                size = _int_value(attributes(raw).get(b"sz"))
                runs[-1].hidden = runs[-1].hidden or (size is not None and size <= 100)
        elif local == b"pPr" and not empty:
            ppr += 1
        elif local == b"tcPr" and not empty:
            tcpr += 1
        elif local == b"tblPr" and not empty:
            tblpr += 1
        elif local == b"rPh" and not empty:
            phonetic += 1
        elif local == b"p" and prefix in (b"w", b"a") and not empty:
            paragraphs.append(False)
        elif local in (b"tc", b"tbl") and prefix == b"w" and not empty:
            containers.append(bool(containers and containers[-1]))
        elif (local in _PPT_SHAPES and prefix == b"p" or local in (b"anchor", b"inline")) and (
            not empty
        ):
            shapes.append(bool(shapes and shapes[-1]))
        elif local in (b"cNvPr", b"docPr") and shapes:
            flag = attributes(raw).get(b"hidden", b"0").lower()
            shapes[-1] = shapes[-1] or flag in (b"1", b"true", b"on")
        elif local == b"sld" and prefix == b"p":
            part_hidden = attributes(raw).get(b"show", b"1").lower() in _OFF
        elif local == b"background" and prefix == b"w":
            color = attributes(raw).get(b"color")
            page_shaded = color is not None and color != b"auto" and not _near_white(color)
        elif local in (b"br", b"cr") and runs and not rpr:
            if hidden_chars:
                current.append("\n")
        elif local == b"br" and prefix == b"a" and family == b"a" and paragraphs and not rpr:
            # DrawingML writes a line break beside the runs of a paragraph, not inside one.
            if hidden_chars:
                drawn_breaks.append(len(current))
                current.append("\n")
        elif local == b"tab" and runs and not rpr and not ppr:
            if hidden_chars:
                current.append("\t")
        elif rpr and not ppr and runs:
            run_property(local, raw, runs[-1])
        elif local == b"shd" and family == b"w":
            shaded = _shaded(attributes(raw))
            if ppr and not rpr and paragraphs:
                paragraphs[-1] = paragraphs[-1] or shaded
            elif (tcpr or tblpr) and containers:
                containers[-1] = containers[-1] or shaded
    flush()
    return [piece for piece in pieces if piece], respelled


def _shaded(values: dict[bytes, bytes]) -> bool:
    """True when a Word ``w:shd`` paints a background that is not near-white."""
    fill = values.get(b"fill")
    if fill is not None and fill.lower() != b"auto" and not _near_white(fill):
        return True
    pattern = values.get(b"val", b"").lower()
    color = values.get(b"color", b"auto")
    return pattern not in _NO_PATTERN and not _near_white(color)


def _ooxml_pieces(
    data: bytes, budget: Budget, boundary: bytes, earlier: bool = False
) -> tuple[list[str], bool]:
    """The text of each ``boundary`` element (a cell's inline string, a comment) with two or
    more runs, and whether the part holds a tag this reader did not match before.

    A run under a prefix of some other vocabulary (``<q:t>`` in a worksheet) is no part of
    the cell to LibreOffice, and written between two words it would part them. The piece is
    given without such runs, and with them as well, which is how it was always read.

    A text element with white space in its end tag, and any tag here with more than 4,096
    bytes of attributes, used to be stepped over. With ``earlier`` they are again, and runs
    of another vocabulary are kept, which is the reading this function gave then.
    """
    cells: list[str] = []
    respelled = False
    runs: list[bytes] = []
    # Where ``runs`` holds a run of another vocabulary, and how many runs that accounts for.
    foreign: list[int] = []
    count_foreign = 0
    inside = phonetic = False
    count_runs = 0

    def piece(kept: Iterable[bytes]) -> None:
        if len(cells) >= MAX_TEXT_PIECES:
            raise ContentLimit("text pieces exceed 100000")
        cells.append("".join(html.unescape(run.decode("utf-8", "replace")) for run in kept))

    for count, match in enumerate(_CELL_TOKEN.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        closing, tag, text = match.group(1), match.group(2), match.group(4)
        if text is None:
            before = match.end() - 1 - match.end(2) <= _EARLIER_TAG_ATTRIBUTES
        else:
            name_end = match.end(3) + 2 if match.group(3) else match.start() + 2
            before = _text_tag_as_before(match, name_end, match.start(4))
        if not before:
            respelled = True
            if earlier:
                continue
        if tag == b"rPh":
            phonetic = not closing and not match.group().endswith(b"/>")
        elif tag == boundary:
            if closing and inside:
                if foreign and not earlier and count_runs - count_foreign >= 2:
                    skipped = set(foreign)
                    piece(run for index, run in enumerate(runs) if index not in skipped)
                if count_runs >= 2:
                    piece(runs)
            inside = not closing and not match.group().endswith(b"/>")
            runs = []
            foreign = []
            count_runs = count_foreign = 0
            phonetic = False
        elif inside and (tag == b"p" and closing or tag == b"br"):
            runs.append(b"\n")
        elif inside and not phonetic and text is not None:
            text, joined = xml_text(text)
            if match.group(3) not in _CELL_TEXT_PREFIXES:
                foreign.append(len(runs))
                count_foreign += 2 if joined else 1
            runs.append(text)
            count_runs += 2 if joined else 1
    return cells, respelled


_HTML_OPENER = re.compile(r"<(?:!doctype\s+(?:html|svg)\b|html\b|svg\b)", re.I)
_HTML_SUFFIXES = frozenset({"html", "htm", "xhtml", "svg"})
# A comment opener, a tag (bounded, and never across another <), a declaration or processing
# instruction, a text run, a run of < that cannot open a tag with the text after it, or a lone <.
# A tag's attributes: a quoted value may hold < or >, as in title="<script>"; every quantifier is
# possessive, so a tag that does not close fails without backtracking.
_HTML_ATTRIBUTES = r"""(?:[^<>"'=]++|=\s*+"[^"]{0,4096}+"|=\s*+'[^']{0,4096}+'|[="']){0,4096}+"""
_HTML_TOKEN = re.compile(
    r"<!--|<(/?)([A-Za-z][A-Za-z0-9:-]{0,64})\b" + _HTML_ATTRIBUTES + r">|<[!?][^<>]{0,4096}>"
    r"|[^<]+|(?:<(?![A-Za-z/!?]))+[^<]*|<"
)
# Elements whose body is not markup: script and style are not shown, and a textarea or title
# shows its body as written, so a <script> or <b> inside one is text, never a tag.
_HTML_RAW_TEXT = {
    tag: re.compile(rf"</{tag}\s*>", re.I) for tag in ("script", "style", "textarea", "title")
}
_SVG_MARKER = re.compile(rb"</?svg\b", re.I)
# Only accept unambiguous tag syntax for the YARA scope exception. In HTML an unquoted
# value consumes a trailing slash, while a slash after a quoted value can close an SVG.
_SCOPE_TAG = re.compile(
    rb"""<(/?)([a-zA-Z][a-zA-Z0-9:-]{0,63}+)(?:[ \t\r\n\f]++[^\s"'<>/=]++"""
    rb"""(?:[ \t\r\n\f]*+=[ \t\r\n\f]*+(?:"[^"]*+"|'[^']*+'|[^\s"'=<>` ]++))?)*+"""
    rb"""[ \t\r\n\f]*+(/?)>"""
)
_SCOPE_DOCTYPE = re.compile(rb"<!doctype[ \t\r\n\f]+html[ \t\r\n\f]*>", re.I)
_SCOPE_RAW_END = {
    name.encode(): re.compile(rb"</" + name.encode() + rb"[ \t\r\n\f]*>", re.I)
    for name in (*_HTML_RAW_TEXT, "xmp", "iframe", "noembed", "noframes")
}
_SCOPE_AMBIGUOUS = frozenset({b"foreignobject", b"select", b"plaintext", b"noscript", b"math"})


def svg_scope_proven(data: bytes) -> bool:
    """Whether raw SVG delimiters can safely narrow the bundled active-content rules.

    Decline the exception on ambiguous markup or budget exhaustion. The rules then keep
    their strict match on the original bytes.
    """
    if len(data) > 1 << 20 or (marker := _SVG_MARKER.search(data)) is None:
        return False
    if data.count(b"<") > 4096:
        return False
    stack: list[bytes] = []
    position = 0
    while marker is not None:
        start = data.find(b"<", position, marker.start() + 1)
        if data.startswith(b"<!--", start):
            end = data.find(b"-->", start + 4)
            if (
                end < 0
                or marker.start() < end
                or data.startswith((b">", b"->"), start + 4)
                or data.find(b"--", start + 4, end) >= 0
            ):
                return False
            position = end + 3
            continue
        if (doctype := _SCOPE_DOCTYPE.match(data, start)) is not None:
            position = doctype.end()
            continue
        tag = _SCOPE_TAG.match(data, start)
        if tag is None:
            return False
        position = tag.end()
        closing, name, self_close = tag.groups()
        name = name.lower()
        lexeme = tag.group()
        if name in _SCOPE_AMBIGUOUS or (name == b"title" and stack):
            return False
        if marker.start() < position:
            if (
                marker.start() != start
                or name != b"svg"
                or _SVG_MARKER.search(data, marker.end(), position) is not None
            ):
                return False
            if closing:
                if re.fullmatch(rb"</svg[ \t\r\n\f]*>", lexeme, re.I) is None:
                    return False
            elif lexeme.endswith(b"/>") != bool(self_close):
                return False
            marker = _SVG_MARKER.search(data, position)
        if stack or name == b"svg":
            if closing:
                if not stack or stack.pop() != name:
                    return False
            elif not self_close:
                stack.append(name)
        elif not closing and name in _SCOPE_RAW_END:
            raw_end = _SCOPE_RAW_END[name].match(data, data.find(b"<", position))
            if raw_end is None or (marker is not None and marker.start() < raw_end.end()):
                return False
            position = raw_end.end()
    return not stack


_HTML_BLOCKS = frozenset(
    {
        "address", "article", "aside", "blockquote", "body", "caption", "center", "dd",
        "details", "dialog", "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer",
        "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr", "html",
        "legend", "li", "main", "menu", "nav", "ol", "option", "p", "pre", "section",
        "summary", "table", "tbody", "td", "textarea", "tfoot", "th", "thead", "title", "tr",
        "ul", "svg", "text",
    }
)  # fmt: skip
_HTML_SPACE = re.compile(r"[ \t\r\n\f]+")


def _opens_as_html(head: str) -> bool:
    """Recognize HTML/SVG after a BOM, whitespace, comments, or an XML declaration.

    Comments are skipped one at a time with str.find, so no pattern can reconsider where an
    earlier comment ended.
    """
    position = 1 if head.startswith("\ufeff") else 0
    while True:
        while position < len(head) and head[position].isspace():
            position += 1
        if head.startswith("<?xml ", position):
            close = head.find("?>", position + 6)
            if close < 0:
                return False
            position = close + 2
            continue
        if not head.startswith("<!--", position):
            return _HTML_OPENER.match(head, position) is not None
        close = head.find("-->", position + 4)
        if close < 0:
            return False
        position = close + 3


def html_text_blocks(name: str, text: str, budget: Budget) -> list[str]:
    """The text of each HTML block or SVG text element split by inline markup.

    A paragraph, list item, table cell, or other block is one piece; bold, links, spans,
    comments, and other inline markup inside it are dropped and their text joined, ``<br>``
    is a line break, and whitespace collapses to one space outside ``<pre>``. Script and style
    bodies are not text, and a textarea or title body is read as written, with no tags in it.
    A block whose text is one run is left to the raw and HTML-unescaped views. Two blocks are
    never joined. One linear pass with bounded tags; this is lexical text extraction, not
    computed visibility, sanitization, or script execution. SVG tspan/textPath are inline;
    separate text elements stay separate. SVG positioning and CSS are not interpreted.
    """
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if suffix not in _HTML_SUFFIXES and not _opens_as_html(text[:8192]):
        return []
    blocks: list[str] = []
    parts: list[str] = []
    segments = 0
    pre = 0
    svg_depth = 0

    def flush() -> None:
        nonlocal segments
        if segments >= 2:
            if len(blocks) >= MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")
            blocks.append("".join(parts).strip(" "))
        parts.clear()
        segments = 0

    position = 0
    count = 0
    while position < len(text):
        count += 1
        if count % 4096 == 0:
            budget.check()
        if svg_depth and text.startswith("<![CDATA[", position):
            end = text.find("]]>", position + 9)
            piece = text[position + 9 : end if end >= 0 else len(text)]
            position = end + 3 if end >= 0 else len(text)
            # XML character data is visible text; entity-looking bytes remain literal.
            if not pre:
                piece = _HTML_SPACE.sub(" ", piece)
            if piece.strip():
                segments += 1
            parts.append(piece)
            continue
        match = _HTML_TOKEN.match(text, position)
        if match is None:  # pragma: no cover - the last alternative matches any character
            break
        lexeme = match.group()
        position = match.end()
        if lexeme == "<!--":
            # A comment hides its text and splits the run it sits in; unclosed, it runs to the end.
            close = text.find("-->", position)
            position = len(text) if close < 0 else close + 3
            continue
        if lexeme.startswith(("<!", "<?")) and lexeme.endswith(">"):
            continue
        tag = (match.group(2) or "").lower()
        if tag:
            if tag == "svg" and not lexeme.endswith("/>"):
                svg_depth = max(0, svg_depth + (-1 if match.group(1) else 1))
            if tag in _HTML_RAW_TEXT and not match.group(1) and not lexeme.endswith("/>"):
                # A textarea or title body is one run of shown text: never a split phrase.
                flush()
                close_match = _HTML_RAW_TEXT[tag].search(text, position)
                position = len(text) if close_match is None else close_match.end()
            elif tag == "br":
                parts.append("\n")
            elif tag in _HTML_BLOCKS:
                flush()
                if tag == "pre":
                    pre = max(0, pre + (-1 if match.group(1) else 1))
            continue
        piece = html.unescape(lexeme)
        if not pre:
            piece = _HTML_SPACE.sub(" ", piece)
        if piece.strip():
            segments += 1
        parts.append(piece)
    flush()
    return blocks


# A line comment: indentation, a leader, more leader characters, and the rest of the line. The
# leader is one of a fixed set tried at a fixed position, and every quantifier is possessive.
# A bare */ is not a leader, so it ends a block comment.
_COMMENT_LINE = re.compile(r"(?m)^[ \t]*+(//|#|--|;|'|/\*|\*(?!/))[/#;*!-]*+([^\r\n]*+)")


def _next_line(text: str, end: int) -> int:
    """Where the line after the one ending at ``end`` starts, or -1 at the end of ``text``."""
    if text.startswith("\r\n", end):
        return end + 2
    if text.startswith(("\n", "\r"), end):
        return end + 1
    return -1


# A long block's lines are joined into a chunk this often, so memory follows its length.
_LINES_PER_CHUNK = 1024


def comment_texts(text: str, budget: Budget) -> list[str]:
    """The text of each block of two or more consecutive line comments, leaders removed.

    A block is a run of adjacent lines that open with the same leader (``//``, ``#``, ``--``,
    ``;``, or ``'``), or the ``*`` lines of a ``/*`` block comment. The lines of a block are
    joined with newlines, so a sentence wrapped over two comment lines reads as it does to a
    person. An empty comment line, a line of code, or another leader ends the block, and a
    ``*`` line outside a block comment (a list item) is not a comment. A one-line comment is
    contiguous in the raw text already. Lexical only: a leader inside a string literal counts,
    and a comment after code on the same line does not.
    """
    blocks: list[str] = []
    lines: list[str] = []
    chunks: list[str] = []
    family = ""
    expected = -1

    def flush() -> None:
        if chunks or len(lines) >= 2:
            if len(blocks) >= MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")
            blocks.append("\n".join(chunks + lines))
        lines.clear()
        chunks.clear()

    for count, match in enumerate(_COMMENT_LINE.finditer(text)):
        if count % 4096 == 0:
            budget.check()
        leader = match.group(1)
        kind = "*" if leader in ("/*", "*") else leader
        if match.start() != expected or kind != family or (leader == "/*" and family == "*"):
            flush()
            family = "" if leader == "*" else kind
        expected = _next_line(text, match.end())
        if not family:
            continue
        body = match.group(2).strip(" \t")
        closed = kind == "*" and body.endswith("*/")
        if closed:
            body = body[:-2].rstrip(" \t")
        if body:
            lines.append(body)
            if len(lines) >= _LINES_PER_CHUNK:
                chunks.append("\n".join(lines))
                lines.clear()
        else:
            flush()
        if closed:
            flush()
            family = ""
    flush()
    return blocks


_MARKDOWN_SUFFIXES = frozenset({"md", "markdown", "mdown", "mkd", "mkdn", "mdx"})
# A heading or YAML front matter at the start of a text file with no suffix or .txt.
_MARKDOWN_OPENER = re.compile(r"\A\ufeff?\s*+(?:#{1,6}[ \t]++\S|---[ \t]*+\r?\n)")
_MARKDOWN_FENCE = re.compile(r"[ \t]{0,3}+(`{3,}+|~{3,}+)")
_MARKDOWN_QUOTE = re.compile(r"[ \t]{0,3}+(?:>[ \t]?+)++")
_MARKDOWN_HEADING = re.compile(r"[ \t]{0,3}+#{1,6}+(?:[ \t]++|$)")
_MARKDOWN_ITEM = re.compile(r"[ \t]*+(?:[-*+]|[0-9]{1,9}+[.)])[ \t]++")
_MARKDOWN_BREAK = re.compile(
    r"[ \t]{0,3}+(?:(?:-[ \t]*+){3,}+|(?:=[ \t]*+){3,}+|(?:[*_][ \t]*+){3,}+)$"
)
# Inline markup within one line: bracketed text, as a link, image, reference, or checkbox, keeps
# its text and loses its brackets and target; emphasis and strong stars,
# strikethrough tildes, code-span backticks, and underscores at a word edge (snake_case stays).
_MARKDOWN_INLINE = re.compile(
    r"!?\[([^\[\]\r\n]{0,1024}+)\]"
    r"(?:\([^()\s]{0,2048}+(?:[ \t]++\"[^\"\r\n]{0,512}+\")?+\)|\[[^\[\]\r\n]{0,256}+\])?+"
    r"|\*++|~~++|`++|(?<![^\W_])_++|_++(?![^\W_])"
)


# One line at a time, ending where str.splitlines ends one, without building a list of every line.
_MARKDOWN_LINE = re.compile(
    r"([^\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]*+)"
    r"(?:\r\n|[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]|\Z)"
)


def _markdown_inline(match: re.Match[str]) -> str:
    return match.group(1) or ""


def markdown_texts(name: str, text: str, budget: Budget) -> list[str]:
    """The text of each Markdown paragraph, list item, or heading that inline markup splits.

    Read for a file named ``.md``, ``.markdown``, ``.mdown``, ``.mkd``, ``.mkdn``, or ``.mdx``,
    or a ``.txt`` or suffixless file that opens with a heading or front matter. Within each line,
    emphasis and strong markers, strikethrough, code-span backticks, and underscores at a word
    edge are dropped; bracketed text (a link, image, reference, or checkbox) keeps its text; and
    a ``>`` quote leader is removed. Lines of one paragraph are joined with newlines. A blank
    line, a heading, a list item, a thematic break, a code fence, or a deeper quote starts a new
    piece, and fenced code is not read, since its markers are literal; a fence closes only on
    its own character repeated at least as many times. Markers are dropped one line at a
    time, never paired across lines. A piece with nothing removed is left to the raw view.
    Lexical only, not a CommonMark renderer.
    """
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    suffix = base.rsplit(".", 1)[-1].lower() if "." in base else ""
    if suffix not in _MARKDOWN_SUFFIXES and (
        suffix not in {"", "txt"} or _MARKDOWN_OPENER.match(text[:4096]) is None
    ):
        return []
    blocks: list[str] = []
    parts: list[str] = []
    chunks: list[str] = []
    changed = False
    fence = ""
    depth = 0

    def flush() -> None:
        nonlocal changed, depth
        if changed and (parts or chunks):
            if len(blocks) >= MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")
            blocks.append("\n".join(chunks + parts))
        parts.clear()
        chunks.clear()
        changed = False
        depth = 0

    for count, found in enumerate(_MARKDOWN_LINE.finditer(text)):
        if count % 4096 == 0:
            budget.check()
        line = found.group(1)
        opener = _MARKDOWN_FENCE.match(line)
        if fence:
            # A closing fence is the opener's character, at least as long, and nothing after it.
            if (
                opener is not None
                and opener.group(1)[0] == fence[0]
                and len(opener.group(1)) >= len(fence)
                and not line[opener.end() :].strip()
            ):
                fence = ""
            continue
        if opener is not None:
            flush()
            fence = opener.group(1)
            continue
        if not line.strip() or _MARKDOWN_BREAK.match(line):
            flush()
            continue
        body = line
        quote = _MARKDOWN_QUOTE.match(body)
        if quote is not None:
            # A deeper quote is a new block; a shallower or unquoted line continues lazily.
            level = quote.group().count(">")
            if level > depth:
                flush()
            depth = max(depth, level)
            body = body[quote.end() :]
            changed = True
        heading = _MARKDOWN_HEADING.match(body)
        item = None if heading else _MARKDOWN_ITEM.match(body)
        marker = heading or item
        if marker is not None:
            level = depth
            flush()
            depth = level
            changed = quote is not None
            body = body[marker.end() :]
        shown = _MARKDOWN_INLINE.sub(_markdown_inline, body)
        changed = changed or shown != body
        parts.append(shown.strip(" \t"))
        if len(parts) >= _LINES_PER_CHUNK:
            chunks.append("\n".join(parts))
            parts.clear()
        if heading is not None:
            flush()
    flush()
    return blocks


_NOTEBOOK_SUFFIX = ".ipynb"


def notebook_texts(name: str, text: str, budget: Budget) -> list[tuple[str, int, bool]]:
    """Each Jupyter cell source and text output, joined, with its line count and code flag.

    nbformat stores multiline text as a list of lines, so the raw and JSON-unescaped views see
    the list's quotes and commas between two lines of one sentence. The text is a notebook when
    it is named ``.ipynb`` or holds both ``"cells"`` and ``"nbformat"``, and parses as a JSON
    object with a ``cells`` list. A cell's ``source``, a stream output's ``text``, and each
    ``text/*`` entry of an output's ``data`` is one item; two items are never joined. Malformed
    or deeply nested JSON gives no items.
    """
    if not name.lower().endswith(_NOTEBOOK_SUFFIX) and (
        '"cells"' not in text or '"nbformat"' not in text
    ):
        return []
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return []
    cells = document.get("cells") if isinstance(document, dict) else None
    if not isinstance(cells, list):
        return []
    items: list[tuple[str, int, bool]] = []

    def add(value: object, code: bool) -> None:
        if isinstance(value, str):
            lines = [value]
        elif isinstance(value, list) and all(isinstance(line, str) for line in value):
            lines = value
        else:
            return
        if len(items) >= MAX_TEXT_PIECES:
            raise ContentLimit("text pieces exceed 100000")
        items.append(("".join(lines), len(lines), code))

    for count, cell in enumerate(cells):
        if count % 4096 == 0:
            budget.check()
        if not isinstance(cell, dict):
            continue
        add(cell.get("source"), cell.get("cell_type") == "code")
        outputs = cell.get("outputs")
        for output in outputs if isinstance(outputs, list) else ():
            if not isinstance(output, dict):
                continue
            add(output.get("text"), False)
            data = output.get("data")
            if isinstance(data, dict):
                for mime, value in data.items():
                    if isinstance(mime, str) and mime.startswith("text/"):
                        add(value, False)
    return items


@dataclass
class PdfStream:
    """One stream of a PDF, decoded once and shared by the ``pdf-flate`` and ``pdf-text`` views.

    ``inflated`` is the FlateDecode output when it sniffs as text (what ``pdf-flate`` reads).
    ``text`` is that, or the stream's own bytes when it has no filter and sniffs as text, which
    is how an uncompressed content stream or ToUnicode CMap arrives. ``number`` is the object
    number of the nearest ``N G obj`` header before the stream keyword.
    """

    offset: int
    number: int | None
    inflated: bytes | None
    text: bytes | None


_PDF_OBJ_HEADER = re.compile(
    rb"(?<![0-9])([0-9]{1,10})[\x00\t\n\f\r ]+[0-9]{1,5}[\x00\t\n\f\r ]+obj\b"
)


def pdf_streams(
    data: bytes, budget: Budget, decoded: dict[int, bytes | None] | None = None
) -> list[PdfStream]:
    """Decode every stream in ``data`` once, under the same limits ``pdf_views`` documents."""
    if not data.startswith(b"%PDF"):
        return []
    streams: list[PdfStream] = []
    objects: dict[tuple[int, int], PdfValue | None] = {}
    for count, start in enumerate(_PDF_STREAM.finditer(data)):
        if count >= MAX_PDF_STREAMS:
            raise ContentLimit("pdf streams exceed 2000")
        budget.check()
        if data[max(0, start.start() - 3) : start.start()] == b"end":
            continue
        if decoded is not None and start.start() in decoded:
            # An object stream the /OpenAction lookup already inflated and charged.
            inflated = decoded[start.start()]
        else:
            inflated = _pdf_stream_bytes(data, start, budget, objects)
            if decoded is not None:
                # Object-stream indexing reads this same dict. Recording the bytes
                # keeps the expansion budget from counting the stream a second time.
                decoded[start.start()] = inflated
        inflated = inflated if inflated and sniff(inflated) == "text" else None
        text = inflated
        if text is None:
            stream_dict = _pdf_stream_dict(data, start.start())
            if stream_dict is not None and b"/Filter" not in stream_dict:
                end = _PDF_END.search(data, start.end())
                raw = data[start.end() : end.start() if end else len(data)]
                text = raw if raw and sniff(raw) == "text" else None
        number = None
        for header in _PDF_OBJ_HEADER.finditer(data, max(0, start.start() - 4096), start.start()):
            number = int(header.group(1))
        streams.append(PdfStream(start.start(), number, inflated, text))
    return streams


def pdf_views(
    data: bytes,
    budget: Budget,
    decoded: dict[int, bytes | None] | None = None,
    streams: list[PdfStream] | None = None,
) -> Iterator[tuple[str, bytes]]:
    """Inflate FlateDecode streams that hold text and return them as one ``pdf-flate`` view.

    The filter is read from the stream's own dictionary, the one value between the object
    header and ``stream``, so nested dictionaries such as ``/DecodeParms`` do not hide it. A PNG
    or TIFF predictor is reversed after inflation; when it cannot be (parameters out of range,
    a predictor a reader rejects, an unknown PNG row type) the inflated bytes are kept as they
    are, so no stream that inflates drops out of the view. ASCIIHexDecode and ASCII85Decode
    stages before FlateDecode are decoded first, and the ``/DecodeParms`` entry at FlateDecode's
    position in the chain selects the predictor. When no dictionary parses, a stream is
    inflated if ``/FlateDecode`` is in the 1 KB before it.
    Content and object streams are text once inflated, so the lexical rules and PDF name
    checks can read them. Fonts, images, and other binary streams are dropped after inflation.
    Each stream is capped at the file limit, the total at the shared expansion budget, and the
    deadline is checked between chunks, so a decompression bomb ends the scan as incomplete.
    ``decoded`` holds object streams that were already inflated, by stream offset; they are
    reused so the same bytes are not inflated or charged twice.
    """
    if streams is None:
        streams = pdf_streams(data, budget, decoded)
    parts = [stream.inflated for stream in streams if stream.inflated]
    if parts:
        joined = b"\n".join(parts)
        yield "pdf-flate", joined
        # Text a PDF shows can itself be base64; its streams are not otherwise decoded.
        for encoded in base64_texts(joined.decode("latin-1"), budget):
            yield "base64-decoded", _derived(encoded, budget)


def _pdf_stream_bytes(
    data: bytes,
    start: re.Match[bytes],
    budget: Budget,
    objects: dict[tuple[int, int], PdfValue | None],
) -> bytes | None:
    """The decoded bytes of the stream whose keyword ``start`` matched, or None.

    None means the chain does not reach FlateDecode through ASCIIHexDecode and ASCII85Decode
    stages alone, or the stream does not inflate. A stream that inflates is never dropped over
    its predictor: parameters this view will not apply leave the inflated bytes as they are, for
    ``sniff`` and the text rules to judge.
    """
    stream_dict = _pdf_stream_dict(data, start.start())
    end = _PDF_END.search(data, start.end())
    body = data[start.end() : end.start() if end else len(data)]
    if stream_dict is None:
        # No parsable dictionary ends at this keyword: inflate when FlateDecode is near.
        if b"/FlateDecode" not in data[max(0, start.start() - 1024) : start.start()]:
            return None
        return _inflate(body, budget)
    plan = _pdf_flate_plan(data, stream_dict, objects)
    if plan is None:
        return None
    stages, parms = plan
    for stage in stages:
        body = _ascii_hex(body, budget) if stage == _PDF_HEX else _ascii85(body, budget)
    inflated = _inflate(body, budget)
    if not inflated:
        return inflated
    predictor = _pdf_predictor(parms)
    if predictor is None:
        return inflated
    decoded = _unpredict(inflated, predictor, budget)
    return inflated if decoded is None else decoded


@dataclass(frozen=True)
class PdfObjectStream:
    """One readable object stream: the offset of its ``stream`` keyword, the object numbers
    and offsets its header lists, in that order, its /First, and its decoded bytes."""

    offset: int
    numbers: list[int]
    offsets: list[int]
    first: int
    data: bytes | memoryview


class PdfObjects:
    """Every definition of a PDF object in one file: raw ``N G obj`` and object-stream members.

    Object streams are indexed on first use, so a file pays for the extra decoding only when an
    /OpenAction reference does not settle without it. Members are kept as offsets into the
    decoded streams, whose bytes the scan budget already counts.

    ISO 32000-1 7.5.7: an object stream's dictionary has /Type /ObjStm, /N, and /First; its
    decoded data starts with /N pairs of object number and offset, and the objects follow at
    /First. Objects in a stream have generation 0. A stream whose dictionary does not parse, a
    header that does not parse, or offsets outside its data is skipped, so its objects stay
    unresolved. More than ``MAX_PDF_DEFINITIONS`` definitions of one object return one empty
    body, which is not a page open.
    """

    def __init__(self, data: bytes, budget: Budget) -> None:
        self._data = data
        self._budget = budget
        self._raw = PdfRawObjects(data, budget.check)
        # Inflated bytes, or a view into ``data`` for an unfiltered stream, so overlapping
        # unfiltered declarations share the file's buffer instead of each holding a copy.
        self._streams: list[bytes | memoryview] = []
        self._members: dict[int, list[tuple[int, int, int]]] | None = None
        # Inflated object streams by the offset of their ``stream`` keyword, for ``pdf_views``
        # to reuse: the same bytes are neither inflated nor charged to the budget twice.
        self.decoded: dict[int, bytes | None] = {}
        # True when an object stream could not be read, so an object may be defined in it.
        self._opaque = False
        # Each readable object stream, in file order.
        self._tables: list[PdfObjectStream] = []

    def prime(self, keys: Iterable[tuple[int, int]]) -> None:
        self._raw.prime(keys)

    def __call__(self, number: int, generation: int) -> list[bytes]:
        found = list(self._raw(number, generation))
        if generation == 0:
            if self._members is None:
                self._members = self._index()
            for stream, begin, stop in self._members.get(number, []):
                # Only the window is ever parsed, as for a raw definition, so a lookup copies at
                # most that much of each member however many declarations reach one tail.
                window = min(stop, begin + _PDF_VALUE_WINDOW)
                found.append(bytes(self._streams[stream][begin:window]))
        if self._opaque:
            # An unreadable object stream may redefine this object as any action.
            found.append(b"")
        if len(found) > MAX_PDF_DEFINITIONS:
            return [b""]
        return found

    @property
    def opaque(self) -> bool:
        """True when an object stream could not be read, so an object may be defined in it."""
        if self._members is None:
            self._members = self._index()
        return self._opaque

    def object_streams(self) -> list[PdfObjectStream]:
        """Each readable object stream with its header as written. A cross-reference entry
        names a member by its position in the header, and a reader may take the objects in
        the order they are written instead of at the header's offsets."""
        if self._members is None:
            self._members = self._index()
        return self._tables

    def stream_members(self) -> Iterator[tuple[int, memoryview]]:
        """Bounded, already budgeted object-stream members; no raw-header lookalikes."""
        if self._members is None:
            self._members = self._index()
        for number, definitions in self._members.items():
            for stream, begin, stop in definitions:
                self._budget.check()
                yield number, memoryview(self._streams[stream])[begin:stop]

    def _index(self) -> dict[int, list[tuple[int, int, int]]]:
        members: dict[int, list[tuple[int, int, int]]] = {}
        data = self._data
        if not data.startswith(b"%PDF"):
            return members
        objects: dict[tuple[int, int], PdfValue | None] = {}
        for count, start in enumerate(_PDF_STREAM.finditer(data)):
            if count >= MAX_PDF_STREAMS:
                raise ContentLimit("pdf streams exceed 2000")
            self._budget.check()
            if data[max(0, start.start() - 3) : start.start()] == b"end":
                continue
            stream_dict = _pdf_stream_dict(data, start.start())
            if stream_dict is None or stream_dict.get(b"/Type") != b"/ObjStm":
                continue
            member = self._read_objstm(start, stream_dict, objects)
            if member is None:
                self._opaque = True
                continue
            decoded, numbers, offsets, origin = member
            self._tables.append(PdfObjectStream(start.start(), numbers, offsets, origin, decoded))
            self._streams.append(decoded)
            stream = len(self._streams) - 1
            bounds = [*offsets[1:], len(decoded) - origin]
            for number, offset, stop in zip(numbers, offsets, bounds, strict=True):
                slot = members.setdefault(number, [])
                if len(slot) <= MAX_PDF_DEFINITIONS:
                    slot.append((stream, origin + offset, origin + stop))
        return members

    def _read_objstm(
        self,
        start: re.Match[bytes],
        stream_dict: dict[bytes, PdfValue],
        objects: dict[tuple[int, int], PdfValue | None],
    ) -> tuple[bytes | memoryview, list[int], list[int], int] | None:
        """Decoded bytes, object numbers, offsets and /First of one object stream, or None."""
        total, first = stream_dict.get(b"/N"), stream_dict.get(b"/First")
        if not (isinstance(total, bytes) and total.isdigit()):
            return None
        if not (isinstance(first, bytes) and first.isdigit()):
            return None
        pairs, origin = 2 * int(total), int(first)
        if pairs > 2 * MAX_OBJSTM_OBJECTS:
            return None
        data = self._data
        filters = _pdf_resolve(data, stream_dict.get(b"/Filter"), objects)
        if isinstance(filters, list) and len(filters) > 1:
            # Decoding stops at the first FlateDecode, so a filter after it (ASCIIHexDecode, a
            # second Flate pass) is still encoded and the objects inside are not the ones a
            # reader sees. Only ASCII stages may come before it, as the last filter.
            names = [_pdf_resolve(data, item, objects) for item in filters]
            if names[-1] not in _PDF_FLATE_NAMES or not all(
                name in _PDF_ASCII_STAGES for name in names[:-1]
            ):
                return None
        if start.start() not in self.decoded:
            self.decoded[start.start()] = _pdf_stream_bytes(data, start, self._budget, objects)
        decoded: bytes | memoryview | None = self.decoded[start.start()]
        if decoded is None and b"/Filter" not in stream_dict:
            # No filter: the stream is its own bytes, which a reader parses as they are. These
            # stay out of ``decoded``, which feeds the inflated view. A view, not a copy: nothing
            # is expanded, and declarations that share one ``endstream`` share one buffer.
            end = _PDF_END.search(data, start.end())
            decoded = memoryview(data)[start.end() : end.start() if end else len(data)]
        if not decoded or origin > len(decoded):
            return None
        header = bytes(decoded[:origin]).split()
        if len(header) < pairs or not all(item.isdigit() for item in header[:pairs]):
            return None
        numbers = [int(item) for item in header[0:pairs:2]]
        offsets = [int(item) for item in header[1:pairs:2]]
        if any(b < a for a, b in zip(offsets, offsets[1:], strict=False)):
            return None
        if offsets and origin + offsets[-1] > len(decoded):
            return None
        return decoded, numbers, offsets, origin


def _pdf_tokens(
    data: bytes, position: int, stop: int, until: frozenset[bytes] = frozenset()
) -> list[bytes] | None:
    """Tokens in ``data[position:stop]``, or None when a string crosses ``stop``.

    Whitespace and comments are dropped, a literal string becomes ``()``, a hex string ``<>``,
    and names are #xx-decoded. A keyword token in ``until`` ends the list early, before any
    bytes after it are lexed.
    """
    tokens: list[bytes] = []
    while position < stop:
        match = _PDF_LEX.match(data, position, stop)
        if match is None:
            return None
        token = match.group()
        position = match.end()
        first = token[:1]
        if first in b"\x00\t\n\f\r " or first == b"%":
            continue
        if token == b"(":
            position = _pdf_string_end(data, position, stop)
            if position < 0:
                return None
            tokens.append(b"()")
        elif first == b"<" and token != b"<<":
            tokens.append(b"<>")
        elif first == b"/":
            tokens.append(_decode_pdf_name(token))
        elif token in until:
            return tokens
        else:
            tokens.append(token)
    return tokens


def _pdf_string_end(data: bytes, position: int, stop: int) -> int:
    """The index after the ``)`` closing a literal string, or -1 when none comes before ``stop``."""
    depth = 1
    while position < stop:
        char = data[position]
        if char == 0x5C:
            position += 2
            continue
        position += 1
        if char == 0x28:
            depth += 1
        elif char == 0x29:
            depth -= 1
            if not depth:
                return position
    return -1


def _pdf_value(
    tokens: list[bytes], index: int, nesting: int = 0, *, reject_duplicates: bool = False
) -> tuple[PdfValue, int]:
    """Parse one object at ``tokens[index]``. Raises IndexError or ValueError when malformed."""
    if nesting > _PDF_MAX_NESTING:
        raise ValueError("nesting")
    token = tokens[index]
    if token == b"<<":
        entries: dict[bytes, PdfValue] = {}
        index += 1
        while tokens[index] != b">>":
            key = tokens[index]
            if not key.startswith(b"/"):
                raise ValueError("key")
            if reject_duplicates and key in entries:
                raise ValueError("duplicate key")
            entries[key], index = _pdf_value(
                tokens, index + 1, nesting + 1, reject_duplicates=reject_duplicates
            )
        return entries, index + 1
    if token == b"[":
        items: list[PdfValue] = []
        index += 1
        while tokens[index] != b"]":
            item, index = _pdf_value(
                tokens, index, nesting + 1, reject_duplicates=reject_duplicates
            )
            items.append(item)
        return items, index + 1
    if token in (b">>", b"]"):
        raise ValueError("close")
    following = tokens[index + 1 : index + 3]
    if token.isdigit() and len(following) == 2 and following[0].isdigit() and following[1] == b"R":
        return (int(token), int(following[0])), index + 3
    return token, index + 1


def _pdf_stream_dict(data: bytes, stream_at: int) -> dict[bytes, PdfValue] | None:
    """The dictionary between an object header and the ``stream`` keyword.

    Headers in the window are tried from the nearest back, and the first one followed by exactly
    one dictionary wins, so a ``(2 0 obj)`` string inside the dictionary is not taken for one.
    """
    window = max(0, stream_at - _PDF_DICT_WINDOW)
    for header in reversed(list(_PDF_OBJ.finditer(data, window, stream_at))):
        tokens = _pdf_tokens(data, header.end(), stream_at)
        if not tokens or tokens[0] != b"<<":
            continue
        try:
            value, used = _pdf_value(tokens, 0)
        except (IndexError, ValueError):
            continue
        if isinstance(value, dict) and used == len(tokens):
            return value
    return None


def _last_match(
    pattern: re.Pattern[bytes], data: bytes, start: int, stop: int
) -> re.Match[bytes] | None:
    found = deque(pattern.finditer(data, start, stop), maxlen=1)
    return found[0] if found else None


def _pdf_resolve(
    data: bytes, value: PdfValue | None, objects: dict[tuple[int, int], PdfValue | None]
) -> PdfValue | None:
    """Follow one indirect reference to a top-level object; anything else is returned as is."""
    if not isinstance(value, tuple):
        return value
    if value not in objects:
        number, generation = value
        pattern = re.compile(
            rb"(?<![0-9])%d[\x00\t\n\f\r ]+%d[\x00\t\n\f\r ]+obj" % (number, generation)
        )
        header = _last_match(pattern, data, 0, len(data))
        resolved: PdfValue | None = None
        if header is not None:
            # Stop at the object's ``endobj`` or ``stream`` token: a lone ``>`` after it, such as
            # an ASCIIHex stream's end marker or a byte in a binary stream, has no token and
            # would void the whole window.
            stop = min(len(data), header.end() + 4096)
            tokens = _pdf_tokens(data, header.end(), stop, _PDF_OBJ_END)
            try:
                resolved = _pdf_value(tokens, 0)[0] if tokens else None
            except (IndexError, ValueError):
                resolved = None
        objects[value] = None if isinstance(resolved, tuple) else resolved
    return objects[value]


def _pdf_flate_plan(
    data: bytes, stream_dict: dict[bytes, PdfValue], objects: dict[tuple[int, int], PdfValue | None]
) -> tuple[tuple[bytes, ...], dict[bytes, PdfValue]] | None:
    """The ASCII stages before FlateDecode and FlateDecode's parameters, or None.

    None when the chain does not reach FlateDecode through ASCIIHexDecode and ASCII85Decode
    alone. With a ``/DecodeParms`` array, the entry at FlateDecode's index applies, as in pdf.js
    and MuPDF. A lone dictionary applies when FlateDecode is the first filter.
    """
    filters = _pdf_resolve(data, stream_dict.get(b"/Filter"), objects)
    chain = filters if isinstance(filters, list) else [filters]
    stages: list[bytes] = []
    for index, item in enumerate(chain):
        name = _pdf_resolve(data, item, objects)
        kind = _PDF_FILTERS.get(name) if isinstance(name, bytes) else None
        if kind is None:
            return None
        if kind != _PDF_FLATE:
            stages.append(kind)
            continue
        parms = _pdf_resolve(data, stream_dict.get(b"/DecodeParms"), objects)
        if isinstance(parms, list):
            parms = _pdf_resolve(data, parms[index], objects) if index < len(parms) else None
        elif index:
            parms = None
        return tuple(stages), parms if isinstance(parms, dict) else {}
    return None


def _pdf_predictor(parms: dict[bytes, PdfValue]) -> tuple[int, int, int, int] | None:
    """(Predictor, Colors, BitsPerComponent, Columns), or None for one a reader rejects.

    A missing or non-integer Predictor means none, as in pdf.js. TIFF is decoded at 8 bits per
    component; other TIFF depths return None and keep the stream out of the view.
    """

    def number(key: bytes, default: int) -> int:
        value = parms.get(key)
        if isinstance(value, bytes) and _PDF_INT.fullmatch(value):
            return int(value)
        return default

    predictor = number(b"/Predictor", 1)
    if predictor <= 1:
        return (1, 1, 8, 1)
    colors = number(b"/Colors", 1)
    bits = number(b"/BitsPerComponent", 8)
    columns = number(b"/Columns", 1)
    if not (1 <= colors <= 32 and bits in (1, 2, 4, 8, 16) and 1 <= columns <= MAX_FILE_BYTES):
        return None
    if predictor == 2:
        return (2, colors, bits, columns) if bits == 8 else None
    if 10 <= predictor <= 15:
        return (predictor, colors, bits, columns)
    return None


def _unpredict(data: bytes, predictor: tuple[int, int, int, int], budget: Budget) -> bytes | None:
    """Reverse a TIFF or PNG predictor. Only the first 4096 bytes are decoded unless they are text.

    ``sniff`` reads no further than that prefix, so a binary image costs one short pass.
    """
    kind, colors, bits, columns = predictor
    if kind == 1:
        return data
    pixel = max(1, (colors * bits + 7) // 8)
    # A row is never longer than the data, so clamping it decodes the same bytes and bounds the
    # row buffer, which /Columns up to the file limit times 32 colors at 16 bits would not.
    row = min((colors * bits * columns + 7) // 8, max(1, len(data)))
    decode = _tiff_rows if kind == 2 else _png_rows
    head = decode(data, row, pixel, budget, 4096)
    if head is None or sniff(head) != "text":
        return None
    return decode(data, row, pixel, budget, None)


def _tiff_rows(data: bytes, row: int, pixel: int, budget: Budget, limit: int | None) -> bytes:
    output = bytearray()
    for start in range(0, len(data), row):
        if limit is not None and len(output) >= limit:
            break
        budget.check()
        line = bytearray(data[start : start + row])
        for index in range(pixel, len(line)):
            if index % _PREDICTOR_CHECK == 0:
                budget.check()
            line[index] = (line[index] + line[index - pixel]) & 0xFF
        output += line
    return bytes(output)


def _png_rows(data: bytes, row: int, pixel: int, budget: Budget, limit: int | None) -> bytes | None:
    """PNG row filters (None, Sub, Up, Average, Paeth); an unknown filter type returns None."""
    output = bytearray()
    previous = bytearray(row)
    position = 0
    while position < len(data):
        if limit is not None and len(output) >= limit:
            break
        budget.check()
        kind = data[position]
        line = bytearray(data[position + 1 : position + 1 + row])
        position += 1 + row
        size = len(line)
        if kind == 1:
            for index in range(pixel, size):
                if index % _PREDICTOR_CHECK == 0:
                    budget.check()
                line[index] = (line[index] + line[index - pixel]) & 0xFF
        elif kind == 2:
            for chunk in range(0, size, _PREDICTOR_CHECK):
                budget.check()
                stop = min(size, chunk + _PREDICTOR_CHECK)
                line[chunk:stop] = bytes(
                    (a + b) & 0xFF
                    for a, b in zip(line[chunk:stop], previous[chunk:stop], strict=True)
                )
        elif kind == 3:
            for index in range(size):
                if index % _PREDICTOR_CHECK == 0:
                    budget.check()
                left = line[index - pixel] if index >= pixel else 0
                line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif kind == 4:
            for index in range(size):
                if index % _PREDICTOR_CHECK == 0:
                    budget.check()
                left = line[index - pixel] if index >= pixel else 0
                up = previous[index]
                corner = previous[index - pixel] if index >= pixel else 0
                estimate = left + up - corner
                near_left, near_up = abs(estimate - left), abs(estimate - up)
                near_corner = abs(estimate - corner)
                if near_left <= near_up and near_left <= near_corner:
                    best = left
                elif near_up <= near_corner:
                    best = up
                else:
                    best = corner
                line[index] = (line[index] + best) & 0xFF
        elif kind != 0:
            return None
        output += line
        previous[:size] = line
    return bytes(output)


def _pdf_grow(output: bytearray, piece: bytes, budget: Budget) -> None:
    """Append one decoded piece within the per-stream cap and the shared expansion budget."""
    budget.expanded += len(piece)
    if budget.expanded > MAX_EXTRACT_BYTES:
        raise ContentLimit("extracted size exceeds 500MB")
    output += piece
    if len(output) > MAX_FILE_BYTES:
        raise ContentLimit("pdf stream exceeds 100MB")


def _ascii_hex(raw: bytes, budget: Budget) -> bytes:
    """ASCIIHexDecode as pdf.js reads it: ``>`` ends the data, other non-hex bytes are skipped,
    and an odd final digit is followed by 0."""
    end = raw.find(b">")
    if end >= 0:
        raw = raw[:end]
    output = bytearray()
    carry = b""
    for start in range(0, len(raw), _PDF_CHUNK):
        budget.check()
        digits = carry + _PDF_NOT_HEX.sub(b"", raw[start : start + _PDF_CHUNK])
        even = len(digits) & ~1
        _pdf_grow(output, binascii.unhexlify(digits[:even]), budget)
        carry = digits[even:]
    if carry:
        _pdf_grow(output, binascii.unhexlify(carry + b"0"), budget)
    return bytes(output)


def _ascii85(raw: bytes, budget: Budget) -> bytes:
    """ASCII85Decode with an optional ``<~`` prefix; ``~`` ends the data, whitespace is skipped.

    ``z`` where a group starts is four zero bytes. As in pdf.js, any other byte in a group is a
    digit and a group's value wraps at 32 bits, so a malformed group does not hide what follows.
    A final group of n digits gives n - 1 bytes. ``z`` expands 5:4 against the encoded size, so
    output is capped like inflation.
    """
    budget.check()
    text = raw.translate(None, _PDF_WHITESPACE)
    if text.startswith(b"<~"):
        text = text[2:]
    end = text.find(b"~")
    if end >= 0:
        text = text[:end]
    output = bytearray()
    position = 0
    while True:
        budget.check()
        match = _PDF_A85_GROUPS.match(text, position)
        if match is None:
            break
        groups = match.group()
        position = match.end()
        piece = None
        if _PDF_A85_DIGITS.fullmatch(groups):
            try:
                piece = base64.a85decode(groups)
            except ValueError:
                piece = None
        _pdf_grow(output, _a85_groups(groups) if piece is None else piece, budget)
    tail = text[position:]
    if len(tail) > 1:
        value = _a85_value(tail.ljust(5, b"u"))
        _pdf_grow(output, value[: len(tail) - 1], budget)
    return bytes(output)


def _a85_groups(groups: bytes) -> bytes:
    """Whole groups, one at a time: the path for overflow, ``z`` inside a group, or odd bytes."""
    output = bytearray()
    index = 0
    while index < len(groups):
        if groups[index] == 0x7A:
            output += bytes(4)
            index += 1
        else:
            output += _a85_value(groups[index : index + 5])
            index += 5
    return bytes(output)


def _a85_value(group: bytes) -> bytes:
    value = 0
    for digit in group:
        value = value * 85 + digit - 0x21
    return (value & 0xFFFFFFFF).to_bytes(4, "big")


def _inflate(raw: bytes, budget: Budget) -> bytes | None:
    inflater = zlib.decompressobj()
    output = bytearray()
    cursor = 0
    try:
        while cursor < len(raw) or inflater.unconsumed_tail:
            budget.check()
            chunk = inflater.unconsumed_tail or raw[cursor : cursor + 64 * 1024]
            if not inflater.unconsumed_tail:
                cursor += len(chunk)
            piece = inflater.decompress(chunk, 64 * 1024)
            budget.expanded += len(piece)
            if budget.expanded > MAX_EXTRACT_BYTES:
                raise ContentLimit("extracted size exceeds 500MB")
            output.extend(piece)
            if len(output) > MAX_FILE_BYTES:
                raise ContentLimit("pdf stream exceeds 100MB")
            if inflater.eof:
                break
        output.extend(inflater.flush())
    except zlib.error:
        # A corrupt or truncated stream is not text the reader sees; the raw bytes were scanned.
        return bytes(output) or None
    return bytes(output)


def _derived(text: str, budget: Budget) -> bytes:
    budget.check()
    data = text.encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise ContentLimit("derived text exceeds 100MB")
    budget.expanded += len(data)
    if budget.expanded > MAX_EXTRACT_BYTES:
        raise ContentLimit("extracted size exceeds 500MB")
    return data
