"""Bounded in-memory content views. Member names are never extracted to disk."""

import base64
import binascii
import bz2
import email
import email.errors
import email.header
import email.message
import email.policy
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
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
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
# A whole word that holds a non-ASCII letter or digit: the only words a mixed-script fold can
# change. An ASCII word fails at its first character after the lazy prefix, so this is linear.
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

# Office XML parts whose text a reader sees. Word splits a sentence across runs on any formatting or
# proofing boundary, so the joined text is what the lexical rules need.
_OOXML_TEXT_PART = re.compile(
    r"(?i)^(word/(document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
    r"|xl/sharedStrings\.xml|ppt/(slides|notesSlides)/[^/]+\.xml)$"
)
# A text run, a paragraph or shared-string end, or a Word break or tab, in document order.
_OOXML_TOKEN = re.compile(
    rb"<(?:w:t|t|a:t)(?:\s[^>]*)?>([^<]*)</(?:w:t|t|a:t)>"
    rb"|</(?:w:p|a:p|si)>"
    rb"|<w:(?:br|cr)\b[^>]*/?>"
    rb"|<w:tab\b[^>]*/?>"
)

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

# A mail message with a MIME body: header lines, a Content-Type, one more message header, and
# either a multipart body or an encoded single part. A reader's mail client shows the decoded
# parts, so they are scanned as members; the raw message is scanned as well.
_MIME_FIRST_LINE = re.compile(rb"\A(?:[A-Za-z][A-Za-z0-9-]*:[ \t]|From )")
_MIME_HEADER_NAME = re.compile(rb"(?m)^([A-Za-z][A-Za-z0-9-]*):")
_MIME_BLANK = re.compile(rb"\r?\n\r?\n")
_MIME_ENCODED = re.compile(rb"content-transfer-encoding:[ \t]*(base64|quoted-printable)")
_MIME_MESSAGE_HEADERS = frozenset(
    {b"mime-version", b"from", b"subject", b"message-id", b"received"}
)
_MIME_PART_SUFFIX = {"text/plain": ".txt", "text/html": ".html", "text/csv": ".csv"}


class ContentLimit(Exception):
    """Inspection did not cover all required content."""


@dataclass
class Budget:
    deadline: float
    expanded: int = 0
    members: int = 0

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
    if _mime_message(data):
        return "mime"
    if _trailing_zip(data):
        return "zip"
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


def _mime_message(data: bytes) -> bool:
    head = data[:8192]
    if not _MIME_FIRST_LINE.match(head):
        return False
    blank = _MIME_BLANK.search(head)
    headers = (head[: blank.start()] if blank else head).lower()
    names = {match.group(1) for match in _MIME_HEADER_NAME.finditer(headers)}
    if b"content-type" not in names or not names & _MIME_MESSAGE_HEADERS:
        return False
    return b"multipart/" in headers or _MIME_ENCODED.search(headers) is not None


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


def content_units(unit: ContentUnit, budget: Budget, depth: int = 0) -> Iterator[ContentUnit]:
    budget.check()
    if unsupported_container(unit.data):
        raise ContentLimit("unsupported archive")
    kind = archive_kind(unit.data)
    if kind is None:
        yield unit
        return
    if depth >= MAX_ARCHIVE_DEPTH:
        raise ContentLimit("archive depth exceeds 3")
    try:
        for index, name, data in _members(unit, kind, budget):
            member = ContentUnit(name, data, (*unit.member_path, f"{kind}:{index}"))
            yield from content_units(member, budget, depth + 1)
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
    for index, part in enumerate(message.walk()):
        if part.is_multipart():
            continue
        budget.member()
        payload = part.get_payload(decode=True)
        if not isinstance(payload, bytes) or not payload:
            continue
        if len(payload) > MAX_FILE_BYTES:
            raise ContentLimit("archive member exceeds 100MB")
        budget.expanded += len(payload)
        if budget.expanded > MAX_EXTRACT_BYTES:
            raise ContentLimit("extracted size exceeds 500MB")
        yield index, _mime_part_name(part, index), _mime_part_text(part, payload)


def _mime_part_name(part: email.message.Message, index: int) -> str:
    filename = part.get_filename()
    if filename:
        name = Path(filename.replace("\\", "/")).name
        if name:
            return name
    return f"part-{index}{_MIME_PART_SUFFIX.get(part.get_content_type(), '')}"


def _mime_part_text(part: email.message.Message, payload: bytes) -> bytes:
    """Transcode a text part declared in a legacy charset to UTF-8 so the lexical rules read it."""
    if part.get_content_maintype() != "text":
        return payload
    charset = (part.get_content_charset() or "").lower()
    if charset in ("", "utf-8", "utf8", "us-ascii", "ascii", "utf-16", "utf-16le", "utf-16be"):
        return payload
    try:
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
_MIME_HEADER_BYTES = 64 * 1024
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
    # A MIME message's base64 parts are already decoded as its members; its headers' RFC 2047
    # encoded words are not parts, so they get their own view.
    if _mime_message(data):
        headers = mime_header_text(data)
        if headers is not None:
            yield from _with_folded("mime-headers-decoded", headers, budget)
    else:
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
    and Greek look-alikes folded to Latin inside
    mixed-script tokens, a word hyphenated at a line end rejoined (``previ-`` then ``ous``),
    letters spaced one apart rejoined, and digit or symbol stand-ins folded inside tokens that
    mix them with letters. Russian, Greek, and ordinary numbers stay as written. The result is a
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


def ooxml_text_views(name: str, data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    """Join the text runs of a Word, Excel, or PowerPoint XML part into one ``ooxml-text`` view.

    Only the parts a reader sees are joined (document body, headers, footers, notes, comments,
    shared strings, slides). Runs inside one paragraph are joined without a separator, paragraphs
    end with a newline, breaks and tabs become whitespace, and XML entities are decoded. No XML
    parser runs and no entity is expanded beyond the predefined and numeric ones. A part with
    fewer than two runs is left to the raw and HTML-unescaped views of the member itself.
    """
    if not _OOXML_TEXT_PART.match(name) or b"<" not in data[:1024]:
        return
    parts: list[str] = []
    runs = 0
    for count, match in enumerate(_OOXML_TOKEN.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        token = match.group()
        text = match.group(1)
        if text is not None:
            runs += 1
            parts.append(html.unescape(text.decode("utf-8", errors="replace")))
        elif token.startswith(b"</"):
            parts.append("\n")
        elif token.startswith(b"<w:tab"):
            parts.append("\t")
        else:
            parts.append("\n")
    if runs >= 2:
        yield from _with_folded("ooxml-text", "".join(parts), budget)


# A worksheet part, where Excel and streaming writers keep inline strings (t="inlineStr").
_SHEET_PART = re.compile(r"(?i)^xl/worksheets/[^/]+\.xml$")
_COMMENT_PART = re.compile(r"(?i)^(xl/comments\d*\.xml|ppt/comments/[^/]+\.xml)$")
# Cell/comment boundaries, phonetic runs, paragraph breaks, and text runs, in order.
_CELL_TOKEN = re.compile(
    rb"<(/?)(?:[A-Za-z][\w.-]{0,32}:)?(is|rPh|comment|cm|p|br)\b[^<>]{0,4096}>"
    rb"|<(?:[A-Za-z][\w.-]{0,32}:)?t(?:\s[^<>]{0,4096})?>([^<]*)</(?:[A-Za-z][\w.-]{0,32}:)?t>"
)
# About 70 microseconds a piece, so the cap stays well inside the 30 s scan deadline.
MAX_TEXT_PIECES = 100_000


def ooxml_cell_texts(name: str, data: bytes, budget: Budget) -> list[str]:
    """The text of each worksheet inline-string cell that is split across two or more runs.

    A cell whose text sits in one run is contiguous in the part's raw bytes already. Each cell is
    its own piece, so text from two cells is never joined into one phrase. Phonetic runs (rPh,
    the furigana a Japanese cell carries) are not part of the shown text. One linear pass over
    the tags; no XML parser runs and no entity is expanded beyond the predefined and numeric
    ones.
    """
    if not _SHEET_PART.match(name) or b"inlineStr" not in data:
        return []
    return _ooxml_pieces(data, budget, b"is")


def ooxml_comment_texts(name: str, data: bytes, budget: Budget) -> list[str]:
    """Join rich-text runs within each Excel or modern PowerPoint comment, never across comments."""
    if not _COMMENT_PART.fullmatch(name):
        return []
    return _ooxml_pieces(data, budget, b"comment" if name.lower().startswith("xl/") else b"cm")


def _ooxml_pieces(data: bytes, budget: Budget, boundary: bytes) -> list[str]:
    cells: list[str] = []
    runs: list[bytes] = []
    inside = phonetic = False
    count_runs = 0
    for count, match in enumerate(_CELL_TOKEN.finditer(data)):
        if count % 4096 == 0:
            budget.check()
        closing, tag, text = match.group(1), match.group(2), match.group(3)
        if tag == b"rPh":
            phonetic = not closing and not match.group().endswith(b"/>")
        elif tag == boundary:
            if closing and inside and count_runs >= 2:
                if len(cells) >= MAX_TEXT_PIECES:
                    raise ContentLimit("text pieces exceed 100000")
                cells.append("".join(html.unescape(run.decode("utf-8", "replace")) for run in runs))
            inside = not closing and not match.group().endswith(b"/>")
            runs = []
            count_runs = 0
            phonetic = False
        elif inside and (tag == b"p" and closing or tag == b"br"):
            runs.append(b"\n")
        elif inside and not phonetic and text is not None:
            runs.append(text)
            count_runs += 1
    return cells


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
    family = ""
    expected = -1

    def flush() -> None:
        if len(lines) >= 2:
            if len(blocks) >= MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")
            blocks.append("\n".join(lines))
        lines.clear()

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
    changed = False
    fence = ""
    depth = 0

    def flush() -> None:
        nonlocal changed, depth
        if changed and parts:
            if len(blocks) >= MAX_TEXT_PIECES:
                raise ContentLimit("text pieces exceed 100000")
            blocks.append("\n".join(parts))
        parts.clear()
        changed = False
        depth = 0

    for count, line in enumerate(text.splitlines()):
        if count % 4096 == 0:
            budget.check()
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


def _pdf_value(tokens: list[bytes], index: int, nesting: int = 0) -> tuple[PdfValue, int]:
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
            entries[key], index = _pdf_value(tokens, index + 1, nesting + 1)
        return entries, index + 1
    if token == b"[":
        items: list[PdfValue] = []
        index += 1
        while tokens[index] != b"]":
            item, index = _pdf_value(tokens, index, nesting + 1)
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
