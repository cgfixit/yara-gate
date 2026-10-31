"""Bounded in-memory content views. Member names are never extracted to disk."""

import base64
import binascii
import email
import email.errors
import email.message
import email.policy
import gzip
import html
import io
import re
import stat
import tarfile
import time
import unicodedata
import zipfile
import zlib
from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from yara_gate.filetype import sniff, utf16_encoding
from yara_gate.heuristics import _PDF_LEX, _decode_pdf_name

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
_WORD = re.compile(r"[^\W_]+")
_LEET_TOKEN = re.compile(r"[^\W_]*[0134578@$][^\W_@$]*(?:[0134578@$][^\W_@$]*)*")
# Four or more single letters separated by one space, dot, dash, underscore, or asterisk.
_SPACED = re.compile(r"(?<![^\W_])(?:[^\W\d_][ .\-_*]){3,}[^\W\d_](?![^\W_])")
_SPACERS = re.compile(r"[ .\-_*]")
# Control characters other than tab, CR, and LF, which is what the Cc filter removes from ASCII.
_ASCII_CONTROL = re.compile(r"[\x00-\x1f]")
_ASCII_CONTROL_DELETE = dict.fromkeys([*range(0, 9), 11, 12, *range(14, 32), 127])

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
_PDF_OBJ_END = re.compile(rb"endobj|stream")
_PDF_MAX_NESTING = 64
_PDF_INT = re.compile(rb"[+-]?[0-9]+")
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


def archive_kind(data: bytes) -> str | None:
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "zip"
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    if _mime_message(data):
        return "mime"
    return None


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


def content_units(unit: ContentUnit, budget: Budget, depth: int = 0) -> Iterator[ContentUnit]:
    budget.check()
    if unit.data.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"BZh", b"\xfd7zXZ\x00")):
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
    ):
        raise ContentLimit("archive unreadable or encrypted") from None
    yield unit


def _members(unit: ContentUnit, kind: str, budget: Budget) -> Iterator[tuple[int, str, bytes]]:
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(unit.data)) as archive:
            if len(archive.infolist()) + budget.members > MAX_MEMBERS:
                raise ContentLimit("archive members exceed 1000")
            for index, info in enumerate(archive.infolist()):
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
                with archive.open(info) as stream:
                    yield index, info.filename, budget.read(stream)
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
    else:
        budget.member()
        name = Path(unit.name).stem
        if unit.name.lower().endswith(".tgz"):
            name += ".tar"
        with gzip.GzipFile(fileobj=io.BytesIO(unit.data)) as compressed:
            yield 0, name, budget.read(compressed)


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
            yield "json-unescaped", _derived(decoded, budget)
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


def folded_text(text: str) -> str:
    """Return ``text`` with look-alike spellings folded to plain letters, for a derived view.

    NFKC compatibility normalization (fullwidth and other presentation forms), removal of format
    controls and of control characters other than tab, CR, and LF, Cyrillic and Greek look-alikes
    folded to Latin inside mixed-script tokens, letters spaced one apart rejoined, and digit or
    symbol stand-ins folded inside tokens that mix them with letters. Russian, Greek, and ordinary
    numbers stay as written. The result is a view; the original bytes are scanned unchanged.
    """
    if not text.strip(" \t\r\n"):
        return text
    folded = unicodedata.normalize("NFKC", text)
    if folded.isascii():
        # Same result as the per-character filter below, without a Python loop over every
        # character of a large ASCII body; every multi-line file has a CR or LF.
        if _ASCII_CONTROL.search(folded) is not None:
            folded = folded.translate(_ASCII_CONTROL_DELETE)
    else:
        folded = "".join(
            char
            for char in folded
            if char in "\t\r\n"
            or (
                unicodedata.category(char) not in ("Cf", "Cc") and not 0xFE00 <= ord(char) <= 0xFE0F
            )
        )
    if not folded.isascii():
        folded = _WORD.sub(_fold_confusables, folded)
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
    if any(char.isalpha() for char in word):
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
        yield "ooxml-text", _derived("".join(parts), budget)


def pdf_views(data: bytes, budget: Budget) -> Iterator[tuple[str, bytes]]:
    """Inflate FlateDecode streams that hold text and return them as one ``pdf-flate`` view.

    The filter is read from the stream's own dictionary, the one value between the object
    header and ``stream``, so nested dictionaries such as ``/DecodeParms`` do not hide it. A PNG
    or TIFF predictor is reversed after inflation; one a reader rejects keeps the stream out.
    ASCIIHexDecode and ASCII85Decode stages before FlateDecode are decoded first, and the
    ``/DecodeParms`` entry at FlateDecode's position in the chain selects the predictor.
    When no dictionary parses, a stream is inflated if ``/FlateDecode`` is in the 1 KB before it.
    Content and object streams are text once inflated, so the lexical rules and PDF name
    checks can read them. Fonts, images, and other binary streams are dropped after inflation.
    Each stream is capped at the file limit, the total at the shared expansion budget, and the
    deadline is checked between chunks, so a decompression bomb ends the scan as incomplete.
    """
    if not data.startswith(b"%PDF"):
        return
    parts: list[bytes] = []
    objects: dict[tuple[int, int], PdfValue | None] = {}
    for count, start in enumerate(_PDF_STREAM.finditer(data)):
        if count >= MAX_PDF_STREAMS:
            raise ContentLimit("pdf streams exceed 2000")
        budget.check()
        if data[max(0, start.start() - 3) : start.start()] == b"end":
            continue
        stream_dict = _pdf_stream_dict(data, start.start())
        stages: tuple[bytes, ...] = ()
        if stream_dict is None:
            # No parsable dictionary ends at this keyword: inflate when FlateDecode is near.
            if b"/FlateDecode" not in data[max(0, start.start() - 1024) : start.start()]:
                continue
            predictor = (1, 1, 8, 1)
        else:
            plan = _pdf_flate_plan(data, stream_dict, objects)
            found = None if plan is None else _pdf_predictor(plan[1])
            if plan is None or found is None:
                # No FlateDecode after the ASCII stages, or a predictor this view cannot reverse.
                continue
            stages, predictor = plan[0], found
        end = _PDF_END.search(data, start.end())
        body = data[start.end() : end.start() if end else len(data)]
        for stage in stages:
            body = _ascii_hex(body, budget) if stage == _PDF_HEX else _ascii85(body, budget)
        inflated = _inflate(body, budget)
        if inflated:
            inflated = _unpredict(inflated, predictor, budget)
        if inflated and sniff(inflated) == "text":
            parts.append(inflated)
    if parts:
        yield "pdf-flate", b"\n".join(parts)


def _pdf_tokens(data: bytes, position: int, stop: int) -> list[bytes] | None:
    """Tokens in ``data[position:stop]``, or None when a string crosses ``stop``.

    Whitespace and comments are dropped, a literal string becomes ``()``, a hex string ``<>``,
    and names are #xx-decoded.
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
    """The dictionary between the nearest object header and the ``stream`` keyword."""
    header = _last_match(_PDF_OBJ, data, max(0, stream_at - _PDF_DICT_WINDOW), stream_at)
    if header is None:
        return None
    tokens = _pdf_tokens(data, header.end(), stream_at)
    if not tokens or tokens[0] != b"<<":
        return None
    try:
        value, used = _pdf_value(tokens, 0)
    except (IndexError, ValueError):
        return None
    return value if isinstance(value, dict) and used == len(tokens) else None


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
            # Stop at the object's end: a lone ``>`` after it, such as an ASCIIHex stream's end
            # marker or a byte in a binary stream, has no token and would void the whole window.
            stop = min(len(data), header.end() + 4096)
            found = _PDF_OBJ_END.search(data, header.end(), stop)
            tokens = _pdf_tokens(data, header.end(), found.start() if found else stop)
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
    row = (colors * bits * columns + 7) // 8
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
                line[index] = (line[index] + line[index - pixel]) & 0xFF
        elif kind == 2:
            line = bytearray((a + b) & 0xFF for a, b in zip(line, previous, strict=False))
        elif kind == 3:
            for index in range(size):
                left = line[index - pixel] if index >= pixel else 0
                line[index] = (line[index] + ((left + previous[index]) >> 1)) & 0xFF
        elif kind == 4:
            for index in range(size):
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
