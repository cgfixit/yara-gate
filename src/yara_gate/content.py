"""Bounded in-memory content views. Member names are never extracted to disk."""

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
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from yara_gate.filetype import sniff, utf16_encoding
from yara_gate.heuristics import PdfRawObjects, pdf_stream_parameters

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

    Content and object streams are text once inflated, so the lexical rules and PDF name
    checks can read them. Fonts, images, and other binary streams are dropped after inflation.
    Each stream is capped at the file limit, the total at the shared expansion budget, and the
    deadline is checked between chunks, so a decompression bomb ends the scan as incomplete.
    """
    if not data.startswith(b"%PDF"):
        return
    parts: list[bytes] = []
    for count, start in enumerate(_PDF_STREAM.finditer(data)):
        if count >= MAX_PDF_STREAMS:
            raise ContentLimit("pdf streams exceed 2000")
        budget.check()
        inflated = _decoded_stream(data, start, budget)
        if inflated and sniff(inflated) == "text":
            parts.append(inflated)
    if parts:
        yield "pdf-flate", b"\n".join(parts)


_OBJSTM_TYPE = re.compile(rb"/Type\s*/ObjStm(?![^\x00\t\n\f\r /<>\[\]()%])")
_PDF_OBJ_HEADER = re.compile(rb"(?<![0-9])[0-9]+[\x00\t\n\f\r ]+[0-9]+[\x00\t\n\f\r ]+obj\b")
_OBJSTM_N = re.compile(rb"/N\s+(\d{1,6})(?!\d)")
_OBJSTM_FIRST = re.compile(rb"/First\s+(\d{1,9})(?!\d)")
MAX_OBJSTM_OBJECTS = 100_000


class PdfObjects:
    """Every definition of a PDF object in one file: raw ``N G obj`` and object-stream members.

    Object streams are indexed on first use, so a file pays for the extra inflation only when
    a reference does not settle without it.

    ISO 32000-1 7.5.7: an object stream's dictionary has /Type /ObjStm, /N, and /First; its
    decoded data starts with /N pairs of object number and offset, and the objects follow at
    /First. Objects in a stream have generation 0. A stream with another filter, decode
    parameters, a header that does not parse, or offsets that leave the data is skipped, so
    its objects stay unresolved. Inflation shares the scan's budget and limits.
    """

    def __init__(self, data: bytes, budget: Budget) -> None:
        self._data = data
        self._budget = budget
        self._raw = PdfRawObjects(data)
        self._objects: dict[int, list[bytes]] | None = None

    def __call__(self, number: int, generation: int) -> list[bytes]:
        found = list(self._raw(number, generation))
        if generation == 0:
            if self._objects is None:
                self._objects = _index_object_streams(self._data, self._budget)
            found.extend(self._objects.get(number, []))
        return found


def _index_object_streams(data: bytes, budget: Budget) -> dict[int, list[bytes]]:
    objects: dict[int, list[bytes]] = {}
    if not data.startswith(b"%PDF") or b"/ObjStm" not in data:
        return objects
    for count, start in enumerate(_PDF_STREAM.finditer(data)):
        if count >= MAX_PDF_STREAMS:
            raise ContentLimit("pdf streams exceed 2000")
        budget.check()
        head = _stream_dictionary(data, start.start())
        if _OBJSTM_TYPE.search(head) is None:
            continue
        count_match, first_match = _OBJSTM_N.search(head), _OBJSTM_FIRST.search(head)
        if count_match is None or first_match is None:
            continue
        total, first = int(count_match.group(1)), int(first_match.group(1))
        if total > MAX_OBJSTM_OBJECTS:
            continue
        decoded = _decoded_stream(data, start, budget)
        if not decoded or first > len(decoded):
            continue
        header = decoded[:first].split()
        if len(header) < 2 * total or not all(item.isdigit() for item in header[: 2 * total]):
            continue
        numbers = [int(item) for item in header[0 : 2 * total : 2]]
        offsets = [int(item) for item in header[1 : 2 * total : 2]]
        if any(b < a for a, b in zip(offsets, offsets[1:], strict=False)):
            continue
        if offsets and first + offsets[-1] > len(decoded):
            continue
        bounds = [*offsets[1:], len(decoded) - first]
        for number, offset, stop in zip(numbers, offsets, bounds, strict=True):
            objects.setdefault(number, []).append(decoded[first + offset : first + stop])
    return objects


def _stream_dictionary(data: bytes, stream_start: int) -> bytes:
    """The dictionary of the stream whose keyword starts at ``stream_start``.

    It is the text after the last ``N G obj`` in the 1 KiB before the keyword, so a nested
    dictionary such as ``/DecodeParms << ... >>`` stays part of it and an earlier object's
    dictionary does not.
    """
    head = data[max(0, stream_start - 1024) : stream_start]
    ends = [match.end() for match in _PDF_OBJ_HEADER.finditer(head)]
    return head[ends[-1] :] if ends else head


def _decoded_stream(data: bytes, start: re.Match[bytes], budget: Budget) -> bytes | None:
    """Inflate one FlateDecode stream and undo a PNG or TIFF predictor, or return None."""
    flate, parameters, image = pdf_stream_parameters(_stream_dictionary(data, start.start()))
    if not flate:
        return None
    end = _PDF_END.search(data, start.end())
    inflated = _inflate(data[start.end() : end.start() if end else len(data)], budget)
    predictor = parameters.get(b"/Predictor", 1)
    # Image samples are not text or objects; reversing their predictor would only cost time.
    if not inflated or predictor <= 1 or image:
        return inflated
    columns = parameters.get(b"/Columns", 1)
    colors = parameters.get(b"/Colors", 1)
    bits = parameters.get(b"/BitsPerComponent", 8)
    if not (0 < columns <= 1 << 20 and 0 < colors <= 32 and bits in (1, 2, 4, 8, 16)):
        return None
    if predictor >= 10:
        return _png_unpredict(inflated, columns, colors, bits, budget)
    if predictor == 2 and bits == 8:
        return _tiff_unpredict(inflated, columns, colors, budget)
    # A predictor the reader would not apply either: the stream is not text it shows.
    return None


def _png_unpredict(
    data: bytes, columns: int, colors: int, bits: int, budget: Budget
) -> bytes | None:
    """Reverse PNG row filters (PDF predictors 10 to 15): each row starts with its filter type."""
    row = (columns * colors * bits + 7) // 8
    step = max(1, (colors * bits + 7) // 8)
    output = bytearray()
    previous = bytearray(row)
    for count, position in enumerate(range(0, len(data), row + 1)):
        if count % 1024 == 0:
            budget.check()
        kind = data[position]
        current = bytearray(data[position + 1 : position + 1 + row])
        size = len(current)
        if kind == 2:
            current = bytearray((x + y) & 0xFF for x, y in zip(current, previous, strict=False))
        elif kind in (1, 3, 4):
            for i in range(size):
                left = current[i - step] if i >= step else 0
                up = previous[i]
                if kind == 1:
                    current[i] = (current[i] + left) & 0xFF
                elif kind == 3:
                    current[i] = (current[i] + ((left + up) >> 1)) & 0xFF
                else:
                    corner = previous[i - step] if i >= step else 0
                    guess = left + up - corner
                    pa, pb, pc = abs(guess - left), abs(guess - up), abs(guess - corner)
                    near = left if pa <= pb and pa <= pc else up if pb <= pc else corner
                    current[i] = (current[i] + near) & 0xFF
        elif kind != 0:
            return None
        output.extend(current)
        previous = current + bytearray(row - size)
    return bytes(output)


def _tiff_unpredict(data: bytes, columns: int, colors: int, budget: Budget) -> bytes:
    """Reverse TIFF predictor 2 for 8-bit components: each byte adds the one a pixel back."""
    row = columns * colors
    output = bytearray(data)
    for count, start in enumerate(range(0, len(output), row)):
        if count % 1024 == 0:
            budget.check()
        for i in range(start + colors, min(start + row, len(output))):
            output[i] = (output[i] + output[i - colors]) & 0xFF
    return bytes(output)


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
