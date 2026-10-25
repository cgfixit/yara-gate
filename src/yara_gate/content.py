"""Bounded in-memory content views. Member names are never extracted to disk."""

import gzip
import html
import io
import re
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

MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_EXTRACT_BYTES = 500 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 3
MAX_MEMBERS = 1000
MAX_PDF_STREAMS = 2000

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
_PDF_STREAM = re.compile(rb"stream\r?\n")
_PDF_END = re.compile(rb"\r?\n?endstream")


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
    return None


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
    except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile, tarfile.TarError):
        raise ContentLimit("archive unreadable or encrypted") from None
    yield unit


def _members(unit: ContentUnit, kind: str, budget: Budget) -> Iterator[tuple[int, str, bytes]]:
    if kind == "zip":
        with zipfile.ZipFile(io.BytesIO(unit.data)) as archive:
            if len(archive.infolist()) + budget.members > MAX_MEMBERS:
                raise ContentLimit("archive members exceed 1000")
            for index, info in enumerate(archive.infolist()):
                budget.member()
                if info.is_dir():
                    continue
                if info.file_size > MAX_FILE_BYTES:
                    raise ContentLimit("archive member exceeds 100MB")
                if info.flag_bits & 1:
                    raise ContentLimit("archive unreadable or encrypted")
                with archive.open(info) as stream:
                    yield index, info.filename, budget.read(stream)
    elif kind == "tar":
        # Stream mode avoids collecting all member metadata before enforcing the count cap.
        with tarfile.open(fileobj=io.BytesIO(unit.data), mode="r|") as archive:
            for index, entry in enumerate(archive):
                budget.member()
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
    if stripped[:1] in ("{", "[") and "\\" in stripped:
        decoded = _JSON_ESCAPE.sub(_json_escape, text)
        if decoded != text:
            yield "json-unescaped", _derived(decoded, budget)
    # ASCII cannot contain Cf characters or Unicode variation selectors.
    # Check after unescaping: an ASCII entity can introduce either one.
    if unescaped.isascii():
        return
    # Inspect hidden formatting without modifying the original or interpreting it as authority.
    normalized = "".join(
        char
        for char in unescaped
        if unicodedata.category(char) != "Cf" and not 0xFE00 <= ord(char) <= 0xFE0F
    )
    if normalized != unescaped:
        yield "format-controls-removed", _derived(normalized, budget)


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
        head = data[max(0, start.start() - 1024) : start.start()]
        if b"/FlateDecode" not in head or b"/FlateDecode" not in head[head.rfind(b"<<") :]:
            continue
        end = _PDF_END.search(data, start.end())
        inflated = _inflate(data[start.end() : end.start() if end else len(data)], budget)
        if inflated and sniff(inflated) == "text":
            parts.append(inflated)
    if parts:
        yield "pdf-flate", b"\n".join(parts)


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
