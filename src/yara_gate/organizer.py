"""Folded text properties from calendar events and contact cards."""

import io
import re
from collections.abc import Iterator

from yara_gate.content import MAX_TEXT_PIECES, Budget, ContentLimit

_TEXT_ESCAPE = re.compile(rb"\\([\\,;nN])")


def _paragraphs(value: bytearray, budget: Budget) -> Iterator[str]:
    """Unescape TEXT once, keeping explicit line breaks as separate pieces."""
    data = memoryview(value)
    paragraph = bytearray()
    start = 0
    for count, match in enumerate(_TEXT_ESCAPE.finditer(value)):
        if count % 1024 == 0:
            budget.check()
        paragraph.extend(data[start : match.start()])
        start = match.end()
        if match[1] in (b"n", b"N"):
            yield paragraph.decode("utf-8")
            paragraph.clear()
        else:
            paragraph.extend(match[1])
    paragraph.extend(data[start:])
    yield paragraph.decode("utf-8")


def organizer_text(data: bytes, budget: Budget) -> tuple[str, list[str]] | None:
    """Read changed plain-text properties of one VCALENDAR 2.0 or VCARD 4.0.

    RFC 5545 §3.1 and RFC 6350 §3.2 remove exactly one continuation whitespace
    byte before UTF-8 decoding. Separate properties and components stay separate.
    """
    fields: tuple[bytes, ...]
    first = data[:17].upper()
    if first.startswith((b"BEGIN:VCALENDAR\r\n", b"BEGIN:VCALENDAR\n")):
        root, version, view = b"VCALENDAR", b"2.0", "icalendar-text"
        fields = (b"SUMMARY", b"DESCRIPTION", b"LOCATION")
    elif first.startswith((b"BEGIN:VCARD\r\n", b"BEGIN:VCARD\n")):
        root, version, view = b"VCARD", b"4.0", "vcard-text"
        fields = (b"FN", b"NOTE", b"TITLE", b"ROLE")
    else:
        return None
    stack: list[bytes] = []
    seen_version = False
    pieces: dict[str, None] = {}
    value: bytearray | None = None
    folded = False
    structural = False
    ended = False
    for index, raw in enumerate(io.BytesIO(data)):
        if index % 1024 == 0:
            budget.check()
        line = raw.removesuffix(b"\n").removesuffix(b"\r")
        if line.startswith((b" ", b"\t")):
            if structural:
                return None
            if value is not None:
                value.extend(line[1:])
                folded = True
            continue
        if value is not None and folded:
            try:
                for paragraph in _paragraphs(value, budget):
                    if paragraph:
                        pieces[paragraph] = None
                    if len(pieces) > MAX_TEXT_PIECES:
                        raise ContentLimit("text pieces exceed 100000")
            except UnicodeDecodeError:
                pass
        value, folded, structural = None, False, False
        if ended:
            if line:
                return None
            continue
        colon = line.find(b":", 0, 16)
        if colon < 0:
            continue
        key = line[:colon].upper()
        if key in (b"BEGIN", b"END"):
            structural = True
            if len(line) > 80:
                return None
            component = line[colon + 1 :].upper()
            if key == b"BEGIN":
                if len(stack) >= 32:
                    return None
                stack.append(component)
            elif not stack or stack.pop() != component:
                return None
            else:
                ended = not stack
        elif key == b"VERSION" and len(stack) == 1:
            if seen_version or line[colon + 1 :] != version:
                return None
            structural = seen_version = True
        elif key in fields and (
            (root == b"VCARD" and stack == [root])
            or (root == b"VCALENDAR" and stack == [root, b"VEVENT"])
        ):
            value = bytearray(line[colon + 1 :])
    return (view, list(pieces)) if ended and seen_version and pieces else None
