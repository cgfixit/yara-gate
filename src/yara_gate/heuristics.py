"""Office, PDF, and embedded-executable checks that sit beside YARA."""

import codecs
import io
import json
import re
import unicodedata
import zipfile
from collections.abc import Callable, Iterable, Iterator, Sequence
from pathlib import Path
from typing import Protocol

from yara_gate.filetype import OFFICE_EXTS, OLE, embedded_exec_offset, sniff
from yara_gate.models import Finding, FindingSource, Severity


class PdfObjectLookup(Protocol):
    """Every definition's bytes after ``obj`` for an object number and generation."""

    def __call__(self, number: int, generation: int, /) -> list[bytes]: ...


PDF_TOKENS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
)
OFFICE_KEYWORDS = ("Shell", "CreateObject", "URLDownloadToFile")


_LETTER_PREFIXES = (
    "ARABIC LETTER",
    "DEVANAGARI LETTER",
    "BENGALI LETTER",
    "GURMUKHI LETTER",
    "GUJARATI LETTER",
    "ORIYA LETTER",
    "TAMIL LETTER",
    "TELUGU LETTER",
    "KANNADA LETTER",
    "MALAYALAM LETTER",
    "SINHALA LETTER",
)
_VARIATION = frozenset({0xFE0E, 0xFE0F})


def heuristic_findings(
    path: Path, data: bytes, objects: PdfObjectLookup | None = None
) -> tuple[list[Finding], str | None]:
    findings = pdf_findings(data, objects)
    findings.extend(embedded_findings(data))
    findings.extend(pickle_reduce_findings(path, data))
    findings.extend(model_header_findings(path, data))
    findings.extend(keras_config_findings(path, data))
    findings.extend(ooxml_structure_findings(path, data))
    findings.extend(mcp_tool_findings(path, data))
    office, error = office_findings(path, data)
    findings.extend(office)
    if error is None and pdf_encrypted(data):
        # The strings and streams a reader decrypts are ciphertext here, so the text is unread.
        error = "encrypted pdf"
    return findings, error


def joiner_findings(text: str) -> list[Finding]:
    """Note a ZWNJ or ZWJ that is not holding an emoji or a joining script together.

    One stray joiner is a paste artifact as often as a hiding trick, so it is a note; the
    conjunction with a lexical note in the same member is ``control_conjunction``.
    """
    if "\u200c" not in text and "\u200d" not in text:
        return []
    findings: list[Finding] = []
    offset = 0
    chars = list(text)
    for index, char in enumerate(chars):
        size = len(char.encode("utf-8"))
        if char in {"\u200c", "\u200d"} and not _joiner_allowed(chars, index):
            findings.append(
                Finding(
                    rule_id="heuristic_invisible_joiner",
                    offset=offset,
                    length=size,
                    severity=Severity.note,
                    source=FindingSource.heuristic,
                )
            )
        offset += size
    return findings


# UTS #51 emoji tag sequence for a subdivision flag: U+1F3F4, then tag letters or digits, then
# CANCEL TAG. CLDR subdivision codes are a region (2 letters or 3 digits) plus 1 to 3 more.
_EMOJI_TAG_SEQUENCE = re.compile(
    "\U0001f3f4[\U000e0030-\U000e0039\U000e0061-\U000e007a]{3,6}\U000e007f"
)
_TAG = re.compile("[\U000e0000-\U000e007f]")


def tag_findings(text: str) -> list[Finding]:
    """Block a Unicode tag character outside an emoji subdivision-flag sequence.

    Tag characters render as nothing and map one to one onto ASCII, which is how instructions
    are smuggled past a human reader (ASCII smuggling). Unicode deprecates them for every use
    but emoji tag sequences, so one outside a flag has no ordinary meaning. The offset is the
    first such character in the UTF-8 encoding of ``text``.
    """
    if _TAG.search(text) is None:
        return []
    remainder = _EMOJI_TAG_SEQUENCE.sub(lambda match: "\0" * len(match.group()), text)
    found = _TAG.search(remainder)
    if found is None:
        return []
    return [
        Finding(
            rule_id="heuristic_unicode_tag",
            offset=len(text[: found.start()].encode("utf-8")),
            length=4,
            severity=Severity.block,
            source=FindingSource.heuristic,
        )
    ]


_CONTEXT = 16

# The Unicode-control signals that are notes on their own.
UNICODE_CONTROL_RULES = frozenset(
    {
        "agent_invisible_unicode",
        "agent_bidi_override",
        "agent_bidi_formatting",
        "heuristic_invisible_joiner",
    }
)


def control_in_text(data: bytes, offset: int, length: int) -> bool:
    """True when the bytes on either side of a control match read as UTF-8 text.

    The control rules match UTF-8 byte sequences such as E2 80 8B (a zero-width space). In a
    buffer that can hold raw sample values, such as decoded PDF streams, those bytes also occur
    in image pixels, where they are not a character. A match is text when the 16 bytes before
    it or the 16 bytes after it decode as UTF-8, allowing a sequence cut at the window's far
    edge; an empty side is text. Hiding a real control between invalid bytes on both sides
    means a UTF-8 reader shows replacement characters next to it.
    """
    before = data[max(0, offset - _CONTEXT) : offset]
    after = data[offset + length : offset + length + _CONTEXT]
    # Up to three continuation bytes at the far edge belong to a character that starts outside.
    trimmed = before.lstrip(bytes(range(0x80, 0xC0)))
    if len(before) - len(trimmed) <= 3 and _utf8(trimmed, final=True):
        return True
    return _utf8(after, final=False)


def _utf8(data: bytes, *, final: bool) -> bool:
    try:
        codecs.getincrementaldecoder("utf-8")("strict").decode(data, final=final)
    except UnicodeDecodeError:
        return False
    return True


def control_conjunction(findings: Sequence[Finding]) -> Finding | None:
    """Return an advisory finding when one member has a control note and a second note.

    ``findings`` are one content unit's findings across all of its views. A lone control is a
    note; a control together with another note in the same member, which is how a phrase split
    by a zero-width character shows up (the phrase matches in format-controls-removed), is two
    independent hits. The finding takes the view of the other note.
    """
    if not any(
        f.rule_id in UNICODE_CONTROL_RULES and f.severity is Severity.note for f in findings
    ):
        return None
    other = next(
        (
            f
            for f in findings
            if f.severity is Severity.note and f.rule_id not in UNICODE_CONTROL_RULES
        ),
        None,
    )
    if other is None:
        return None
    return Finding(
        rule_id="heuristic_unicode_control_conjunction",
        severity=Severity.advisory,
        source=FindingSource.heuristic,
        view=other.view,
    )


def base64_run_signals(data: bytes, *, samples: bool = False) -> tuple[bool, bool]:
    """Return (blob, executable) for base64 runs of 400 or more characters in ``data``.

    ``blob`` is a run that is not media, a font, a PEM body, or an SSH key: its first characters
    are not an image, audio, video, or font header, and it does not follow a ``data:`` media URI,
    a PEM header, or an SSH key type. ``executable`` is a run whose decoded head is MZ, ELF, or
    Mach-O. Each exemption covers its own run. The YARA rules agent_base64_blob and
    agent_base64_executable read these as globals and keep their ids and verdict_on_match.

    ``samples`` marks a buffer that can hold raw sample values, such as decoded PDF streams,
    where a run of image pixels reads as base64. There a run is a blob only when it still has
    400 characters after each repeat is cut to one copy (``_b64_holds_data``, flat areas) and
    400 characters outside windows that read as neighboring pixels (``_b64_unsampled``, grainy
    areas). Content a payload carries counts in both. The executable check is unchanged.
    """
    blob = exe = False
    for match in _B64_RUN.finditer(data):
        start = match.start()
        head = data[start : start + 16]
        if _B64_EXE.match(head):
            exe = True
        if not blob and _B64_MEDIA.match(head) is None:
            before = data[max(0, start - 128) : start]
            blob = _B64_PREFIX.search(before) is None
            if blob and samples:
                end = match.end()
                blob = _b64_holds_data(data, start, end) and _b64_unsampled(data, start, end)
        if blob and exe:
            break
    return blob, exe


def _b64_holds_data(data: bytes, position: int, stop: int) -> bool:
    """True when ``data[position:stop]`` keeps 400 characters once repeats are cut to one copy.

    A repeat is a unit of 1 to 12 characters that occurs four or more times in a row: a flat
    area of 8-bit gray, RGB, or CMYK pixels, a two-pixel dither, or 16-bit samples. What is cut
    can be rebuilt from the copy that stays, so a run below 400 carries no more than a shorter
    run the rule already ignores. The walk reads about 450 characters at a time and stops at
    400. A repeat cut short at the end of a window is counted as kept, never as cut.
    """
    kept = 0
    while position < stop and kept < _B64_MIN:
        # A repeat is at most 48 characters before it has four copies, so one that starts in a
        # window's last 48 characters is left for the next window.
        end = min(stop, position + _B64_MIN - kept + 48)
        match = _B64_REPEAT.search(data, position, end)
        if match is None:
            step = end if end == stop else end - 48
            kept += step - position
            position = step
            continue
        unit = match.group(1)
        kept += match.start() - position + len(unit)
        position = match.end()
        block = unit * max(1, 4096 // len(unit))
        while data.startswith(block, position) and position + len(block) <= stop:
            position += len(block)
        while data.startswith(unit, position) and position + len(unit) <= stop:
            position += len(unit)
    return kept >= _B64_MIN


def _b64_unsampled(data: bytes, position: int, stop: int) -> bool:
    """True when ``data[position:stop]`` has 400 characters outside sample-like windows.

    The run is read in 64-character windows from its start. A window is sample-like when, at
    one lag of 1, 2, 3, 4, 6, or 8 bytes (a gray, gray+alpha, RGB, RGBA or CMYK, 16-bit RGB, or
    16-bit CMYK pixel), at least 58 of its 64 characters are near the character that lag
    before: within 4 of it, and at most 7. Neighboring pixels of a photo or a noisy gradient
    differ by a few levels; base64 of text, UTF-16LE or UTF-32LE text, JSON, compressed data,
    or random bytes reached at most 52 of 64 when measured, and base64 of hex text 55. A
    window is kept or cut whole, and a partial last window is kept, so a payload between
    sample-like stretches loses at most the characters that share a cut window with them.
    The near test runs in C: the bytes are bucketed by 8 on two grids offset by 4, two bytes
    within 4 share a bucket on one grid, and a big-integer XOR marks the positions where
    neither grid matches.
    """
    kept = 0
    while position < stop and kept < _B64_MIN:
        windows = min(stop - position, _B64_CHUNK) // _B64_WINDOW
        if windows == 0:
            kept += stop - position
            break
        # Each window's first characters are compared with the bytes just before it.
        lead = max(0, position - _B64_LAGS[-1])
        end = position + windows * _B64_WINDOW
        grids = [data[lead:end].translate(table) for table in _B64_GRIDS]
        far = [_b64_far(grids, lag, position - lead) for lag in _B64_LAGS]
        for begin in range(0, windows * _B64_WINDOW, _B64_WINDOW):
            # Not sample-like: more than 64 - 58 far characters at every lag.
            if all(
                mask.count(1, begin, begin + _B64_WINDOW) > _B64_WINDOW - _B64_NEAR for mask in far
            ):
                kept += _B64_WINDOW
                if kept >= _B64_MIN:
                    return True
        position = end
    return kept >= _B64_MIN


def _b64_far(grids: list[bytes], lag: int, offset: int) -> bytes:
    """One byte per position from ``offset`` on, 1 where no grid matches the byte ``lag`` back.

    A position with nothing ``lag`` before it counts as far.
    """
    start = max(offset, lag)
    head = b"\x01" * (start - offset)
    count = len(grids[0]) - start
    if count <= 0:
        return head
    found = -1
    for grid in grids:
        now = int.from_bytes(grid[start:], "big")
        back = int.from_bytes(grid[start - lag : start - lag + count], "big")
        found &= int.from_bytes((now ^ back).to_bytes(count, "big").translate(_B64_NONZERO), "big")
    return head + found.to_bytes(count, "big")


def pdf_findings(data: bytes, objects: PdfObjectLookup | None = None) -> list[Finding]:
    if sniff(data) != "pdf":
        return []
    return pdf_token_findings(data, objects)


def pdf_encrypted(data: bytes) -> bool:
    """True when a trailer or XRef stream dictionary has an /Encrypt entry.

    A small top-level tokenizer skips whitespace and comments between tokens (both are legal
    separators), literal and hex strings, and stream bodies, so /Encrypt in page text, a comment,
    or a content stream does not count. The key is compared after #xx decoding, and its value
    must be a dictionary or an indirect reference.
    """
    if sniff(data) != "pdf":
        return False
    if b"Encr" not in data and b"#" not in data:
        return False
    tokens = _pdf_top_tokens(data)
    window: list[bytes] = []
    depth = 0
    root_kind = b""
    last_keyword = b""
    for token in tokens:
        if token == b"<<":
            if depth == 0:
                root_kind = b"trailer" if last_keyword == b"trailer" else b"object"
                window = []
            depth += 1
            window.append(token)
            continue
        if token == b">>":
            depth = max(0, depth - 1)
            if depth == 0 and window:
                window.append(token)
                if _pdf_dict_encrypts(window, root_kind):
                    return True
                window = []
            continue
        if depth:
            window.append(token)
        elif not token.startswith(b"/"):
            last_keyword = token
    return False


def _pdf_dict_encrypts(window: list[bytes], root_kind: bytes) -> bool:
    """Look for a direct /Encrypt key in the outermost dictionary of ``window``."""
    names = [_decode_pdf_name(item) if item.startswith(b"/") else item for item in window]
    if root_kind != b"trailer":
        typed = any(
            names[i] == b"/Type" and names[i + 1] == b"/XRef" for i in range(len(names) - 1)
        )
        if not typed:
            return False
    depth = 0
    for index, item in enumerate(names):
        if item == b"<<":
            depth += 1
        elif item == b">>":
            depth -= 1
        elif depth == 1 and item == b"/Encrypt":
            rest = names[index + 1 : index + 4]
            if rest[:1] == [b"<<"]:
                return True
            if len(rest) == 3 and rest[0].isdigit() and rest[1].isdigit() and rest[2] == b"R":
                return True
    return False


def _pdf_top_tokens(data: bytes, *, mark_strings: bool = False) -> Iterator[bytes]:
    """Yield PDF tokens outside strings, comments, and stream bodies.

    With ``mark_strings``, a literal or hex string yields ``()`` in its place, so a parser can
    tell that a value was present without reading it.
    """
    position = 0
    size = len(data)
    while position < size:
        match = _PDF_LEX.match(data, position)
        if match is None:
            position += 1
            continue
        token = match.group()
        position = match.end()
        first = token[:1]
        if first in b"\x00\t\n\f\r " or first == b"%":
            continue
        if token == b"(":
            position = _skip_pdf_string(data, position)
            if mark_strings:
                yield b"()"
            continue
        if first == b"<" and token != b"<<":
            if mark_strings:
                yield b"()"
            continue
        if token == b"stream":
            end = data.find(b"endstream", position)
            position = size if end < 0 else end + len(b"endstream")
            continue
        yield token


def _skip_pdf_string(data: bytes, position: int) -> int:
    depth = 1
    size = len(data)
    while position < size and depth:
        char = data[position]
        if char == 0x5C:
            position += 2
            continue
        if char == 0x28:
            depth += 1
        elif char == 0x29:
            depth -= 1
        position += 1
    return position


def pdf_token_findings(data: bytes, objects: PdfObjectLookup | None = None) -> list[Finding]:
    """PDF action and embedding names in ``data``, which may be an inflated stream view.

    Every name blocks except an /OpenAction whose every occurrence opens a page: a direct
    destination array, or a /GoTo action dictionary with no /Next. That one is the note
    ``heuristic_pdf_OpenAction_goto``. ``objects`` returns every definition of an object
    number and generation in the whole file, raw or in an object stream, so a reference read
    from an inflated view resolves against the file it came from.
    """
    findings: list[Finding] = []
    for token in PDF_TOKENS:
        found = _pdf_name_span(data, token)
        if found is None:
            continue
        offset, length = found
        rule_id = "heuristic_pdf_" + token.decode("ascii").removeprefix("/")
        severity = Severity.block
        if token == b"/OpenAction" and _open_action_is_goto(data, objects):
            rule_id, severity = "heuristic_pdf_OpenAction_goto", Severity.note
        findings.append(
            Finding(
                rule_id=rule_id,
                offset=offset,
                length=length,
                severity=severity,
                source=FindingSource.heuristic,
            )
        )
    return findings


_PDF_DESTINATIONS = frozenset(
    {b"/XYZ", b"/Fit", b"/FitH", b"/FitV", b"/FitR", b"/FitB", b"/FitBH", b"/FitBV"}
)
_PDF_NUMBER = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)")


def _open_action_is_goto(data: bytes, objects: PdfObjectLookup | None = None) -> bool:
    """True when every /OpenAction in ``data`` only opens a page.

    Every occurrence the name scanner finds is read from its own position, so a malformed
    stream earlier in a joined view cannot hide one, and a decoy in a string or comment is only
    one more value that must pass. Each must be a direct destination array, a /GoTo action
    dictionary without a /Next chain, or an indirect reference whose every definition, raw or
    in an object stream, is one of those. Anything else is not a page open: another action
    type (/JavaScript, /Launch, /URI, /GoToR, /GoToE, /SubmitForm, /ImportData, /Rendition), a
    missing /S, a value that does not parse, or a reference that resolves to nothing.
    """
    lookup = objects if objects is not None else PdfRawObjects(data)
    values: list[list[bytes]] = []
    for match in _PDF_NAME.finditer(data):
        if _decode_pdf_name(match.group()) != b"/OpenAction":
            continue
        if len(values) >= MAX_PDF_DEFINITIONS:
            return False
        values.append(_pdf_value_tokens(data[match.end() : match.end() + _PDF_VALUE_WINDOW]))
    # Every referenced object is found in one pass over the file, not one pass per reference.
    prime = getattr(lookup, "prime", None)
    if callable(prime):
        prime(
            {(int(v[0]), int(v[1])) for v in values if _pdf_reference(v[:3])},
        )
    return bool(values) and all(_pdf_goto_value(v, 0, objects=lookup) for v in values)


# A page destination or a GoTo dictionary is a few dozen bytes; a value longer than this
# does not close inside the window and so does not parse as a page open.
_PDF_VALUE_WINDOW = 4096


def _pdf_goto_value(tokens: list[bytes], start: int, *, objects: PdfObjectLookup | None) -> bool:
    head = tokens[start : start + 3]
    if head[:1] == [b"["]:
        return _pdf_destination(tokens[start : _pdf_value_end(tokens, start)])
    if head[:1] == [b"<<"]:
        entries = _pdf_dictionary(tokens[start : _pdf_value_end(tokens, start)])
        return entries is not None and entries.get(b"/S") == [b"/GoTo"] and b"/Next" not in entries
    if objects is not None and _pdf_reference(head):
        # Every definition counts: an incremental update can redefine the object, and the same
        # number can also sit in an object stream. A reference to a reference does not resolve.
        bodies = objects(int(head[0]), int(head[1]))
        return bool(bodies) and all(
            _pdf_goto_value(_pdf_value_tokens(body[:_PDF_VALUE_WINDOW]), 0, objects=None)
            for body in bodies
        )
    return False


def _pdf_value_tokens(data: bytes) -> list[bytes]:
    return [
        _decode_pdf_name(token) if token.startswith(b"/") else token
        for token in _pdf_top_tokens(data, mark_strings=True)
    ]


_PDF_OBJ = re.compile(rb"(?<![0-9])([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+obj\b")


# More definitions of one object, or more /OpenAction names, than this does not resolve: the
# file is treated as not a page open, so an attacker cannot buy work or memory with repeats.
MAX_PDF_DEFINITIONS = 64


# A definition header: object number, generation, and the obj keyword. A digit run is matched
# whole however long it is, since readers accept any number of leading zeros. The lookbehind
# allows one attempt per run and the possessive ``++`` never gives digits back (a digit always
# follows the split), so matching stays linear. ``_pdf_header_key`` drops the zeros.
_PDF_HEADER = re.compile(rb"(?<![0-9])([0-9]++)[\x00\t\n\f\r ]+([0-9]++)[\x00\t\n\f\r ]+obj\b")
# Significant digits past this cannot name an object any reference resolves to.
_PDF_HEADER_DIGITS = 32
_PDF_HEADER_CHECK_EVERY = 4096


def _pdf_header_key(number: bytes, generation: bytes) -> tuple[int, int] | None:
    """(number, generation) without leading zeros, or None when either is too long to be real."""
    number = number.lstrip(b"0") or b"0"
    generation = generation.lstrip(b"0") or b"0"
    if len(number) > _PDF_HEADER_DIGITS or len(generation) > _PDF_HEADER_DIGITS:
        return None
    return int(number), int(generation)


class PdfRawObjects:
    """Bodies of the ``N G obj`` definitions written directly in ``data``.

    ``prime`` finds every wanted object in one pass over the file and keeps only offsets, so a
    file with many /OpenAction references costs one scan, not one per reference. A lookup that
    was not primed searches for its own object. A body is sliced, at most ``_PDF_VALUE_WINDOW``
    bytes, when returned. A match inside a string or stream is kept too: an extra definition
    can only make a reference harder to accept. More than ``MAX_PDF_DEFINITIONS`` definitions
    return one empty body, which is not a page open. ``check`` is called between matches and
    before each search, so the scan deadline ends the work.
    """

    def __init__(self, data: bytes, check: Callable[[], None] | None = None) -> None:
        self._data = data
        self._check = check
        self._offsets: dict[tuple[int, int], list[int]] = {}

    def prime(self, keys: Iterable[tuple[int, int]]) -> None:
        wanted = {key for key in keys if key not in self._offsets}
        if not wanted:
            return
        found: dict[tuple[int, int], list[int]] = {key: [] for key in wanted}
        for count, match in enumerate(_PDF_HEADER.finditer(self._data)):
            if self._check is not None and count % _PDF_HEADER_CHECK_EVERY == 0:
                self._check()
            key = _pdf_header_key(match.group(1), match.group(2))
            slot = None if key is None else found.get(key)
            if slot is not None and len(slot) <= MAX_PDF_DEFINITIONS:
                slot.append(match.end())
        self._offsets.update(found)

    def __call__(self, number: int, generation: int) -> list[bytes]:
        key = (number, generation)
        if key not in self._offsets:
            self.prime([key])
        offsets = self._offsets[key]
        if len(offsets) > MAX_PDF_DEFINITIONS:
            return [b""]
        return [self._data[start : start + _PDF_VALUE_WINDOW] for start in offsets]


def _pdf_reference(tokens: list[bytes]) -> bool:
    return len(tokens) == 3 and tokens[0].isdigit() and tokens[1].isdigit() and tokens[2] == b"R"


def _pdf_value_end(tokens: list[bytes], start: int) -> int:
    """Index just past the value that begins at ``start``."""
    if start >= len(tokens):
        return start
    if tokens[start] in (b"<<", b"["):
        depth = 0
        for index in range(start, len(tokens)):
            if tokens[index] in (b"<<", b"["):
                depth += 1
            elif tokens[index] in (b">>", b"]"):
                depth -= 1
                if depth == 0:
                    return index + 1
        return len(tokens)
    if _pdf_reference(tokens[start : start + 3]):
        return start + 3
    return start + 1


def _pdf_destination(array: list[bytes]) -> bool:
    """A closed explicit destination: a page reference or number, a fit type, and numbers."""
    if len(array) < 3 or array[-1] != b"]":
        return False
    items = array[1:-1]
    if not any(item in _PDF_DESTINATIONS for item in items):
        return False
    return all(
        item in _PDF_DESTINATIONS
        or item in (b"R", b"null")
        or _PDF_NUMBER.fullmatch(item) is not None
        for item in items
    )


def _pdf_dictionary(value: list[bytes]) -> dict[bytes, list[bytes]] | None:
    """The direct entries of one closed dictionary, or None when it does not parse."""
    if len(value) < 2 or value[0] != b"<<" or value[-1] != b">>":
        return None
    entries: dict[bytes, list[bytes]] = {}
    index = 1
    while index < len(value) - 1:
        key = value[index]
        if not key.startswith(b"/") or key in entries:
            return None
        end = _pdf_value_end(value, index + 1)
        if end <= index + 1 or end > len(value) - 1:
            return None
        entries[key] = value[index + 1 : end]
        index = end
    return entries


def embedded_findings(data: bytes) -> list[Finding]:
    found = embedded_exec_offset(data)
    if found is None:
        return []
    kind, offset = found
    length = 4 if kind != "pe" else 2
    return [
        Finding(
            rule_id=f"heuristic_embedded_{kind}",
            offset=offset,
            length=length,
            severity=Severity.block,
            source=FindingSource.heuristic,
        )
    ]


def office_findings(path: Path, data: bytes) -> tuple[list[Finding], str | None]:
    if not _looks_like_office(path, data):
        return [], None
    from oletools.olevba import VBA_Parser, detect_autoexec

    if data.startswith(OLE) and _ole_encrypted(data):
        # An encrypted OOXML package or a legacy file encrypted in place: macros, text, and
        # embedded objects are ciphertext, so a clean result would describe nothing.
        return [], "encrypted office file"
    try:
        parser = VBA_Parser(str(path), data=data)
    except Exception:
        if _claims_vba(data):
            return [], "office parse error"
        return [], None
    try:
        try:
            detected = bool(parser.detect_vba_macros())
        except Exception:
            if _claims_vba(data):
                return [], "office parse error"
            return [], None
        if not detected:
            return [], None
        code = _extracted_code(parser)
        if not code:
            # ponytail: olevba saw a VBA project whose dir stream did not yield source.
            # Scan that project only. A full MS-OVBA dir writer would retire this.
            code = _project_bytes(data).decode("latin-1", errors="ignore")
        findings: list[Finding] = []
        if detect_autoexec(code):
            findings.append(_office("heuristic_office_autoexec"))
        for keyword in OFFICE_KEYWORDS:
            if re.search(rf"(?i)\b{re.escape(keyword)}\b", code):
                findings.append(_office(f"heuristic_office_{keyword.lower()}"))
        return findings, None
    finally:
        close = getattr(parser, "close", None)
        if callable(close):
            close()


def _office(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.block,
        source=FindingSource.heuristic,
    )


def _extracted_code(parser: object) -> str:
    extract = getattr(parser, "extract_macros", None)
    if not callable(extract):
        return ""
    parts: list[str] = []
    try:
        for item in extract():
            if len(item) >= 4 and isinstance(item[3], str):
                parts.append(item[3])
    except Exception:
        return ""
    return "\n".join(parts)


def _ole_encrypted(data: bytes) -> bool:
    """Detect [MS-OFFCRYPTO] encryption from stream names and msoffcrypto, without decrypting."""
    import olefile
    from oletools.crypto import is_encrypted

    try:
        ole = olefile.OleFileIO(data)
    except Exception:
        return False
    try:
        if ole.exists("EncryptedPackage") or ole.exists("\x06DataSpaces"):
            return True
        try:
            return bool(is_encrypted(ole))
        except Exception:
            return False
    finally:
        ole.close()


def _looks_like_office(path: Path, data: bytes) -> bool:
    if path.suffix.lower() in OFFICE_EXTS:
        return True
    if data.startswith(OLE):
        return True
    return data.startswith(b"PK") and _claims_vba(data)


def _claims_vba(data: bytes) -> bool:
    return b"vbaProject" in data or data.startswith(OLE)


def _project_bytes(data: bytes) -> bytes:
    if data.startswith(OLE):
        return data
    if not data.startswith(b"PK"):
        return b""
    chunks: list[bytes] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                blob = archive.read(info)
                if blob.startswith(OLE):
                    chunks.append(blob)
    except zipfile.BadZipFile:
        return b""
    return b"\n".join(chunks)


def _joiner_allowed(chars: list[str], index: int) -> bool:
    left = _joiner_neighbor(chars, index, -1)
    right = _joiner_neighbor(chars, index, 1)
    if not left or not right:
        return False
    if chars[index] == "\u200d" and _emoji(left) and _emoji(right):
        return True
    return _script_letter(left) and _script_letter(right)


def _joiner_neighbor(chars: list[str], index: int, step: int) -> str:
    cursor = index + step
    while 0 <= cursor < len(chars) and ord(chars[cursor]) in _VARIATION:
        cursor += step
    if cursor < 0 or cursor >= len(chars):
        return ""
    return chars[cursor]


def _emoji(char: str) -> bool:
    code = ord(char)
    if 0x1F3FB <= code <= 0x1F3FF or 0x1F1E6 <= code <= 0x1F1FF:
        return True
    if 0x1F000 <= code <= 0x1FAFF or 0x2600 <= code <= 0x27BF:
        return True
    return "EMOJI" in unicodedata.name(char, "")


def _script_letter(char: str) -> bool:
    if unicodedata.category(char) not in {"Lo", "Lm"}:
        return False
    name = unicodedata.name(char, "")
    return any(name.startswith(prefix) for prefix in _LETTER_PREFIXES)


# A run starts where the previous byte is not in the alphabet, so each run is visited once.
_B64_RUN = re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{400,}")
_B64_MIN = 400
# The shortest unit first, then as many further copies as follow.
_B64_REPEAT = re.compile(rb"([A-Za-z0-9+/]{1,12}?)\1{3,}")
# _b64_unsampled: 64-character windows, a sample-like one has 58 near neighbors at one lag.
_B64_WINDOW = 64
_B64_NEAR = 58
_B64_LAGS = (1, 2, 3, 4, 6, 8)
_B64_CHUNK = 64 * 1024
_B64_GRIDS = (
    bytes(value >> 3 for value in range(256)),
    bytes((value + 4) >> 3 for value in range(256)),
)
_B64_NONZERO = bytes([0]) + bytes([1]) * 255
# PNG, JPEG, GIF, WebP, ISO-BMFF (AVIF, HEIC, MP4), MP3, Ogg, WOFF, WOFF2, OpenType, TrueType: only
# the characters the magic bytes fix, since the next one depends on the following byte.
_B64_MEDIA = re.compile(
    rb"iVBORw0KGg|/9j/|R0lGOD[dl]h|UklGR[A-Za-z0-9+/]{7}RUJQ|AAAA[A-Za-z0-9+/]{2}Z0eX"
    rb"|SUQz|T2dnU|d09GR|d09GM|T1RUT|AAEAAA"
)
# MZ is TV then o-r; 7F ELF is f0VMR; FE ED FA CE/CF is /u36z; CE/CF FA ED FE is zvrt/ or z/rt/.
# CA FE BA BE is left out because Java class files share it with fat Mach-O.
_B64_EXE = re.compile(rb"TV[opqr]|f0VMR|/u36z|z[v/]rt/")
_B64_PREFIX = re.compile(
    rb"(?:data:(?:image|audio|video|font)/[A-Za-z0-9.+-]{1,64};base64,"
    rb"|-----BEGIN [A-Z0-9 ]{1,40}-----[\r\n]+"
    rb"|\b(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))[ \t]+)\Z"
)
_PDF_NAME = re.compile(rb"/(?:[^\x00\t\n\f\r /<>\[\]()#%]|#[0-9A-Fa-f]{2})+")
# Whitespace, a comment, a dictionary bracket, a hex string, a string opener, an array bracket,
# a name, or a regular token (number or keyword).
_PDF_LEX = re.compile(
    rb"[\x00\t\n\f\r ]+|%[^\r\n]*|<<|>>|<[0-9A-Fa-f\x00\t\n\f\r ]*>|\(|[\[\]{}]"
    rb"|/(?:[^\x00\t\n\f\r /<>\[\]()#%{}]|#[0-9A-Fa-f]{2})*"
    rb"|[^\x00\t\n\f\r /<>\[\]()%{}]+"
)


def _pdf_name_span(data: bytes, token: bytes) -> tuple[int, int] | None:
    for match in _PDF_NAME.finditer(data):
        decoded = _decode_pdf_name(match.group())
        if decoded == token:
            return match.start(), len(match.group())
    return None


# Walk opcodes only. pickle.loads would run the callable this check exists to stop.
_PICKLE_MODULES = frozenset({"os", "subprocess", "builtins", "posix", "nt"})
_PICKLE_NAMES = frozenset({"eval", "exec"})
_SHELL_COMMAND = re.compile(r"(?i)^(sh|bash|zsh|curl|wget|osascript|powershell|pwsh)(\s|$)")
_SHELL_ARG = re.compile(r"(?i)\b(sh|bash|curl|wget|osascript|powershell|pwsh)\b")
# Tool-poisoning text hides in a tool description: a shouted tag, a "do not mention" clause,
# or a request to read a key or client config and pass it along in another argument.
_HIDDEN_INSTRUCTION = re.compile(
    r"(?i)do not (tell|mention|inform|reveal|show)( this| it| that)?( to)? the user"
    r"|don'?t (tell|mention)( this| it)?( to)? the user"
    r"|ignore (all )?previous instructions"
    r"|<\s*important\s*>"
    r"|before (using|calling|running) this tool,? (read|open|cat)\b"
    r"|~?/?\.ssh/|\bid_(rsa|ed25519)\b|\bmcp\.json\b"
    r"|\bpass (its|the|their|this) contents?\b|\b(as|in) an? sidenote\b"
)


def pickle_reduce_findings(path: Path, data: bytes) -> list[Finding]:
    if not _pickle_candidate(path, data):
        return []
    offset = _pickle_reduce_offset(data)
    if offset is None:
        return []
    return [
        Finding(
            rule_id="heuristic_pickle_reduce",
            offset=offset,
            length=1,
            severity=Severity.block,
            source=FindingSource.heuristic,
        )
    ]


def model_header_findings(path: Path, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()
    if suffix == ".safetensors" and _safetensors_bad(data):
        findings.append(_block("heuristic_safetensors_header"))
    if (suffix == ".gguf" or data.startswith(b"GGUF")) and _gguf_bad(data):
        findings.append(_block("heuristic_gguf_header"))
    return findings


# A Keras config that names one of these modules imports it during load_model; none is a layer,
# loss, or activation. keras.utils.get_file (CVE-2025-8747) and
# keras.config.enable_unsafe_deserialization (CVE-2025-9906) are Keras's own functions that
# fetch a file or switch safe_mode off, so they are listed by name.
_KERAS_UNSAFE_MODULES = frozenset(
    {
        "__builtin__",
        "builtins",
        "code",
        "codeop",
        "ctypes",
        "http",
        "importlib",
        "marshal",
        "nt",
        "os",
        "pickle",
        "posix",
        "pty",
        "requests",
        "runpy",
        "shutil",
        "socket",
        "subprocess",
        "sys",
        "urllib",
        "webbrowser",
    }
)
_KERAS_UNSAFE_FUNCTIONS = frozenset({"enable_unsafe_deserialization", "get_file"})
_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_KERAS_JSON_START = b'{"class_name"'
_KERAS_MAX_NODES = 200_000
_KERAS_MAX_DEPTH = 64
_KERAS_H5_CONFIGS = 4
_KERAS_H5_SPAN = 16 * 1024 * 1024


def keras_config_findings(path: Path, data: bytes) -> list[Finding]:
    """Walk a Keras model config without loading it.

    A ``.keras`` archive keeps its graph in ``config.json``; ``model.to_json()`` writes the same
    shape; a legacy ``.h5`` stores it as the ``model_config`` attribute, plain JSON inside the
    HDF5 file. ``keras.models.load_model`` resolves every ``module`` and ``class_name`` it names,
    and a Lambda layer carries marshalled Python bytecode. Block a reference to a module or
    function that runs commands, fetches files, or turns safe_mode off; flag a Lambda as advisory,
    since safe_mode refuses it by default and an operator may still allow it.
    """
    for config in _keras_configs(path, data):
        hits: set[str] = set()
        _walk_keras(config, hits)
        findings: list[Finding] = []
        if "unsafe" in hits:
            findings.append(_block("heuristic_keras_unsafe_call"))
        if "lambda" in hits:
            findings.append(_advisory("heuristic_keras_lambda"))
        if findings:
            return findings
    return []


def _keras_configs(path: Path, data: bytes) -> Iterator[object]:
    suffix = path.suffix.lower()
    if suffix == ".json":
        if b'"class_name"' not in data or not data.lstrip().startswith(b"{"):
            return
        try:
            yield json.loads(data)
        except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return
        return
    if not (suffix in {".h5", ".hdf5"} or data.startswith(_HDF5_MAGIC)):
        return
    decoder = json.JSONDecoder()
    start = data.find(_KERAS_JSON_START)
    for _ in range(_KERAS_H5_CONFIGS):
        if start < 0:
            return
        window = data[start : start + _KERAS_H5_SPAN].decode("utf-8", "replace")
        try:
            config, _end = decoder.raw_decode(window)
        except (json.JSONDecodeError, RecursionError):
            config = None
        if config is not None:
            yield config
        start = data.find(_KERAS_JSON_START, start + 1)


def _walk_keras(root: object, hits: set[str]) -> None:
    stack: list[tuple[object, int]] = [(root, 0)]
    seen = 0
    while stack and seen < _KERAS_MAX_NODES and len(hits) < 2:
        node, depth = stack.pop()
        seen += 1
        if depth > _KERAS_MAX_DEPTH:
            continue
        if isinstance(node, dict):
            if _keras_unsafe(node):
                hits.add("unsafe")
            class_name = node.get("class_name")
            if class_name == "__lambda__" or (
                node.get("function_type") == "lambda" and "function" in node
            ):
                hits.add("lambda")
            stack.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            stack.extend((item, depth + 1) for item in node)


def _keras_unsafe(node: dict[object, object]) -> bool:
    module = node.get("module")
    if not isinstance(module, str):
        return False
    if module.split(".", 1)[0] in _KERAS_UNSAFE_MODULES:
        return True
    if not module.startswith("keras"):
        return False
    names = (node.get("class_name"), node.get("config"), node.get("registered_name"))
    return any(
        isinstance(name, str) and name.rsplit(">", 1)[-1] in _KERAS_UNSAFE_FUNCTIONS
        for name in names
    )


def ooxml_structure_findings(path: Path, data: bytes) -> list[Finding]:
    name = path.as_posix().lower()
    findings: list[Finding] = []
    if name.endswith("vbaproject.bin"):
        findings.append(_block("heuristic_ooxml_vba"))
    if "oleobject" in name:
        findings.append(_advisory("heuristic_ooxml_oleobject"))
    if b"http://schemas.openxmlformats.org" not in data:
        return findings
    if b"altChunk" in data:
        findings.append(_advisory("heuristic_ooxml_altchunk"))
    if b"DDE" in data and (b"instrText" in data or b"fldChar" in data):
        findings.append(_block("heuristic_ooxml_dde"))
    return findings


def mcp_tool_findings(path: Path, data: bytes) -> list[Finding]:
    if path.suffix.lower() != ".json" or not data.lstrip().startswith((b"{", b"[")):
        return []
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        return []
    hits: list[str] = []
    _walk_mcp(parsed, hits, 0)
    findings: list[Finding] = []
    if "shell" in hits:
        findings.append(_advisory("heuristic_mcp_shell"))
    if "hidden" in hits:
        findings.append(_advisory("heuristic_mcp_hidden_instruction"))
    return findings


def _block(rule_id: str) -> Finding:
    return Finding(rule_id=rule_id, severity=Severity.block, source=FindingSource.heuristic)


def _advisory(rule_id: str) -> Finding:
    return Finding(rule_id=rule_id, severity=Severity.advisory, source=FindingSource.heuristic)


def _pickle_candidate(path: Path, data: bytes) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".pkl", ".pickle", ".pt", ".pth", ".ckpt"}:
        return data[:1] == b"\x80"
    return len(data) >= 2 and data[0] == 0x80 and data[1] <= 5


def _pickle_reduce_offset(data: bytes) -> int | None:
    stack: list[str | tuple[str, str] | None] = []
    offset = 0
    steps = 0
    while offset < len(data) and steps < 100_000:
        steps += 1
        opcode = data[offset]
        start = offset
        offset += 1
        if opcode == 0x80:  # PROTO
            offset += 1
        elif opcode == 0x95:  # FRAME
            offset += 8
        elif opcode == 0x2E:  # STOP
            return None
        elif opcode == 0x94:  # MEMOIZE
            continue
        elif opcode == 0x28:  # MARK
            stack.append(None)
        elif opcode in {0x29, 0x5D, 0x7D, 0x4E, 0x88, 0x89, 0x8F}:
            stack.append(None)
        elif opcode == 0x4B:  # BININT1
            offset += 1
            stack.append(None)
        elif opcode == 0x4D:  # BININT2
            offset += 2
            stack.append(None)
        elif opcode == 0x4A:  # BININT
            offset += 4
            stack.append(None)
        elif opcode == 0x47:  # BINFLOAT
            offset += 8
            stack.append(None)
        elif opcode == 0x8C:  # SHORT_BINUNICODE
            text, offset = _counted(data, offset, 1)
            if text is None:
                return None
            stack.append(text)
        elif opcode == 0x58:  # BINUNICODE
            text, offset = _counted(data, offset, 4)
            if text is None:
                return None
            stack.append(text)
        elif opcode == 0x8D:  # BINUNICODE8
            text, offset = _counted(data, offset, 8)
            if text is None:
                return None
            stack.append(text)
        elif opcode == 0x63:  # GLOBAL
            module, offset = _line(data, offset)
            name, offset = _line(data, offset) if module is not None else (None, offset)
            if module is None or name is None:
                return None
            stack.append((module, name))
        elif opcode == 0x93:  # STACK_GLOBAL
            if len(stack) < 2:
                return None
            top_name = stack.pop()
            top_module = stack.pop()
            if not isinstance(top_module, str) or not isinstance(top_name, str):
                return None
            stack.append((top_module, top_name))
        elif opcode in {0x52, 0x81}:  # REDUCE, NEWOBJ
            if len(stack) < 2:
                return None
            stack.pop()
            callable_item = stack.pop()
            if isinstance(callable_item, tuple) and _dangerous(*callable_item):
                return start
            stack.append(None)
        elif opcode == 0x85 and stack:  # TUPLE1
            stack.pop()
            stack.append(None)
        elif opcode == 0x86 and len(stack) >= 2:  # TUPLE2
            del stack[-2:]
            stack.append(None)
        elif opcode == 0x87 and len(stack) >= 3:  # TUPLE3
            del stack[-3:]
            stack.append(None)
        elif opcode == 0x73 and len(stack) >= 2:  # SETITEM
            del stack[-2:]
        elif opcode == 0x30 and stack:  # POP
            stack.pop()
        elif opcode == 0x71:  # BINPUT
            offset += 1
        elif opcode == 0x72:  # LONG_BINPUT
            offset += 4
        elif opcode == 0x43:  # SHORT_BINBYTES
            # The payload is an argument, not a callable. Skip it and keep walking.
            nxt = _skip_counted(data, offset, 1)
            if nxt is None:
                return None
            offset = nxt
            stack.append(None)
        elif opcode == 0x42:  # BINBYTES
            nxt = _skip_counted(data, offset, 4)
            if nxt is None:
                return None
            offset = nxt
            stack.append(None)
        else:
            # An opcode this walker does not know stops the walk with no finding.
            return None
        if offset > len(data):
            return None
    return None


def _dangerous(module: str, name: str) -> bool:
    return module in _PICKLE_MODULES or name in _PICKLE_NAMES


def _skip_counted(data: bytes, offset: int, width: int) -> int | None:
    if offset + width > len(data):
        return None
    size = int.from_bytes(data[offset : offset + width], "little")
    start = offset + width
    if size > len(data) - start:
        return None
    return start + size


def _counted(data: bytes, offset: int, width: int) -> tuple[str | None, int]:
    if offset + width > len(data):
        return None, offset
    size = int.from_bytes(data[offset : offset + width], "little")
    start = offset + width
    if size > len(data) - start:
        return None, start
    try:
        text = data[start : start + size].decode("utf-8")
    except UnicodeError:
        return None, start + size
    return text, start + size


def _line(data: bytes, offset: int) -> tuple[str | None, int]:
    end = data.find(b"\n", offset, offset + 256)
    if end < 0:
        return None, offset
    try:
        return data[offset:end].decode("ascii"), end + 1
    except UnicodeError:
        return None, end + 1


def _safetensors_bad(data: bytes) -> bool:
    if len(data) < 8:
        return True
    header_len = int.from_bytes(data[:8], "little")
    if header_len < 2 or header_len > len(data) - 8:
        return True
    try:
        parsed = json.loads(data[8 : 8 + header_len])
    except json.JSONDecodeError:
        return True
    if not isinstance(parsed, dict):
        return True
    data_len = len(data) - 8 - header_len
    for key, value in parsed.items():
        if key == "__metadata__":
            continue
        if not isinstance(value, dict):
            return True
        offsets = value.get("data_offsets")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or not isinstance(offsets[0], int)
            or not isinstance(offsets[1], int)
        ):
            return True
        start = offsets[0]
        end = offsets[1]
        if start < 0 or end < start or end > data_len:
            return True
    return False


def _gguf_bad(data: bytes) -> bool:
    if len(data) < 24 or data[:4] != b"GGUF":
        return True
    version = int.from_bytes(data[4:8], "little")
    tensors = int.from_bytes(data[8:16], "little")
    pairs = int.from_bytes(data[16:24], "little")
    if version not in {1, 2, 3} or tensors > 100_000 or pairs > 100_000:
        return True
    offset: int | None = 24
    for _ in range(pairs):
        offset = _gguf_pair(data, offset)
        if offset is None:
            return True
    for _ in range(tensors):
        offset = _gguf_tensor(data, offset)
        if offset is None:
            return True
    return False


def _gguf_pair(data: bytes, offset: int | None) -> int | None:
    offset = _gguf_string(data, offset)
    if offset is None or offset + 4 > len(data):
        return None
    value_type = int.from_bytes(data[offset : offset + 4], "little")
    return _gguf_value(data, offset + 4, value_type)


def _gguf_tensor(data: bytes, offset: int | None) -> int | None:
    offset = _gguf_string(data, offset)
    if offset is None or offset + 4 > len(data):
        return None
    dims = int.from_bytes(data[offset : offset + 4], "little")
    offset += 4
    if dims > 8 or offset + dims * 8 + 12 > len(data):
        return None
    offset += dims * 8 + 4
    tensor_offset = int.from_bytes(data[offset : offset + 8], "little")
    if tensor_offset > len(data):
        return None
    return offset + 8


def _gguf_string(data: bytes, offset: int | None) -> int | None:
    if offset is None or offset + 8 > len(data):
        return None
    size = int.from_bytes(data[offset : offset + 8], "little")
    if size > len(data) - (offset + 8):
        return None
    return offset + 8 + size


def _gguf_value(data: bytes, offset: int, value_type: int) -> int | None:
    widths = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
    if value_type in widths:
        size = widths[value_type]
        if offset + size > len(data):
            return None
        return offset + size
    if value_type == 8:
        return _gguf_string(data, offset)
    if value_type != 9 or offset + 12 > len(data):
        return None
    element = int.from_bytes(data[offset : offset + 4], "little")
    count = int.from_bytes(data[offset + 4 : offset + 12], "little")
    if count > 100_000:
        return None
    cursor: int | None = offset + 12
    for _ in range(count):
        cursor = _gguf_value(data, cursor, element) if cursor is not None else None
        if cursor is None:
            return None
    return cursor


def _walk_mcp(node: object, hits: list[str], depth: int) -> None:
    if depth > 8 or len(hits) > 4:
        return
    if isinstance(node, dict):
        command = node.get("command")
        if isinstance(command, str) and _SHELL_COMMAND.search(command):
            hits.append("shell")
        args = node.get("args")
        if isinstance(args, list):
            for item in args:
                if isinstance(item, str) and _SHELL_ARG.search(item):
                    hits.append("shell")
                    break
        description = node.get("description")
        if isinstance(description, str) and _HIDDEN_INSTRUCTION.search(description):
            hits.append("hidden")
        for value in node.values():
            _walk_mcp(value, hits, depth + 1)
    elif isinstance(node, list):
        for item in node[:50]:
            _walk_mcp(item, hits, depth + 1)


def _decode_pdf_name(token: bytes) -> bytes:
    if b"#" not in token:
        return token
    decoded = bytearray()
    index = 0
    while index < len(token):
        if token[index] == ord("#") and index + 2 < len(token):
            decoded.append(int(token[index + 1 : index + 3], 16))
            index += 3
            continue
        decoded.append(token[index])
        index += 1
    return bytes(decoded)
