"""The text a PDF reader shows: strings of Tj, TJ, ', and " joined per BT ... ET block.

A content stream rarely holds a sentence as one string. Word, LaTeX, and browsers write kerned
``[(Ign) -20 (ore)] TJ`` arrays, one word per ``Tj``, or hex strings, so the raw and
``pdf-flate`` views see fragments. This module rebuilds each text block from the operators and
decodes each string through its font: a simple font as WinAnsi bytes, a font with a ToUnicode
CMap through that map. A composite (two-byte) font with no readable ToUnicode map cannot be
decoded; the caller reports that as a coverage note instead of a silent clean.

Nothing is rendered and no font program is read. Positions are not tracked, so text placed out
of reading order is joined in stream order, and a sentence split across two text blocks is not
rejoined. Every loop is bounded and checks the scan deadline.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from yara_gate.content import Budget, ContentLimit, PdfStream

MAX_TEXT_BLOCKS = 20_000
MAX_BLOCK_CHARS = 64 * 1024
MAX_TOKENS = 4_000_000
MAX_CMAP_ENTRIES = 1 << 17
MAX_FONT_VARIANTS = 4
# A TJ adjustment is in thousandths of an em; a gap this wide reads as a word space.
_SPACE_ADJUST = -200.0

_NUMBER = re.compile(rb"[+-]?(?:\d+\.?\d*|\.\d+)\Z")
_CP1252 = [bytes((value,)).decode("cp1252", errors="replace") for value in range(256)]
_HEX_DIGITS = re.compile(rb"[^0-9A-Fa-f]")
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
_CMAP_SECTION = re.compile(rb"begin(codespacerange|bfchar|bfrange)(.*?)end\1", re.DOTALL)
_CMAP_TOKEN = re.compile(rb"<([0-9A-Fa-f\x00\t\n\f\r ]*)>|\[|\]")

Lookup = Callable[[int, int], list[bytes]]


@dataclass
class Font:
    """How a font's string bytes become text: ``cmap`` when it has a map, else WinAnsi."""

    composite: bool
    cmap: dict[bytes, str] | None = None
    lengths: tuple[int, ...] = (1,)

    @property
    def unreadable(self) -> bool:
        return self.composite and not self.cmap


@dataclass
class PdfText:
    """Text blocks, and whether some text could not be decoded.

    ``blocks`` holds the joined strings of each text object (BT ... ET), cut where the text
    moves to a new paragraph, so each is scanned on its own.
    """

    blocks: list[str] = field(default_factory=list)
    unmapped: bool = False


def pdf_text(data: bytes, streams: list[PdfStream], objects: Lookup, budget: Budget) -> PdfText:
    """Text blocks from every content stream in ``streams``, decoded through the file's fonts."""
    result = PdfText()
    if not data.startswith(b"%PDF"):
        return result
    by_number: dict[int, bytes | None] = {
        stream.number: stream.text for stream in streams if stream.number is not None
    }
    fonts = _fonts(data, streams, objects, by_number, budget)
    tokens = 0
    # A page's /Contents array is read as one stream, so the font one stream selects stays
    # selected in the next; a form XObject also inherits its caller's font. The selection is
    # carried across streams in file order.
    state = _TextState()
    for stream in streams:
        body = stream.text
        if body is None or b"BT" not in body:
            continue
        tokens = _blocks(body, fonts, result, budget, tokens, state)
    return result


def _fonts(
    data: bytes,
    streams: list[PdfStream],
    objects: Lookup,
    by_number: dict[int, bytes | None],
    budget: Budget,
) -> dict[bytes, list[Font]]:
    """Resource name to the distinct fonts it names anywhere in the file (pages may differ)."""
    sources: list[bytes] = [data]
    sources.extend(stream.text for stream in streams if stream.text and stream.inflated)
    references: dict[bytes, set[tuple[int, int]]] = {}
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
    _prime(objects, indirect)
    for key in sorted(indirect):
        dictionaries.extend(objects(*key))
    for dictionary in dictionaries:
        for ref in _NAME_REF.finditer(dictionary):
            name = _name(ref.group(1))
            slot = references.setdefault(name, set())
            if len(slot) < 64:
                slot.add((int(ref.group(2)), int(ref.group(3))))
    cache: dict[tuple[int, int], Font | None] = {}
    fonts: dict[bytes, list[Font]] = {}
    _prime(objects, {key for refs in references.values() for key in refs})
    headers: dict[tuple[int, int], int] | None = None

    def raw(key: tuple[int, int]) -> bytes:
        nonlocal headers
        if headers is None:
            headers = {}
            for match in _OBJ_HEADER.finditer(data):
                headers[(int(match.group(1)), int(match.group(2)))] = match.end()
        start = headers.get(key)
        if start is None:
            return b""
        end = data.find(b"endobj", start, start + _MAX_OBJECT_BYTES)
        return data[start : end if end >= 0 else start + _MAX_OBJECT_BYTES]

    for name, refs in references.items():
        found: list[Font] = []
        for key in sorted(refs):
            if key not in cache:
                cache[key] = _font(objects(*key), by_number, budget, raw, key)
            font = cache[key]
            if font is not None and font not in found:
                found.append(font)
        if found:
            fonts[name] = found
    return fonts


def _font(
    bodies: list[bytes],
    by_number: dict[int, bytes | None],
    budget: Budget,
    raw: Callable[[tuple[int, int]], bytes],
    key: tuple[int, int],
) -> Font | None:
    for body in bodies:
        if b"/Font" not in body and b"/Subtype" not in body:
            continue
        composite = bool(_TYPE0.search(body) or _IDENTITY.search(body))
        mapping = _TO_UNICODE.search(body)
        if mapping is None and len(body) >= _LOOKUP_WINDOW:
            # The object lookup returns a 4 KB window; a Type0 font that embeds its descendant
            # font and a long /W widths array puts /ToUnicode past it. Read the whole object.
            mapping = _TO_UNICODE.search(raw(key))
        if mapping is None:
            return Font(composite, None, (2,) if composite else (1,))
        cmap_bytes = by_number.get(int(mapping.group(1)))
        if not cmap_bytes:
            return Font(composite, None, (2,) if composite else (1,))
        cmap, lengths = _cmap(cmap_bytes, budget)
        default = (2,) if composite else (1,)
        return Font(composite, cmap or None, lengths or default)
    return None


_LOOKUP_WINDOW = 4000
_MAX_OBJECT_BYTES = 1 << 20


_OBJ_HEADER = re.compile(
    rb"(?<![0-9])([0-9]{1,10})[\x00\t\n\f\r ]+([0-9]{1,5})[\x00\t\n\f\r ]+obj\b"
)


def _prime(objects: Lookup, keys: set[tuple[int, int]]) -> None:
    prime = getattr(objects, "prime", None)
    if keys and callable(prime):
        prime(keys)


def _cmap(data: bytes, budget: Budget) -> tuple[dict[bytes, str], tuple[int, ...]]:
    """bfchar and bfrange entries of a ToUnicode CMap, and its code lengths in bytes."""
    mapping: dict[bytes, str] = {}
    lengths: set[int] = set()
    for section in _CMAP_SECTION.finditer(data):
        budget.check()
        kind, body = section.group(1), section.group(2)
        items = [
            _hex_bytes(token.group(1)) if token.group(1) is not None else token.group()
            for token in _CMAP_TOKEN.finditer(body)
        ]
        if kind == b"codespacerange":
            lengths.update(len(item) for item in items[0::2] if isinstance(item, bytes) and item)
        elif kind == b"bfchar":
            for source, target in zip(items[0::2], items[1::2], strict=False):
                if len(mapping) >= MAX_CMAP_ENTRIES:
                    break
                if source and target not in (b"[", b"]"):
                    mapping[source] = _utf16(target)
        else:
            _cmap_ranges(items, mapping)
    return mapping, tuple(sorted(lengths, reverse=True))


def _cmap_ranges(items: list[bytes], mapping: dict[bytes, str]) -> None:
    index = 0
    while index + 2 < len(items) and len(mapping) < MAX_CMAP_ENTRIES:
        low, high, target = items[index], items[index + 1], items[index + 2]
        index += 3
        if not low or len(low) != len(high) or low in (b"[", b"]") or high in (b"[", b"]"):
            continue
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
            for offset, each in enumerate(targets[: last - first + 1]):
                mapping[(first + offset).to_bytes(len(low), "big")] = _utf16(each)
            continue
        if target == b"]":
            continue
        base = int.from_bytes(target, "big") if target else 0
        width = max(len(target), 2)
        for offset in range(last - first + 1):
            if len(mapping) >= MAX_CMAP_ENTRIES:
                return
            # The last byte of the target increments across the range (ISO 32000-1 9.10.3).
            mapping[(first + offset).to_bytes(len(low), "big")] = _utf16(
                (base + offset).to_bytes(width, "big")
            )


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
    """Text shown in one content stream, grouped into paragraphs by baseline position."""

    def __init__(self, result: PdfText) -> None:
        self.result = result
        self.variants: list[list[str]] = []
        self.baseline: float | None = None
        self.size = 0.0
        # Where the current block starts in each variant.
        self.block_start = 0

    def show(
        self, fonts: list[Font], strings: Iterable[object], baseline: float, size: float
    ) -> None:
        strings = list(strings)
        variants = fonts or [Font(False)]
        if any(font.unreadable for font in variants):
            self.result.unmapped = True
        elif not fonts and _two_byte(strings):
            # A font the file never resolves, whose codes are two bytes wide: decoding them as
            # WinAnsi would yield noise, so the text counts as unread.
            self.result.unmapped = True
            return
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
        while len(self.variants) < min(len(variants), MAX_FONT_VARIANTS):
            # A name that means different fonts on different pages: one reading per font.
            self.variants.append(list(self.variants[0]))
        for index, variant in enumerate(self.variants):
            font = variants[index % len(variants)]
            if separator and variant:
                variant.append(separator)
            for item in strings:
                if isinstance(item, bytes):
                    variant.append(_decode(item, font))
                elif isinstance(item, float) and item <= _SPACE_ADJUST:
                    variant.append(" ")

    def end_block(self) -> None:
        """Close the current text object's piece of this paragraph and emit it as a block."""
        for variant in self.variants:
            text = "".join(variant[self.block_start :]).strip()
            if text:
                self._emit(self.result.blocks, text)
        self.block_start = len(self.variants[0]) if self.variants else 0

    def flush(self) -> None:
        self.end_block()
        self.variants = []
        self.baseline = None
        self.block_start = 0

    def _emit(self, target: list[str], text: str) -> None:
        if len(self.result.blocks) >= MAX_TEXT_BLOCKS:
            raise ContentLimit("pdf text blocks exceed 20000")
        target.append(text[:MAX_BLOCK_CHARS])


@dataclass
class _TextState:
    """The selected font and size, which outlive one content stream."""

    fonts: list[Font] = field(default_factory=list)
    size: float = 0.0
    selected: bool = False


def _blocks(
    body: bytes,
    fonts: dict[bytes, list[Font]],
    result: PdfText,
    budget: Budget,
    tokens: int,
    state: _TextState,
) -> int:
    """Append the paragraphs of one content stream to ``result``; return the token count.

    The CTM (cm, q, Q) and the text matrix (Tm, Td, TD, T*, TL, ', ") are followed so each
    string's baseline is known in device space; text objects (BT ... ET) do not split text,
    because generators start a new one at every font change or line.
    """
    operands: list[object] = []
    current: list[Font] = state.fonts
    size = state.size
    leading = 0.0
    ctm = _IDENTITY_MATRIX
    saved: list[Matrix] = []
    line = _IDENTITY_MATRIX
    paragraphs = _Paragraphs(result)

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
        paragraphs.show(current, strings, device[5], abs(size) * scale)

    for token in _tokens(body):
        tokens += 1
        if tokens % 4096 == 0:
            budget.check()
        if tokens > MAX_TOKENS:
            raise ContentLimit("pdf content exceeds token limit")
        if not isinstance(token, _Operator):
            operands.append(token)
            continue
        op = token.value
        if op == b"BT":
            paragraphs.end_block()
            line = _IDENTITY_MATRIX
        elif op == b"ET":
            paragraphs.end_block()
        elif op == b"q":
            if len(saved) < 64:
                saved.append(ctm)
        elif op == b"Q":
            ctm = saved.pop() if saved else ctm
        elif op == b"cm" and (values := numbers(6)) is not None:
            ctm = _multiply((values[0], values[1], values[2], values[3], values[4], values[5]), ctm)
        elif op == b"Tf" and len(operands) >= 2 and isinstance(operands[-2], _Name):
            current = fonts.get(operands[-2].value, [])
            size = operands[-1] if isinstance(operands[-1], float) else size
            state.fonts, state.size, state.selected = current, size, True
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


def _tokens(data: bytes) -> Iterable[object]:
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
    digits = _HEX_DIGITS.sub(b"", raw)
    if len(digits) % 2:
        digits += b"0"
    return bytes.fromhex(digits.decode("ascii"))


def _utf16(raw: bytes) -> str:
    if len(raw) % 2:
        raw = b"\x00" + raw
    return raw.decode("utf-16-be", errors="replace")


def _decode(raw: bytes, font: Font) -> str:
    if font.cmap is None:
        if font.composite:
            return ""
        return raw.decode("cp1252", errors="replace")
    cmap = font.cmap
    if font.lengths == (2,):
        return "".join(
            [cmap.get(raw[index : index + 2], "") for index in range(0, len(raw) - 1, 2)]
        )
    if font.lengths == (1,):
        return "".join(
            [cmap.get(raw[index : index + 1]) or _CP1252[raw[index]] for index in range(len(raw))]
        )
    output: list[str] = []
    index = 0
    while index < len(raw):
        for length in font.lengths:
            code = raw[index : index + length]
            if len(code) == length and code in font.cmap:
                output.append(font.cmap[code])
                index += length
                break
        else:
            # A code the map does not list: a simple font falls back to its byte, a composite
            # font has nothing to show for it.
            step = font.lengths[-1] if font.composite else 1
            if not font.composite:
                output.append(raw[index : index + 1].decode("cp1252", errors="replace"))
            index += step
    return "".join(output)


def _name(raw: bytes) -> bytes:
    """A PDF name with #xx escapes decoded, so /F#31 and /F1 compare equal."""
    if b"#" not in raw:
        return raw
    return re.sub(rb"#([0-9A-Fa-f]{2})", lambda match: bytes.fromhex(match.group(1).decode()), raw)
