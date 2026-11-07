"""Bounded RTF text pieces; formatting joins, paragraphs and destinations do not."""

import codecs
import re
from dataclasses import dataclass, replace

from yara_gate.content import MAX_EXTRACT_BYTES, MAX_TEXT_PIECES, Budget, ContentLimit

_TOKEN = re.compile(
    rb"\\([a-zA-Z]++)(-?[0-9]++)? ?|\\'([0-9a-fA-F]{2})|\\(.)|([{}])"
    rb"|([^\\{}\r\n]{1,4096})|[\r\n]",
    re.DOTALL,
)
_SKIP = frozenset(
    b"fonttbl colortbl stylesheet info pict objdata fldinst filetbl listtable "
    b"listoverridetable revtbl rsidtbl generator datastore themedata colorschememapping "
    b"xmlnstbl nonshppict shppict".split()
)
_STORY = frozenset(
    b"header headerl headerr headerf footer footerl footerr footerf footnote annotation "
    b"shptxt".split()
)
_BREAK = frozenset(b"par sect page cell row nestcell nestrow".split())
_CHAR = {
    b"tab": "\t",
    b"line": "\n",
    b"emdash": "\u2014",
    b"endash": "\u2013",
    b"emspace": "\u2003",
    b"enspace": "\u2002",
    b"qmspace": "\u2005",
    b"bullet": "\u2022",
    b"lquote": "\u2018",
    b"rquote": "\u2019",
    b"ldblquote": "\u201c",
    b"rdblquote": "\u201d",
}
_CHARSET = {
    0: None,
    1: None,
    77: "mac_roman",
    128: "cp932",
    129: "cp949",
    130: "cp1361",
    134: "cp936",
    136: "cp950",
    161: "cp1253",
    162: "cp1254",
    163: "cp1258",
    177: "cp1255",
    178: "cp1256",
    186: "cp1257",
    204: "cp1251",
    222: "cp874",
    238: "cp1250",
    254: "cp437",
    255: "cp850",
}


@dataclass
class _State:
    skip: bool = False
    uc: int = 1
    encoding: str = "cp1252"
    font: int = 0
    font_table: bool = False
    boundary: bool = False
    upr: bool = False
    children: int = 0


def rtf_texts(data: bytes, budget: Budget) -> list[str]:
    """Read an RTF header, including renamed members, without opening embedded objects."""
    if not data.startswith(b"{\\rtf1") or data[6:7].isdigit():
        return []
    state = _State()
    stack: list[_State] = []
    fonts: dict[int, str | None] = {}
    pieces: list[str] = []
    text: list[str] = []
    raw = bytearray()
    position = fallback = tokens = size = 0
    starred = False
    default_font = 0

    def append(value: str) -> None:
        nonlocal size
        # UTF-16 code units are combined when a piece ends, before UTF-8 is charged by scanner.
        size += len(value) * 4
        if budget.expanded + size > MAX_EXTRACT_BYTES:
            raise ContentLimit("rtf text exceeds extracted size budget")
        text.append(value)

    def flush_bytes() -> None:
        if raw:
            encoding = fonts.get(state.font) or state.encoding
            try:
                append(raw.decode(encoding))
            except (LookupError, UnicodeError) as exc:
                raise ContentLimit("rtf text encoding unreadable") from exc
            raw.clear()

    def flush() -> None:
        flush_bytes()
        if text:
            try:
                value = "".join(text).encode("utf-16-le", "surrogatepass").decode("utf-16-le")
            except UnicodeError as exc:
                raise ContentLimit("rtf unicode unreadable") from exc
            if value.strip():
                if len(pieces) >= MAX_TEXT_PIECES:
                    raise ContentLimit("text pieces exceed 100000")
                pieces.append(value)
            text.clear()

    while position < len(data):
        budget.check()
        tokens += 1
        if tokens > 4_000_000:
            raise ContentLimit("rtf tokens exceed 4000000")
        match = _TOKEN.match(data, position)
        if match is None:
            raise ContentLimit("rtf malformed control")
        position = match.end()
        word, parameter, hex_byte, symbol, brace, plain = match.groups()
        if (word and len(word) > 32) or (parameter and len(parameter.lstrip(b"-")) > 10):
            raise ContentLimit("rtf control exceeds limit")
        if symbol == b"'":
            raise ContentLimit("rtf malformed hex escape")
        if brace:
            starred = False
        if brace == b"{":
            flush_bytes()
            fallback = 0
            if len(stack) >= 128:
                raise ContentLimit("rtf group depth exceeds 128")
            state.children += 1
            stack.append(state)
            state = replace(
                state,
                skip=state.skip or (state.upr and state.children == 1),
                boundary=False,
                upr=False,
                children=0,
            )
        elif brace == b"}":
            if not stack:
                raise ContentLimit("rtf unbalanced groups")
            flush_bytes()
            if state.boundary:
                flush()
            state = stack.pop()
            fallback = 0
            if not stack:
                if data[position:].strip(b"\r\n\t "):
                    raise ContentLimit("rtf trailing data")
                break
        elif word == b"bin":
            count = int(parameter or b"-1")
            if count < 0 or count > len(data) - position:
                raise ContentLimit("rtf binary length invalid")
            position += count
            if fallback:
                fallback -= 1
            elif not state.skip:
                flush()
        elif fallback and (word or hex_byte or symbol or plain):
            count = min(fallback, len(plain) if plain else 1)
            fallback -= count
            if plain and not state.skip:
                raw.extend(plain[count:])
        elif symbol == b"*":
            starred = True
        elif word:
            if starred:
                # The Unicode alternative of upr is a recognized starred destination.
                if word != b"ud" or not stack or not stack[-1].upr:
                    state.skip = True
                    flush_bytes()
                starred = False
            if word in _SKIP:
                flush_bytes()
                state.skip = True
                state.font_table = word == b"fonttbl"
            elif word in _STORY and not state.skip:
                flush()
                state.boundary = True
            elif word == b"f" and parameter is not None:
                flush_bytes()
                state.font = int(parameter)
            elif state.font_table and word in (b"fcharset", b"cpg"):
                number = int(parameter or b"-1")
                fonts[state.font] = (
                    _CHARSET.get(number, "unmapped-rtf-font")
                    if word == b"fcharset"
                    else f"cp{number}"
                )
            elif state.skip:
                continue
            elif word == b"deff" and parameter is not None:
                flush_bytes()
                default_font = state.font = int(parameter)
            elif word == b"plain":
                flush_bytes()
                state.font = default_font
            elif word == b"upr":
                state.upr = True
                state.children = 0
            elif word in (b"ansi", b"mac", b"pc", b"pca", b"ansicpg"):
                flush_bytes()
                state.encoding = (
                    f"cp{int(parameter or b'0')}"
                    if word == b"ansicpg"
                    else {b"ansi": "cp1252", b"mac": "mac_roman", b"pc": "cp437", b"pca": "cp850"}[
                        word
                    ]
                )
                try:
                    codecs.lookup(state.encoding)
                except LookupError as exc:
                    raise ContentLimit("rtf text encoding unreadable") from exc
            elif word == b"uc":
                state.uc = int(parameter or b"-1")
                if not 0 <= state.uc <= 32767:
                    raise ContentLimit("rtf unicode fallback invalid")
            elif word == b"u":
                value = int(parameter or b"-99999")
                if not -32768 <= value <= 65535:
                    raise ContentLimit("rtf unicode value invalid")
                flush_bytes()
                append(chr(value & 0xFFFF))
                fallback = state.uc
            elif word in _BREAK:
                flush()
            elif word in _CHAR:
                flush_bytes()
                append(_CHAR[word])
        elif not state.skip:
            if plain:
                raw.extend(plain)
            elif hex_byte:
                raw.extend(bytes.fromhex(hex_byte.decode("ascii")))
            elif symbol in (b"\\", b"{", b"}"):
                raw.extend(symbol)
            elif symbol in (b"~", b"_", b"-", b"\r", b"\n"):
                flush_bytes()
                append({b"~": "\u00a0", b"_": "\u2011", b"-": "\u00ad"}.get(symbol, "\n"))
    if stack:
        raise ContentLimit("rtf unbalanced groups")
    flush()
    return pieces
