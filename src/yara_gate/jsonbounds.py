"""Bound JSON object-tree allocation before the standard decoder runs."""

import re
from collections.abc import Callable

# Separators and container openings bound the number of allocated values and keys.
MAX_JSON_STRUCTURE = 100_000
MAX_JSON_DEPTH = 64
_SPACE = re.compile(r"[ \t\r\n]*")
_TOKEN = re.compile(r'\\[\s\S]|//|/\*|["{}\[\],:]')


class JsonLimit(Exception):
    pass


def check_json_structure(
    text: str, check: Callable[[], None] | None = None, *, embedded: bool = False
) -> bool:
    """Check JSON without allocating its tree or validating its syntax.

    Strings and JSONC comments do not contribute structure. The caller still uses its own
    decoder. For raw_decode, stop at the embedded value's end; otherwise inspect trailing
    comments too. Return whether comments or trailing commas require JSONC decoding.
    """
    if check is not None:
        check()
    position = depth = count = tokens = 0
    quoted = relaxed = False
    while (match := _TOKEN.search(text, position)) is not None:
        position = match.end()
        piece = match.group()
        tokens += 1
        if check is not None and tokens % 4096 == 0:
            check()
        if piece == '"':
            quoted = not quoted
        elif quoted or piece.startswith("\\"):
            continue
        elif piece in ("//", "/*"):
            relaxed = True
            end = text.find("\n" if piece == "//" else "*/", position)
            if end < 0:
                return relaxed
            position = end + (1 if piece == "//" else 2)
        elif piece in "}]":
            depth -= 1
            if embedded and depth <= 0:
                return relaxed
        else:
            if piece == ",":
                space = _SPACE.match(text, position)
                if space is not None and text[space.end() : space.end() + 1] in ("}", "]"):
                    relaxed = True
            count += 1
            if piece in "{[":
                depth += 1
            if count > MAX_JSON_STRUCTURE or depth > MAX_JSON_DEPTH:
                raise JsonLimit("json exceeds structure limit")
    if check is not None:
        check()
    return relaxed
