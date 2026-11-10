"""HTML text a browser does not show, read from the markup without rendering it.

``html_hidden_texts`` returns the text of a document that a person who opens it does not see:
comments, ``data-*`` values, the content of a ``template``, and the text of elements hidden by
their own inline style or attributes. Nothing is rendered, no stylesheet is resolved, and no
script runs.

A claim that text is hidden rests on one exact declaration on an element the text is inside:
``display:none``, the ``hidden`` attribute, ``visibility:hidden``, a font size of zero, an
opacity of zero, transparent text, or text the colour of the background its own element
declares. A value counts only in a spelling a browser is known to accept. A browser drops a
declaration it cannot parse, so ``font-size:0 px``, ``display:none\\9``, and a declaration
after an unclosed parenthesis are no claim, and one that could have set a property back ends
the claim an ancestor made.

Nothing here depends on layout. A box of no height that clips its content, text moved off the
page, a font of one pixel, and white text on a page taken to be white are left to the lexical
rule ``agent_hidden_html``: where text lands, how large it is drawn, and what is behind it are
not settled by the markup.

Whether text is inside a hidden element depends on which elements are open, so the open
elements follow the HTML tree builder where a browser's tree differs from the written nesting:
end tags a writer may leave out, formatting elements reopened after a misnested end tag, an
end tag ignored because a block element is in the way, a link that ends an open link, the
parts of a table and text moved out of one, and HTML that ends an ``svg``. Markup past what is
modeled here stops the element reader for the rest of the document; comments and ``data-*``
values are still read.

Three things are assumed, not read. The document is taken as it is when it opens, before a
script changes it. The browser has scripting on, so a ``noscript`` body is not markup. A
stylesheet restyles an element only through its class or id, and never overrides an inline
declaration.

Checked against headless Chromium on generated documents and on single-rule probes; see
``docs/verification/2026-11-10-hidden-html-text.md`` for the method and what it does not cover.
"""

import colorsys
import html
import re
from dataclasses import dataclass
from html.entities import html5 as _REFERENCES
from typing import NamedTuple

from yara_gate.content import (
    _HTML_BLOCKS,
    _HTML_SPACE,
    _HTML_SUFFIXES,
    MAX_TEXT_PIECES,
    Budget,
    ContentLimit,
    _opens_as_html,
)

# HTML and CSS fold only the ASCII letters. ``str.lower`` also folds the Kelvin sign to "k",
# which would read a name a browser does not.
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
# The characters HTML takes as whitespace. A no-break space is text: it starts a body and
# moves out of a table like any other character.
_HTML_BLANK = "\t\n\f\r "

# A start or end tag as the HTML tokenizer reads it: ``<``, an optional ``/``, and a name that
# starts with a letter and runs to whitespace, ``/``, or ``>``.
_TAG = re.compile(r"<(/?)([A-Za-z][^\t\n\f\r />]*+)")
# The rest of a tag through its ``>``. A quote opens a value only after ``=``; anywhere else it
# is part of a name, so ``<p it's>`` ends at the first ``>``. Unlike ``content._HTML_TOKEN`` a
# value has no length bound: an inline image or an SVG path is often longer than 4,096
# characters, and a tag this reader could not close would leave every later element unread.
# Each repeat is possessive. A value whose quote never closes is read as bare characters,
# which costs one scan to the end at most once for each kind of quote in a document, and the
# match fails only when no ``>`` follows at all: the end of input inside a tag.
_TAG_REST = re.compile(r"""(?:[^>="']++|=[\t\n\f\r ]*+"[^"]*+"|=[\t\n\f\r ]*+'[^']*+'|[="'])*+>""")
_ATTRIBUTE = re.compile(
    r"""([^\t\n\f\r "'/=<>]++)"""
    r"""(?:[\t\n\f\r ]*+=[\t\n\f\r ]*+(?:"([^"]*+)"|'([^']*+)'|([^\t\n\f\r "'=<>`]++)))?"""
)
_HTML_SPACES = re.compile(r"[\t\n\f\r ]+")
# Names a browser reads with its XML parser, and how a document with another name starts when
# a browser would: there a slash closes any element, nothing is implied, and none of the HTML
# rules below hold, so only comments and data-* values are read.
_XML_SUFFIXES = frozenset({"svg", "xht", "xhtml", "xml"})
_XML_START = re.compile(r"(?i)<\?xml\b|<svg[\t\n\f\r />]")
# A document with none of these hides nothing this reader can see.
_ANY_HIDING = re.compile(
    r"(?i)<!--|style[\t\n\f\r ]*=|hidden|data-|<template|sr-only|visually-hidden"
    r"|screen-reader-text"
)
_VOID = frozenset(
    {
        "area", "base", "basefont", "bgsound", "br", "col", "embed", "frame", "hr", "image",
        "img", "input", "keygen", "link", "meta", "param", "source", "track", "wbr",
    }
)  # fmt: skip
# Elements whose body is not markup. The first group is never drawn: a frame's fallback is not,
# and with scripting on a noscript body is not either. The second shows its body as written.
_NOT_DRAWN = frozenset({"script", "style", "iframe", "noembed", "noframes", "noscript"})
_AS_WRITTEN = frozenset({"textarea", "title", "xmp"})
_RAW_END = {
    tag: re.compile(rf"</{tag}(?=[\t\n\f\r />])", re.I) for tag in (*_NOT_DRAWN, *_AS_WRITTEN)
}
# The only elements a select holds. A select with anything else in it is not followed: which
# tags end one differs between browser versions.
_SELECT_PARTS = frozenset({"hr", "optgroup", "option"})
_SELECT_TAG = re.compile(r"(?i)</?(?:option|optgroup|hr)\b[^<>]*>")
# Elements a browser reopens when an end tag closed them from outside.
_FORMATTING = frozenset(
    {
        "a", "b", "big", "code", "em", "font", "i", "nobr", "s", "small", "strike", "strong",
        "tt", "u",
    }
)  # fmt: skip
# The HTML "special" elements: an end tag for an ordinary element does not reach past one, and
# a formatting element that ends while one is open inside it leaves that element open.
_SPECIAL = frozenset(
    {
        "address", "applet", "area", "article", "aside", "base", "basefont", "bgsound",
        "blockquote", "body", "br", "button", "caption", "center", "col", "colgroup", "dd",
        "details", "dir", "div", "dl", "dt", "embed", "fieldset", "figcaption", "figure",
        "footer", "form", "frame", "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head",
        "header", "hgroup", "hr", "html", "iframe", "img", "input", "keygen", "li", "link",
        "listing", "main", "marquee", "menu", "meta", "nav", "noembed", "noframes", "noscript",
        "object", "ol", "p", "param", "plaintext", "pre", "script", "search", "section",
        "select", "source", "style", "summary", "table", "tbody", "td", "template", "textarea",
        "tfoot", "th", "thead", "title", "tr", "track", "ul", "wbr", "xmp",
        # and, inside svg or math, the elements that hold HTML
        "desc", "foreignobject", "mi", "mn", "mo", "ms", "mtext",
    }
)  # fmt: skip
# Start tags that end an open ``p``, and the elements an open ``p`` is not looked for beyond.
_P_ENDERS = frozenset(
    {
        "address", "article", "aside", "blockquote", "center", "dd", "details", "dialog", "dir",
        "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
        "h3", "h4", "h5", "h6", "header", "hgroup", "hr", "li", "listing", "main", "menu", "nav",
        "ol", "p", "plaintext", "pre", "search", "section", "summary", "table", "ul", "xmp",
    }
)  # fmt: skip
# Inside one of these, within svg or math, the content is HTML again. The names belong to
# their own kind: an ``mi`` inside an svg is an svg element and holds no HTML.
_INTEGRATION = {
    "svg": frozenset({"desc", "foreignobject", "title"}),
    "math": frozenset({"mi", "mn", "mo", "ms", "mtext"}),
}
# Elements an end tag is not looked for beyond. An HTML title is never an open element here
# (its body is read as written), so the name can only be an svg title.
_SCOPE = frozenset(
    {
        "applet", "caption", "html", "marquee", "object", "table", "td", "template", "th",
        "desc", "foreignobject", "title", "mi", "mn", "mo", "ms", "mtext",
    }
)  # fmt: skip
_P_SCOPE = _SCOPE | {"button"}
_LIST_SCOPE = _SCOPE | {"ol", "ul"}
# End tags that close their element when it is in scope. Any other end tag, including one for
# an element in the special list that is not named here, stops at the first block element.
_BLOCK_ENDS = frozenset(
    {
        "address", "applet", "article", "aside", "blockquote", "button", "center", "dd",
        "details", "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption", "figure",
        "footer", "header", "hgroup", "listing", "main", "marquee", "menu", "nav", "object", "ol",
        "pre", "search", "section", "summary", "ul",
    }
)  # fmt: skip
_P_ONLY = frozenset({"p"})
_A_ONLY = frozenset({"a"})
_NOBR_ONLY = frozenset({"nobr"})
_RUBY_ONLY = frozenset({"ruby"})
# Elements an end tag closes on its way: a writer may leave their own end tags out.
_ENDS_ITSELF = frozenset({"dd", "dt", "li", "optgroup", "option", "p", "rb", "rp", "rt", "rtc"})
_HEAD = frozenset({"head"})
_NONE: frozenset[str] = frozenset()
_TABLE_PARTS = frozenset({"tbody", "thead", "tfoot"})
# Where the list of elements a browser may reopen starts again: a link inside a table cell
# does not end a link around the table, and nothing from inside the cell is reopened after it.
_MARKERS = frozenset({"applet", "caption", "marquee", "object", "td", "template", "th"})
_HEADINGS = frozenset({"h1", "h2", "h3", "h4", "h5", "h6"})
# The parts of a table. Their start tags are dropped, attributes and all, where no table is
# being filled; inside one they close whatever is open back to where the part belongs.
_TABLE_ONLY = frozenset({"caption", "col", "colgroup", "tbody", "td", "tfoot", "th", "thead", "tr"})
# Directly inside one of these, text and any element that is not part of the table are moved
# out and drawn before the table, so the table's own style does not apply to them.
_TABLE_CONTEXT = frozenset({"table", "tbody", "thead", "tfoot", "tr"})
_TABLE_ITSELF = frozenset({"table"})
_TABLE_ENDS = frozenset({"html", "table", "template"})
_ROW_HOME = _TABLE_ENDS | _TABLE_PARTS
_CELL_HOME = _ROW_HOME | {"tr"}
# Elements that belong in the head: anything else written there starts the body.
_HEAD_ONLY = frozenset(
    {
        "base", "basefont", "bgsound", "link", "meta", "noframes", "noscript", "script", "style",
        "template", "title",
    }
)  # fmt: skip
# A list item, a term, or a description ends the open one unless a block element other than
# these three is in the way.
_ITEM_BARRIERS = _SPECIAL - {"address", "div", "p"}
_ITEM_ENDS = frozenset({"dd", "dt"})
_LI_ONLY = frozenset({"li"})
_BUTTON_ONLY = frozenset({"button"})
_FORM_ONLY = frozenset({"form"})
_TEMPLATE_ONLY = frozenset({"template"})
# Start tags with a rule of their own about what they end.
_ENDERS = frozenset(
    {"a", "button", "dd", "dt", "li", "nobr", "optgroup", "option", "rb", "rp", "rt", "rtc"}
)
_RUBY_PARTS = frozenset({"rb", "rp", "rt", "rtc"})
_RUBY_ENDS_LESS = _ENDS_ITSELF - {"rtc"}
# Start tags a browser inserts without first reopening the formatting elements that were
# closed from outside; every other start tag, and text, reopens them.
_NO_REOPEN = frozenset(
    {
        "address", "article", "aside", "base", "basefont", "bgsound", "blockquote", "body",
        "center", "dd", "details", "dialog", "dir", "div", "dl", "dt", "fieldset", "figcaption",
        "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header",
        "hgroup", "hr", "html", "iframe", "li", "link", "listing", "main", "menu", "meta", "nav",
        "noembed", "noframes", "noscript", "ol", "p", "param", "plaintext", "pre", "rb", "rp",
        "rt", "rtc", "script", "search", "section", "source", "style", "summary", "table",
        "template", "textarea", "title", "track", "ul",
    }
)  # fmt: skip
# HTML start tags that end an open ``svg`` or ``math``: the element is drawn after it.
_FOREIGN_BREAKOUT = frozenset(
    {
        "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt", "em",
        "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li", "listing",
        "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span", "strong",
        "strike", "sub", "sup", "table", "tt", "u", "ul", "var",
    }
)  # fmt: skip
_FOREIGN_ROOTS = frozenset({"svg", "math"})
# Markup this reader does not follow: where one of these is written the element reader stops.
_NOT_FOLLOWED = frozenset({"annotation-xml", "malignmark", "mglyph"})
# How far down the open elements a rule looks. Past it the tree is not known, so the element
# reader stops; no ordinary page nests inline markup this deep around a misnested tag.
_SCAN = 64
# The reader's own bounds. No page nests elements 500 deep or holds 400,000 tags; past either
# the element reader stops, so a file made of nothing but tags costs a bounded amount of work.
# Comments and data-* values are read to the end.
_MAX_DEPTH = 500
_MAX_TAGS = 400_000
_K_CONTEXT, _K_TABLE, _K_MARKER, _K_FORMAT, _K_FOREIGN = 1, 2, 4, 8, 16

_SR_ONLY = frozenset({"sr-only", "visually-hidden", "screen-reader-text"})
# Elements that take neither a font size nor a colour from what they are in: a form control,
# a mark, an open dialog. A table is here because without a standards doctype it takes neither
# from its parent; with one the claim is only dropped.
_OWN_STYLE = frozenset(
    {"button", "dialog", "input", "mark", "optgroup", "option", "select", "table", "textarea"}
)
# Inline elements with no colour of their own: their text sits in the boxes of the inline
# element around them, over the background it paints.
_INLINE = frozenset(
    {
        "a", "abbr", "b", "bdi", "bdo", "cite", "code", "dfn", "em", "font", "i", "kbd", "label",
        "nobr", "s", "samp", "small", "span", "strike", "strong", "tt", "u", "var",
    }
)  # fmt: skip
# Elements that are a block box unless a style says otherwise: a background they declare is
# behind everything written in them.
_BLOCK_BOXES = frozenset(
    {
        "address", "article", "aside", "blockquote", "body", "center", "dd", "div", "dl", "dt",
        "figcaption", "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header",
        "hgroup", "li", "main", "nav", "ol", "p", "pre", "section", "td", "th", "ul",
    }
)  # fmt: skip
# A data-* value shorter than this, or with no space, is an identifier, a flag, or a URL.
_DATA_MIN = 12

_PAGE_SCRIPT = re.compile(r"""(?i)<script\b|[\t\n\f\r "'/]on[a-z]{3,24}[\t\n\f\r ]*=""")
_PAGE_LINKED_STYLE = re.compile(
    r"(?i)<link\b[^<>]{0,1024}\bstylesheet|@import\b|<\?xml-stylesheet\b"
)
_PAGE_STYLE_OPEN = re.compile(r"(?i)<style\b")
_PAGE_STYLE_CLOSE = re.compile(r"(?i)</style\b")
_STYLE_PAINTS = re.compile(r"(?i)background")
_STYLE_MOVES = re.compile(r"(?i)animation|transition|@keyframes|opacity")
_PAGE_GLYPHS = re.compile(r"(?i)background-clip|text-fill-color|text-shadow|text-stroke")
# The doctype that puts a browser in standards mode whatever else it reads, and any doctype
# at all. An older doctype selects a mode by a list of identifiers this reader does not hold.
_PAGE_STANDARDS = re.compile(r"(?i)<!doctype[\t\n\f\r ]+html[\t\n\f\r ]*>")
_PAGE_DOCTYPE = re.compile(r"(?i)<!doctype\b")

# The characters CSS takes as whitespace. ``str.strip`` alone also strips a no-break space,
# which in CSS is part of a name.
_CSS_SPACE = " \t\n\r\f"
_CSS_GAPS = re.compile(r"[ \t\n\r\f]+")
_CSS_SYNTAX = re.compile(r"""[\\"'()\[\]{}]|/\*""")
_CSS_SPECIAL = re.compile(r"""/\*|[\\"'()\[\]{};]""")
_CSS_ESCAPE = re.compile(r"\\(?:([0-9A-Fa-f]{1,6})[ \t\n\r\f]?|(.))", re.DOTALL)
_CSS_STRING = {
    '"': re.compile(r'(?:[^"\\\n\r\f]|\\.)*+', re.DOTALL),
    "'": re.compile(r"(?:[^'\\\n\r\f]|\\.)*+", re.DOTALL),
}
_CSS_IMPORTANT = re.compile(r"![ \t\n\r\f]*important\Z")
# An address written without quotes: everything to the closing parenthesis is the address, and
# a quote or a comment opener inside it is not one. One with a quote, a parenthesis, a
# backslash, or a space in the middle is read by rules this reader does not follow.
_CSS_URL = re.compile(r"""[ \t\n\r\f]*+(?!["'])([^"'()\\ \t\n\r\f]*+)[ \t\n\r\f]*+\)""")
# A shorthand resets the longhand declared before it; "all" resets everything.
_CSS_SHORTHANDS = {"font": ("font-size",), "background": ("background-color",)}
_CSS_REAL = r"(?:\d{1,8}(?:\.\d{1,8})?|\.\d{1,8})"
_CSS_NOTHING = r"[+-]?(?:0{1,8}(?:\.0{1,8})?|\.0{1,8})"
# Zero as a font size: with a unit a browser knows, or with none.
_CSS_ZERO_SIZE = re.compile(
    _CSS_NOTHING + r"(?:px|pt|pc|in|cm|mm|q|em|rem|ex|ch|vw|vh|vmin|vmax|%)?"
)
# A size relative to the parent's: under a parent of zero it is zero too.
_CSS_RELATIVE_SIZE = re.compile(r"\+?" + _CSS_REAL + r"(?:em|%)")
_CSS_SAME_SIZE = frozenset({"inherit", "unset", "smaller", "larger"})
_CSS_SAME_VISIBILITY = frozenset({"inherit", "unset"})
_CSS_ZERO_ALPHA = re.compile(_CSS_NOTHING + "%?")
_CSS_MOVES = ("transition", "animation", "transform", "will-change")
_CSS_HEX = re.compile(r"#([0-9a-f]{3,8})")
_CSS_FUNCTION = re.compile(r"(rgba?|hsla?)\(([^()]{0,96})\)")
_CSS_NUMBER = re.compile(r"[+-]?" + _CSS_REAL)
_CSS_PERCENT = re.compile(r"[+-]?" + _CSS_REAL + "%")
_CSS_HUE = re.compile(r"[+-]?" + _CSS_REAL + "(?:deg)?")
# The properties an element may declare beside a colour and a background of the same colour.
# None of them draws the text another way, puts anything else behind it, or moves it out of
# the box the background fills.
_CSS_PLAIN = frozenset(
    {
        "background", "background-color", "color", "display", "font-family", "font-size",
        "font-style", "font-weight", "letter-spacing", "margin", "margin-bottom", "margin-left",
        "margin-right", "margin-top", "padding", "padding-bottom", "padding-left",
        "padding-right", "padding-top", "text-align",
    }
)  # fmt: skip
_CSS_BOXES = {"block": 2, "inline-block": 2, "inline": 1}
# The sixteen HTML colours, the X11 near-whites, and the light greys mail templates use. Any
# other name is a colour this reader does not know, which never counts as hidden.
_CSS_COLORS: dict[str, tuple[int, int, int]] = {
    "black": (0, 0, 0), "silver": (192, 192, 192), "gray": (128, 128, 128),
    "grey": (128, 128, 128), "white": (255, 255, 255), "maroon": (128, 0, 0),
    "red": (255, 0, 0), "purple": (128, 0, 128), "fuchsia": (255, 0, 255),
    "magenta": (255, 0, 255), "green": (0, 128, 0), "lime": (0, 255, 0),
    "olive": (128, 128, 0), "yellow": (255, 255, 0), "navy": (0, 0, 128),
    "blue": (0, 0, 255), "teal": (0, 128, 128), "aqua": (0, 255, 255),
    "cyan": (0, 255, 255), "orange": (255, 165, 0), "snow": (255, 250, 250),
    "ivory": (255, 255, 240), "ghostwhite": (248, 248, 255), "floralwhite": (255, 250, 240),
    "azure": (240, 255, 255), "mintcream": (245, 255, 250), "whitesmoke": (245, 245, 245),
    "aliceblue": (240, 248, 255), "honeydew": (240, 255, 240),
    "lavenderblush": (255, 240, 245), "seashell": (255, 245, 238), "linen": (250, 240, 230),
    "oldlace": (253, 245, 230), "beige": (245, 245, 220), "gainsboro": (220, 220, 220),
    "lightgray": (211, 211, 211), "lightgrey": (211, 211, 211), "darkgray": (169, 169, 169),
    "darkgrey": (169, 169, 169), "dimgray": (105, 105, 105), "dimgrey": (105, 105, 105),
}  # fmt: skip
# Text within this many steps of its background on every channel reads as the background.
_SAME_COLOUR = 12
# An alpha at or below this, of 255, is ink a reader does not see.
_CLEAR_ALPHA = 5
_NO_ATTRS: dict[str, str] = {}
# A character reference as an attribute value holds one.
_REFERENCE = re.compile(r"&(#[0-9]++;?|#[xX][0-9A-Fa-f]++;?|[A-Za-z][A-Za-z0-9]{1,31};?)")


@dataclass(frozen=True)
class _PageFacts:
    """What a document's own scripts and stylesheets could change, read lexically.

    Each is decided for the whole document before any element is judged, and each errs toward
    "could": a ``<script`` inside a comment still counts as a script.
    """

    # No script and no animating style: nothing can raise an opacity of zero.
    static: bool
    # A stylesheet exists. It may give any element a colour or a font size of its own, by the
    # element's type as well as by a class or id, and it may undo the hidden attribute.
    restyles: bool
    # A stylesheet is linked, so what it holds is not known.
    linked: bool
    # A stylesheet may put an image behind an element that declares only a background colour.
    repaints: bool
    # Some style draws text by a clip, a shadow, a stroke, or a fill, whatever its colour.
    glyphs: bool
    # Whether the document is in quirks mode, where a table stays inside an open paragraph:
    # False under the plain doctype, True with no doctype at all, None when an older doctype
    # decides it.
    quirks: bool | None


def _prologue_end(head: str, *, xml_too: bool = True) -> int:
    """Where a document's first tag or text starts: past a byte order mark, whitespace,
    comments, and processing instructions (an XML declaration among them unless ``xml_too``
    is off). Each is skipped on its own with ``str.find``, so nothing reconsiders where an
    earlier one ended."""
    position = 1 if head.startswith("\ufeff") else 0
    size = len(head)
    while True:
        while position < size and head[position] in _HTML_BLANK:
            position += 1
        if head.startswith("<!--", position):
            end = head.find("-->", position + 4)
            step = 3
        elif head.startswith("<?", position) and (
            xml_too or head[position : position + 5].lower() != "<?xml"
        ):
            end = head.find(">", position + 2)
            step = 1
        else:
            return position
        if end < 0:
            return size
        position = end + step


def _quirks(head: str) -> bool | None:
    start = _prologue_end(head)
    if _PAGE_STANDARDS.match(head, start) is not None:
        return False
    if _PAGE_DOCTYPE.match(head, start) is not None or start >= len(head):
        return None
    return True


def _page_facts(text: str) -> _PageFacts:
    linked = _PAGE_LINKED_STYLE.search(text) is not None
    paints = moves = sheets = False
    position = 0
    while not (paints and moves):
        opened = _PAGE_STYLE_OPEN.search(text, position)
        if opened is None:
            break
        sheets = True
        closed = _PAGE_STYLE_CLOSE.search(text, opened.end())
        end = len(text) if closed is None else closed.start()
        paints = paints or _STYLE_PAINTS.search(text, opened.end(), end) is not None
        moves = moves or _STYLE_MOVES.search(text, opened.end(), end) is not None
        if closed is None:
            # An unclosed style runs to the end, so no later one is searched for.
            break
        position = closed.end()
    return _PageFacts(
        static=not linked and not moves and _PAGE_SCRIPT.search(text) is None,
        restyles=linked or sheets,
        linked=linked,
        repaints=linked or paints,
        glyphs=_PAGE_GLYPHS.search(text) is not None,
        quirks=_quirks(text[:8192]),
    )


def _attribute_reference(match: re.Match[str]) -> str:
    body = match.group(1)
    if body[0] == "#":
        # A numeric reference reads the same in text and in an attribute value.
        return html.unescape(match.group())
    if body.endswith(";") and body in _REFERENCES:
        return _REFERENCES[body]
    # No name that ends in a semicolon: one of the old names that needs none may start it. In
    # an attribute value such a name stays as written when a letter, a digit, or = follows.
    name = body.rstrip(";")
    text = match.string
    for length in range(len(name), 1, -1):
        prefix = name[:length]
        if prefix in _REFERENCES:
            after = text[match.start() + 1 + length : match.start() + 2 + length]
            if after == "=" or (after.isascii() and after.isalnum()):
                return match.group()
            return _REFERENCES[prefix] + body[length:]
    return match.group()


def _attribute_text(value: str) -> str:
    """An attribute value with its character references decoded as a browser decodes them."""
    return _REFERENCE.sub(_attribute_reference, value) if "&" in value else value


def _css_unescape(match: re.Match[str]) -> str:
    digits = match.group(1)
    if digits is None:
        char = match.group(2)
    else:
        code = int(digits, 16)
        char = chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else "�"
    # An escaped letter is that letter inside a name. An escaped digit, space, or sign is not
    # the character it spells: ``\30 px`` is a name, not zero pixels, and ``none\9`` is not
    # ``none``. Those become a character no name or value here contains.
    return char if char.isalpha() or char in "-_" else "�"


def _css_parts(style: str) -> list[str] | None:
    """A style's declarations as written, split at the semicolons that end one.

    Comments are removed. A semicolon inside a string, parentheses, or brackets ends nothing,
    and a block that never closes takes the rest of the style with it, as in a browser. None
    for a style this reader does not follow: one with a brace, where a browser may read a
    nested rule, with a string broken by a line break, with an unquoted address that is not
    plain, or with an escape beside a parenthesis, which may spell a name this reader acts on.
    """
    if "\\" in style and "(" in style:
        return None
    parts: list[str] = []
    current: list[str] = []
    closers: list[str] = []
    position = 0
    size = len(style)
    while True:
        found = _CSS_SPECIAL.search(style, position)
        if found is None:
            current.append(style[position:])
            break
        at = found.start()
        current.append(style[position:at])
        mark = found.group()
        position = at + 1
        if mark == "/*":
            closed = style.find("*/", at + 2)
            if closed < 0:
                break
            current.append(" ")
            position = closed + 2
        elif mark == "\\":
            escape = _CSS_ESCAPE.match(style, at)
            if escape is None:
                return None
            current.append(escape.group())
            position = escape.end()
        elif mark in "\"'":
            body = _CSS_STRING[mark].match(style, position)
            end = size if body is None else body.end()
            if end < size and style[end] != mark:
                return None
            current.append(style[at : end + 1])
            if end >= size:
                break
            position = end + 1
        elif mark in "{}":
            return None
        elif mark == ";" and not closers:
            parts.append("".join(current))
            current = []
        else:
            if mark == "(":
                if style[max(0, at - 3) : at].translate(_ASCII_LOWER) == "url":
                    address = _CSS_URL.match(style, position)
                    if address is None:
                        if style[position:].lstrip(_CSS_SPACE)[:1] not in ('"', "'"):
                            return None
                    else:
                        current.append(style[at : address.end()])
                        position = address.end()
                        continue
                closers.append(")")
            elif mark == "[":
                closers.append("]")
            elif closers and mark == closers[-1]:
                closers.pop()
            current.append(mark)
    parts.append("".join(current))
    return parts


def _css_declarations(style: str) -> dict[str, str] | None:
    """An inline style's declarations, ASCII-lowercased: property to value as written.

    A later declaration replaces an earlier one unless the earlier one is ``!important`` and
    the later one is not, as a browser resolves a single style attribute. A browser also
    drops a declaration whose value it cannot parse and keeps the earlier one; here the later
    value stays, and whoever reads it takes any value it does not know as no claim. None for
    a style this reader does not follow.
    """
    parts = style.split(";") if _CSS_SYNTAX.search(style) is None else _css_parts(style)
    if parts is None:
        return None
    found: dict[str, str] = {}
    weighted: set[str] = set()
    for part in parts:
        name, colon, value = part.partition(":")
        if not colon:
            continue
        if "\\" in part:
            name = _CSS_ESCAPE.sub(_css_unescape, name)
            value = _CSS_ESCAPE.sub(_css_unescape, value)
        name = name.strip(_CSS_SPACE).translate(_ASCII_LOWER)
        value = value.strip(_CSS_SPACE).translate(_ASCII_LOWER)
        important = _CSS_IMPORTANT.search(value)
        if important is not None:
            value = value[: important.start()].rstrip(_CSS_SPACE)
        elif name in weighted:
            continue
        if name == "all":
            # Everything declared so far goes back to its initial or inherited value. The entry
            # stays so the reader knows nothing is inherited that it can rely on.
            for earlier in [key for key in found if important or key not in weighted]:
                del found[earlier]
            found[name] = value
            continue
        for longhand in _CSS_SHORTHANDS.get(name, ()):
            if important or longhand not in weighted:
                found.pop(longhand, None)
        if important:
            weighted.add(name)
            weighted.update(_CSS_SHORTHANDS.get(name, ()))
        found[name] = value
    return found


def _css_color(value: str) -> tuple[int, int, int, int] | None:
    """Red, green, blue, and alpha (0 to 255) of a colour in a spelling a browser takes.

    None for anything else: a name outside the table, a system colour, a variable, a function
    with the wrong number of parts or with numbers and percentages mixed. A browser drops such
    a declaration or draws a colour this reader does not know, so it is never a claim.
    """
    if value == "transparent":
        return (0, 0, 0, 0)
    named = _CSS_COLORS.get(value)
    if named is not None:
        return (*named, 255)
    hexed = _CSS_HEX.fullmatch(value)
    if hexed is not None:
        digits = hexed.group(1)
        if len(digits) in (3, 4):
            digits = "".join(char * 2 for char in digits)
        if len(digits) not in (6, 8):
            return None
        alpha = int(digits[6:8], 16) if len(digits) == 8 else 255
        return (int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16), alpha)
    function = _CSS_FUNCTION.fullmatch(value)
    if function is None:
        return None
    inner = function.group(2).strip(_CSS_SPACE)
    faint: str | None = None
    if "," in inner:
        # The older spelling: three parts and an optional alpha, all apart by commas.
        parts = [part.strip(_CSS_SPACE) for part in inner.split(",")]
        if len(parts) == 4:
            faint = parts.pop()
    else:
        main, slash, tail = inner.partition("/")
        parts = _CSS_GAPS.split(main.strip(_CSS_SPACE))
        if slash:
            faint = tail.strip(_CSS_SPACE)
    if len(parts) != 3:
        return None
    if faint is None:
        alpha = 255
    elif _CSS_PERCENT.fullmatch(faint) is not None:
        alpha = round(min(1.0, max(0.0, float(faint[:-1]) / 100)) * 255)
    elif _CSS_NUMBER.fullmatch(faint) is not None:
        alpha = round(min(1.0, max(0.0, float(faint))) * 255)
    else:
        return None
    if function.group(1).startswith("rgb"):
        if all(_CSS_NUMBER.fullmatch(part) is not None for part in parts):
            levels = [float(part) for part in parts]
        elif all(_CSS_PERCENT.fullmatch(part) is not None for part in parts):
            levels = [float(part[:-1]) * 2.55 for part in parts]
        else:
            return None
        red, green, blue = (round(min(255.0, max(0.0, level))) for level in levels)
        return (red, green, blue, alpha)
    if _CSS_HUE.fullmatch(parts[0]) is None:
        return None
    if _CSS_PERCENT.fullmatch(parts[1]) is None or _CSS_PERCENT.fullmatch(parts[2]) is None:
        return None
    hue = float(parts[0].removesuffix("deg")) % 360 / 360
    saturation = min(1.0, max(0.0, float(parts[1][:-1]) / 100))
    lightness = min(1.0, max(0.0, float(parts[2][:-1]) / 100))
    mixed = colorsys.hls_to_rgb(hue, lightness, saturation)
    return (round(mixed[0] * 255), round(mixed[1] * 255), round(mixed[2] * 255), alpha)


class _Sight(NamedTuple):
    """What decides whether the text directly inside an element is shown."""

    # Not drawn, whatever is inside: display none, the hidden attribute, a template, a
    # settled zero opacity.
    gone: bool
    # visibility: hidden, which a descendant may turn back on.
    invisible: bool
    # A font size of zero, which a descendant may set again.
    zero: bool
    # Transparent ink. Followed only into elements that carry no attribute, and into none in
    # a document with a stylesheet: either may be a colour of the element's own.
    veiled: bool
    # Ink the colour of the background its own element declares: 1 from an inline element,
    # whose background is behind inline text only, 2 from a block box. Followed like veiled.
    blend: int
    # A screen-reader-only class, taken to clip the element to nothing. Followed into
    # elements that carry no attribute.
    tucked: bool
    # Any of the above.
    hidden: bool


_PLAIN = _Sight(False, False, False, False, 0, False, False)


def _sight_of(
    tag: str, attrs: dict[str, str], parent: _Sight, facts: _PageFacts, *, foreign: bool
) -> _Sight:
    """The sight of an element from its own attributes and its parent's sight."""
    if parent.gone:
        # Nothing inside an element that is not drawn can be shown again.
        return parent
    template = tag == "template" and not foreign
    if not attrs and not template:
        if not parent.hidden:
            return parent
        if not (parent.zero or parent.veiled or parent.blend or tag in _OWN_STYLE):
            # Hidden by visibility or a class, which every element without attributes keeps.
            return parent
    _, invisible, zero, veiled, blend, tucked, _ = parent
    gone = template
    if foreign:
        # SVG text is painted by fill, not by the colour this reader follows.
        veiled, blend = False, 0
    elif tag in _OWN_STYLE:
        zero, veiled, blend, tucked = False, False, 0, False
    if facts.restyles:
        # A stylesheet styles elements by their type: "code { color: ... }" and
        # "p { font-size: 16px }" are ordinary. A colour or a size an ancestor declared is
        # followed into no element here, only to the text directly inside that ancestor.
        zero, veiled, blend = False, False, 0
    if not attrs:
        if blend == 1 and tag not in _INLINE:
            # A block inside an inline element is not over the inline element's background.
            blend = 0
    else:
        veiled, blend, tucked = False, 0, False
        style = attrs.get("style")
        rules = _css_declarations(_attribute_text(style)) if style is not None else {}
        # A class or id a stylesheet may use to restyle this element.
        hooked = facts.restyles and ("class" in attrs or "id" in attrs)
        if rules is None or hooked or foreign or "all" in rules:
            # The style is not followed, a stylesheet may set what the style does not, an svg
            # attribute may, or "all" sets everything back: nothing inherited is relied on.
            invisible = zero = False
        if tag == "font" and "size" in attrs:
            zero = False
        if rules is not None:
            display = rules.get("display")
            if display == "none":
                gone = True
            elif "hidden" in attrs and display is None and "all" not in rules:
                # The browser's own display:none for an HTML element. Any display the style
                # declares overrides it, and so does a stylesheet's ("section { display:
                # block }" is in every older reset), so it counts only where there is no
                # stylesheet. It means nothing on an svg element, and a marquee is drawn
                # with it set.
                gone = gone or not (facts.restyles or foreign or tag == "marquee")
            visibility = rules.get("visibility")
            if visibility in ("hidden", "collapse"):
                invisible = True
            elif visibility is not None and visibility not in _CSS_SAME_VISIBILITY:
                invisible = False
            size = rules.get("font-size")
            if size is None:
                if "font" in rules:
                    zero = False
            elif _CSS_ZERO_SIZE.fullmatch(size) is not None:
                zero = True
            elif size not in _CSS_SAME_SIZE and _CSS_RELATIVE_SIZE.fullmatch(size) is None:
                zero = False
            opacity = rules.get("opacity")
            if opacity is not None and facts.static and not gone:
                # Only where nothing could raise it: a fade-in starts from the same style, and
                # an older spelling of the property, written after it, sets it again.
                settled = not any(
                    name.startswith(_CSS_MOVES) or name.endswith("-opacity") for name in rules
                )
                gone = settled and _CSS_ZERO_ALPHA.fullmatch(opacity) is not None
            ink = rules.get("color")
            if ink is not None and not foreign and not facts.glyphs and not facts.linked:
                # Not where a linked stylesheet could draw the text by a shadow or a stroke.
                veiled, blend = _unseen_ink(tag, attrs, rules, ink, facts)
        if style is None and "class" in attrs and facts.restyles and not foreign:
            # A class a stylesheet is taken to clip to nothing, as the lexical rule takes it.
            tucked = not _SR_ONLY.isdisjoint(_HTML_SPACES.split(attrs["class"]))
    concealed = gone or invisible or zero or veiled or blend > 0 or tucked
    sight = _Sight(gone, invisible, zero, veiled, blend, tucked, concealed)
    return parent if sight == parent else sight


def _unseen_ink(
    tag: str, attrs: dict[str, str], rules: dict[str, str], ink: str, facts: _PageFacts
) -> tuple[bool, int]:
    """Whether an element's own colour hides its text: transparent, or its own background's."""
    colour = _css_color(ink)
    if colour is None:
        return False, 0
    if colour[3] <= _CLEAR_ALPHA:
        return True, 0
    paint = rules.get("background-color")
    whole = rules.get("background")
    if paint is None:
        paint = whole
    elif whole is None:
        if facts.repaints:
            # Only the colour is declared: a stylesheet's image would still be behind the text.
            return False, 0
    elif whole not in ("none", "transparent") and _css_color(whole) is None:
        # The colour was declared after a background that may hold an image, which stays.
        return False, 0
    if paint is None or tag in _OWN_STYLE or "background" in attrs:
        return False, 0
    if any(name not in _CSS_PLAIN and not name.startswith("mso-") for name in rules):
        return False, 0
    behind = _css_color(paint)
    if behind is None or behind[3] != 255:
        return False, 0
    if max(abs(colour[index] - behind[index]) for index in range(3)) > _SAME_COLOUR:
        return False, 0
    display = rules.get("display")
    if display is not None:
        return False, _CSS_BOXES.get(display, 0)
    return False, 2 if tag in _BLOCK_BOXES else 1 if tag in _INLINE else 0


class _Pieces:
    """Hidden pieces and shown text, in document order."""

    def __init__(self) -> None:
        self.pieces: list[str] = []
        self.shown: list[str] = []
        # For each piece, whether it is element text, which depends on the open elements.
        self._from_elements: list[bool] = []
        self._seen: set[str] = set()
        self._current: list[str] = []
        self._hidden_chars = False

    def keep(self, piece: str, *, sentence: bool = False, element: bool = False) -> None:
        """Add one piece, once: a comment, an attribute value, or a finished hidden stretch."""
        lines = (line.strip() for line in piece.split("\n"))
        piece = "\n".join(line for line in lines if line)
        if len(piece) < 3 or piece in self._seen:
            return
        if sentence and (len(piece) < _DATA_MIN or " " not in piece):
            return
        if len(self.pieces) >= MAX_TEXT_PIECES:
            raise ContentLimit("text pieces exceed 100000")
        self._seen.add(piece)
        self.pieces.append(piece)
        self._from_elements.append(element)

    def flush(self) -> None:
        if self._hidden_chars:
            self.keep("".join(self._current), element=True)
        self._current.clear()
        self._hidden_chars = False

    def retract(self, since: int) -> None:
        """Take back the element text kept from piece ``since`` on, and the open stretch.

        A browser can change what is around text it has already placed: a formatting element
        that ends across a block is copied around the block's earlier content. What was judged
        there is no longer known. Comments and attribute values do not depend on the open
        elements and are kept.
        """
        self._current.clear()
        self._hidden_chars = False
        if since >= len(self.pieces):
            return
        kept: list[str] = []
        for piece, element in zip(self.pieces[since:], self._from_elements[since:], strict=True):
            if element:
                self._seen.discard(piece)
            else:
                kept.append(piece)
        del self.pieces[since:]
        del self._from_elements[since:]
        self.pieces.extend(kept)
        self._from_elements.extend([False] * len(kept))

    def run(self, raw: str, sight: _Sight, *, entities: bool = True) -> None:
        """One run of text under ``sight``: part of a hidden stretch, or shown."""
        piece = html.unescape(raw) if entities and "&" in raw else raw
        piece = _HTML_SPACE.sub(" ", piece)
        if sight.hidden:
            self._current.append(piece)
            self._hidden_chars = self._hidden_chars or bool(piece.strip())
        elif piece.strip():
            self.flush()
            self.shown.append(piece)
        elif self._hidden_chars:
            # A shown space between two hidden runs is kept, as between hidden Office runs.
            self._current.append(piece)

    def boundary(self) -> None:
        """A block edge or a line break: a newline inside a hidden stretch."""
        if self._hidden_chars:
            self._current.append("\n")
        self.shown.append(" ")


# One open element: its name, its sight, its attributes (to reopen it), what it registered, and
# how many pieces had been kept when it opened.
_Frame = tuple[str, _Sight, dict[str, str], int, int]


class _Tree:
    """The open elements of a document, as far as what is drawn depends on them.

    ``doubt`` is set when the markup goes past what is modeled (a rule would have to look
    deeper than ``_SCAN`` elements, a formatting element ends across a table cell or an
    ``svg``, a ``select`` holds something other than options) or past the reader's bounds.
    From then on no element is judged and every text run is shown.
    """

    def __init__(self, facts: _PageFacts, out: _Pieces) -> None:
        self.facts = facts
        self.out = out
        self.stack: list[_Frame] = []
        # How many HTML elements of each name are open; svg and math elements are not counted.
        self.opened: dict[str, int] = {}
        # Formatting elements closed from outside, waiting to be reopened, oldest first; and
        # for each open marker element, where its own entries start.
        self.pending: list[tuple[str, dict[str, str]]] = []
        self.marks: list[int] = []
        # For each open table, the sight of the element it sits in.
        self.around_tables: list[_Sight] = []
        # For each open svg or math its name, and "" for each element inside one that holds
        # HTML again.
        self.context: list[str] = []
        # Whether an html element, a head, and a body exist yet: a browser makes each when the
        # first thing that needs it is written, tag or no tag.
        self.rooted = False
        self.saw_head = False
        self.body = False
        # The parser's form element pointer: set by a form start tag and cleared only by a form
        # end tag. A form closed any other way (by its parent's end tag) leaves it set, and
        # the next form start tag is then ignored although no form is open.
        self.form = False
        # The attribute names on the first html and body tags: a later tag adds what is new.
        self.root_attrs: dict[str, frozenset[str]] = {}
        self.doubt = False

    @property
    def foreign(self) -> bool:
        return bool(self.context) and bool(self.context[-1])

    def sight(self) -> _Sight:
        return self.stack[-1][1] if self.stack else _PLAIN

    def top_is(self, tag: str) -> bool:
        """Whether the current element is the HTML element ``tag``."""
        return bool(self.stack) and self.stack[-1][0] == tag and not self.stack[-1][3] & _K_FOREIGN

    def outer(self) -> _Sight:
        """The sight a new child of the current element starts from. Text and elements written
        directly inside a table are drawn before it, in whatever the table sits in."""
        if not self.stack:
            return _PLAIN
        tag, sight, _, kind, _ = self.stack[-1]
        if tag in _TABLE_CONTEXT and not kind & _K_FOREIGN and self.around_tables:
            return self.around_tables[-1]
        return sight

    def lose_track(self) -> None:
        self.doubt = True
        self.out.flush()

    def push(
        self, tag: str, sight: _Sight, attrs: dict[str, str], around: _Sight, space: str = ""
    ) -> None:
        """Open an element. ``space`` is "svg" or "math" for an element of that kind."""
        kind = 0
        if space:
            kind = _K_FOREIGN
            if tag == space:
                self.context.append(space)
                kind |= _K_CONTEXT
            elif tag in _INTEGRATION[space]:
                self.context.append("")
                kind |= _K_CONTEXT
        else:
            self.opened[tag] = self.opened.get(tag, 0) + 1
            if tag == "table":
                self.around_tables.append(around)
                kind |= _K_TABLE
            if tag in _MARKERS:
                self.marks.append(len(self.pending))
                kind |= _K_MARKER
            elif tag in _FORMATTING:
                kind |= _K_FORMAT
        self.stack.append((tag, sight, attrs, kind, len(self.out.pieces)))
        if len(self.stack) > _MAX_DEPTH:
            self.lose_track()

    def pop(self, depth: int, *, outside: bool = False) -> None:
        """Close the top ``depth`` elements. A formatting element among them waits to be
        reopened, except the lowest one when its own end tag closed it (not ``outside``)."""
        frames = self.stack[-depth:]
        del self.stack[-depth:]
        waiting: list[tuple[str, dict[str, str]]] = []
        for index in range(depth - 1, -1, -1):
            tag, _, attrs, kind, _ = frames[index]
            if kind & _K_FOREIGN:
                if kind & _K_CONTEXT:
                    self.context.pop()
                continue
            self.opened[tag] -= 1
            if kind & _K_TABLE:
                self.around_tables.pop()
            if kind & _K_MARKER:
                # Nothing opened inside a cell, a caption, or a template is reopened after it.
                waiting.clear()
                del self.pending[self.marks.pop() :]
            elif kind & _K_FORMAT and (index or outside):
                waiting.append((tag, attrs))
        if waiting:
            self.pending.extend(reversed(waiting))
            if len(self.pending) > _SCAN:
                self.lose_track()

    def find(self, names: frozenset[str] | str, barriers: frozenset[str]) -> int:
        """How many elements to close to end the nearest HTML one named in ``names`` (a set,
        or one name): 0 when a barrier or the bottom comes first, -1 when it is deeper than
        this reader looks. An element is looked at as a name before it is a barrier."""
        stack = self.stack
        limit = min(len(stack), _SCAN)
        one = names if isinstance(names, str) else None
        for depth in range(1, limit + 1):
            tag, _, _, kind, _ = stack[-depth]
            if kind & _K_FOREIGN:
                # An svg or math element is a barrier only where it holds HTML.
                if kind & _K_CONTEXT and tag in barriers:
                    return 0
            elif tag == one if one is not None else tag in names:
                return depth
            elif tag in barriers:
                return 0
        return 0 if limit == len(stack) else -1

    def close(self, names: frozenset[str] | str, barriers: frozenset[str]) -> None:
        if isinstance(names, str):
            if not self.opened.get(names):
                return
        elif not any(self.opened.get(name) for name in names):
            return
        depth = self.find(names, barriers)
        if depth > 0:
            self.pop(depth)
        elif depth < 0:
            self.lose_track()

    def clear_to(self, homes: frozenset[str]) -> str:
        """Close elements until the current one is in ``homes``; its name, or "" if none is."""
        depth = 0
        for tag, _, _, kind, _ in reversed(self.stack):
            if tag in homes and not kind & _K_FOREIGN:
                if depth:
                    self.pop(depth, outside=True)
                return tag
            depth += 1
        return ""

    def listed(self, tag: str, attrs: dict[str, str] | None = None) -> int:
        """Among the open formatting elements a browser keeps a list of, how deep the nearest
        ``tag`` is (0 for none), or with ``attrs`` how many carry the same attributes."""
        same = 0
        limit = min(len(self.stack), _SCAN)
        for depth in range(1, limit + 1):
            name, _, held, kind, _ = self.stack[-depth]
            if kind & _K_MARKER:
                return same
            if name == tag and kind & _K_FORMAT:
                if attrs is None:
                    return depth
                same += held == attrs
        if limit < len(self.stack):
            self.lose_track()
        return same

    def reopen(self) -> None:
        """Reopen the formatting elements that were closed from outside, in order."""
        base = self.marks[-1] if self.marks else 0
        if len(self.pending) <= base:
            return
        entries = self.pending[base:]
        del self.pending[base:]
        for tag, attrs in entries:
            parent = self.outer()
            self.push(tag, _sight_of(tag, attrs, parent, self.facts, foreign=False), attrs, parent)

    def start_body(self) -> None:
        """Text or an element that belongs in a body makes one, where none is written yet."""
        if not self.body:
            self.close(_HEAD, _NONE)
            self.rooted = self.saw_head = self.body = True
            self.root_attrs.setdefault("html", frozenset())
            self.root_attrs.setdefault("body", frozenset())

    def table_mode(self) -> str:
        """Where the nearest table is being filled: "table" outside its cells, "cell" inside a
        cell or a caption, "" when no table is in reach."""
        if not self.opened.get("table"):
            return ""
        limit = min(len(self.stack), _SCAN)
        for depth in range(1, limit + 1):
            tag, _, _, kind, _ = self.stack[-depth]
            if kind & _K_FOREIGN:
                continue
            if tag in _TABLE_CONTEXT or tag == "colgroup":
                return "table"
            if tag in ("caption", "td", "th"):
                return "cell"
            if tag == "template":
                return ""
        if limit < len(self.stack):
            self.lose_track()
        return ""

    def table_part(self, tag: str, attrs: dict[str, str]) -> tuple[_Sight, str]:
        """A caption, a column, a row group, a row, or a cell: whatever is open is closed back
        to where the part belongs, and the row group or row a writer left out is opened."""
        if self.top_is("colgroup"):
            if tag == "col":
                return _PLAIN, "none"
            self.pop(1)
        if tag in ("td", "th"):
            home = self.clear_to(_CELL_HOME)
        elif tag == "tr":
            home = self.clear_to(_ROW_HOME)
        else:
            home = self.clear_to(_TABLE_ENDS)
        if home in ("", "html", "template") or self.doubt:
            return _PLAIN, "none"
        if tag == "col":
            # A column written straight into a table gets the group a writer left out.
            tag, attrs = "colgroup", _NO_ATTRS
        elif tag in ("td", "th", "tr"):
            if home == "table":
                self.push("tbody", self.sight(), _NO_ATTRS, self.sight())
                home = "tbody"
            if home != "tr" and tag != "tr":
                self.push("tr", self.sight(), _NO_ATTRS, self.sight())
        parent = self.sight()
        sight = _sight_of(tag, attrs, parent, self.facts, foreign=False)
        self.push(tag, sight, attrs, parent)
        return sight, ""

    def text(self, raw: str, *, entities: bool = True) -> None:
        if self.doubt:
            self.out.run(raw, _PLAIN, entities=entities)
            return
        if self.foreign:
            self.out.run(raw, self.sight(), entities=entities)
            return
        decoded = html.unescape(raw) if entities and "&" in raw else raw
        if not decoded.strip(_HTML_BLANK):
            # Whitespace starts no body and stays inside a table. Inside a body it reopens
            # the formatting elements that are waiting, as any text does.
            if self.body and not (self.stack and self.stack[-1][0] in _TABLE_CONTEXT):
                if not self.top_is("colgroup"):
                    self.reopen()
            self.out.run(raw, self.sight(), entities=entities)
            return
        self.start_body()
        if self.top_is("colgroup"):
            # A column group holds columns only: text ends it.
            self.pop(1)
        self.reopen()
        self.out.run(raw, self.outer(), entities=entities)

    def start(self, tag: str, attrs: dict[str, str], slashed: bool) -> tuple[_Sight, str]:
        """Open an element. Returns its sight and how its body is read: ``""`` as markup,
        ``"skip"`` not at all, ``"written"`` as text to its end tag, ``"rest"`` as text to the
        end of the document, ``"select"`` as a list of options, and ``"none"`` when the tag is
        dropped."""
        if self.doubt:
            if tag in _NOT_DRAWN:
                return _PLAIN, "skip"
            if tag == "plaintext":
                return _PLAIN, "rest"
            return _PLAIN, "written" if tag in _AS_WRITTEN else "none"
        if tag in _NOT_FOLLOWED:
            self.lose_track()
            return _PLAIN, "none"
        if self.foreign:
            font_breaks = tag == "font" and not attrs.keys().isdisjoint(("color", "face", "size"))
            if tag in _FOREIGN_BREAKOUT or font_breaks:
                # An HTML element ends the svg or math it was written in.
                while self.foreign:
                    self.pop(1)
            else:
                # Every element here is an svg or math element, whatever its name: a style or
                # a title inside an svg holds markup, not text as written.
                sight = _sight_of(tag, attrs, self.sight(), self.facts, foreign=True)
                if not slashed:
                    self.push(tag, sight, attrs, sight, self.context[-1])
                return sight, ""
        opened = self.opened
        if tag in ("html", "body"):
            first = self.root_attrs.setdefault(tag, frozenset(attrs))
            if self.body if tag == "body" else self.rooted:
                if not first.issuperset(attrs) and not first.isdisjoint(("class", "hidden")):
                    # A browser adds a later tag's new attributes to the first. A style added
                    # to an element hidden by its attribute or its class may show it again,
                    # with text already read: nothing judged so far, or from here on, is known.
                    self.out.retract(0)
                    self.lose_track()
                return _PLAIN, "none"
            self.rooted = True
            if tag == "body":
                self.close(_HEAD, _NONE)
                self.saw_head = self.body = True
        elif tag == "frameset":
            # Dropped once a body has content. Before that it replaces the body, and nothing
            # written after it is drawn: not opening it claims nothing there.
            return _PLAIN, "none"
        elif tag == "head":
            if self.saw_head:
                return _PLAIN, "none"
            self.rooted = self.saw_head = True
        elif not self.body:
            self.rooted = True
            if tag in _HEAD_ONLY and (tag != "noscript" or opened.get("head") or not self.saw_head):
                # It goes in the head, which exists from here on whether or not one is written.
                self.saw_head = True
            else:
                self.start_body()
        table = self.table_mode()
        if tag in _TABLE_ONLY:
            if not table:
                return _PLAIN, "none"
            return self.table_part(tag, attrs)
        if table == "table":
            if tag == "table":
                # A table written where a row or a cell belongs ends the open table.
                self.close(_TABLE_ITSELF, _NONE)
            elif tag == "form":
                # A form here is put in the table and closed at once: it holds nothing.
                if not self.form and not opened.get("template"):
                    self.form = True
                return _PLAIN, "none"
        if tag != "template" and self.top_is("colgroup"):
            self.pop(1)
        if tag == "form" and self.form and not opened.get("template"):
            return _PLAIN, "none"
        if tag in _HEADINGS and self.stack and self.stack[-1][0] in _HEADINGS:
            self.pop(1)
        if tag in _ENDERS:
            if tag == "a":
                self.end_link()
            elif tag == "nobr":
                # An open nobr ends as its own end tag would end it, after those waiting
                # reopen.
                self.reopen()
                if self.find(_NOBR_ONLY, _SCOPE) > 0:
                    self.end_formatting(tag)
            elif tag == "button":
                self.close(_BUTTON_ONLY, _SCOPE)
            elif tag == "li":
                self.close(_LI_ONLY, _ITEM_BARRIERS)
            elif tag in _ITEM_ENDS:
                self.close(_ITEM_ENDS, _ITEM_BARRIERS)
            elif tag in _RUBY_PARTS:
                if self.find(_RUBY_ONLY, _SCOPE) > 0:
                    # Inside a ruby, a new part ends the parts a writer may leave open.
                    ends = _RUBY_ENDS_LESS if tag in ("rp", "rt") else _ENDS_ITSELF
                    while self.stack and self.stack[-1][0] in ends and not self.stack[-1][3]:
                        self.pop(1)
            elif self.top_is("option"):
                self.pop(1)
        if tag in _P_ENDERS:
            if tag != "table" or self.facts.quirks is False:
                self.close(_P_ONLY, _P_SCOPE)
            elif self.facts.quirks is None and self.find(_P_ONLY, _P_SCOPE) != 0:
                # In quirks mode a table stays inside an open p, and an older doctype decides
                # the mode: with a p open here, which tree a browser builds is not known.
                self.lose_track()
        if self.doubt:
            return _PLAIN, "none"
        if tag not in _NO_REOPEN:
            self.reopen()
            if tag in _FORMATTING and opened.get(tag, 0) >= 3 and self.listed(tag, attrs) >= 3:
                # A fourth copy of the same element drops the first from what a browser
                # reopens. Not followed.
                self.lose_track()
            if self.doubt:
                return _PLAIN, "none"
        parent = self.outer()
        root = tag in _FOREIGN_ROOTS
        sight = _sight_of(tag, attrs, parent, self.facts, foreign=root)
        if tag in _NOT_DRAWN:
            return sight, "skip"
        if tag in _AS_WRITTEN:
            return sight, "written"
        if tag == "plaintext":
            return sight, "rest"
        if tag == "select":
            return sight, "select"
        if tag in _VOID or (slashed and root):
            return sight, ""
        if tag == "form" and not opened.get("template"):
            self.form = True
        self.push(tag, sight, attrs, parent, tag if root else "")
        return sight, ""

    def end_link(self) -> None:
        """A link cannot hold another: the open one, or one waiting to be reopened, ends."""
        base = self.marks[-1] if self.marks else 0
        for index in range(len(self.pending) - 1, base - 1, -1):
            if self.pending[index][0] == "a":
                del self.pending[index]
                return
        depth = self.listed("a")
        if depth <= 0 or self.doubt:
            return
        if self.find(_A_ONLY, _SCOPE) > 0:
            self.end_formatting("a")
        else:
            # Open, but an svg's HTML or a table is in the way: it is taken out of the open
            # elements where it stands, and what was written inside it stays open.
            del self.stack[-depth]
            self.opened["a"] -= 1

    def end(self, tag: str) -> None:
        if self.doubt:
            return
        if self.stack and self.stack[-1][3] & _K_FOREIGN:
            # The current element is an svg or math element, one that holds HTML included: an
            # end tag there is read by the rules of svg and math, not by HTML's.
            if tag in ("p", "br"):
                # These two end tags end the svg or math they are written in.
                while self.foreign:
                    self.pop(1)
            else:
                # An svg or math element of that name ends; past the svg or math, the end tag
                # is read as HTML reads it.
                limit = min(len(self.stack), _SCAN)
                for depth in range(1, limit + 1):
                    name, _, _, kind, _ = self.stack[-depth]
                    if not kind & _K_FOREIGN:
                        break
                    if name == tag:
                        self.pop(depth)
                        return
                else:
                    if limit < len(self.stack):
                        self.lose_track()
                    return
        opened = self.opened
        if tag in ("body", "html"):
            self.start_body()
            return
        if tag == "head":
            if not self.body:
                self.close(_HEAD, _NONE)
            return
        if not self.body:
            # Any other end tag before the body is dropped.
            return
        if self.top_is("colgroup"):
            if tag == "col":
                return
            self.pop(1)
            if tag == "colgroup":
                return
        if tag in _FORMATTING:
            self.end_formatting(tag)
        elif tag in _HEADINGS:
            self.close(_HEADINGS, _SCOPE)
        elif tag == "form" and not opened.get("template"):
            # A form's end tag clears the form pointer, takes the form out of the open
            # elements, and leaves everything written inside it open, after ending an open
            # paragraph or list item. With no form in scope it only clears the pointer.
            self.form = False
            if not opened.get(tag) or self.find(_FORM_ONLY, _SCOPE) == 0:
                return
            while self.stack and self.stack[-1][0] in _ENDS_ITSELF and not self.stack[-1][3]:
                self.pop(1)
            depth = self.find(_FORM_ONLY, _SCOPE)
            if depth > 0:
                del self.stack[-depth]
                opened[tag] -= 1
            elif depth < 0:
                self.lose_track()
        elif not opened.get(tag):
            return
        elif tag == "template":
            self.close(_TEMPLATE_ONLY, _NONE)
        elif tag == "p":
            self.close(_P_ONLY, _P_SCOPE)
        elif tag == "li":
            self.close(_LI_ONLY, _LIST_SCOPE)
        elif tag == "table" or tag in _TABLE_ONLY:
            self.close(tag, _TABLE_ENDS)
        elif tag in _BLOCK_ENDS:
            self.close(tag, _SCOPE)
        else:
            # Any other element: its end tag does not reach past a block element.
            self.close(tag, _SPECIAL)

    def end_formatting(self, tag: str) -> None:
        """The end tag of a formatting element: what browsers call the adoption agency."""
        # The most recent one counts, and one waiting to be reopened is more recent than any
        # that is open: its end tag withdraws it and closes nothing.
        base = self.marks[-1] if self.marks else 0
        for index in range(len(self.pending) - 1, base - 1, -1):
            if self.pending[index][0] == tag:
                del self.pending[index]
                return
        for _ in range(8):
            if not self.opened.get(tag):
                return
            depth = self.find(tag, _SCOPE)
            if depth <= 0:
                if depth < 0:
                    self.lose_track()
                return
            start = len(self.stack) - depth
            block = -1
            for index in range(start + 1, len(self.stack)):
                name, _, _, kind, _ = self.stack[index]
                if name in _SPECIAL and (not kind & _K_FOREIGN or kind & _K_CONTEXT):
                    block = index
                    break
            if block < 0:
                self.pop(depth)
                return
            moved = self.stack[start:]
            if any(frame[3] & ~_K_FORMAT for frame in moved):
                # Ending across a table, a cell, or an svg is not modeled.
                self.lose_track()
                return
            between = [frame for frame in self.stack[start + 1 : block] if frame[3] & _K_FORMAT]
            if len(between) > 3:
                # A browser keeps the nearest three; which ones is not followed.
                self.lose_track()
                return
            # A block element is open inside it. The block moves out from under the formatting
            # element, inside copies of the formatting elements that were between them; the
            # formatting element is copied inside the block, around what the block already
            # holds; and any other element that was between them is left behind. The text read
            # in the block since it opened was judged under the old order and is taken back.
            self.out.retract(self.stack[block][4])
            rebuilt = [*between, self.stack[block], self.stack[start], *self.stack[block + 1 :]]
            for frame in moved:
                self.opened[frame[0]] -= 1
            del self.stack[start:]
            for name, _, attrs, _, _ in rebuilt:
                parent = self.outer()
                self.push(
                    name, _sight_of(name, attrs, parent, self.facts, foreign=False), attrs, parent
                )


def _select_body(text: str, position: int) -> tuple[int, int] | None:
    """Where a select's body ends and where reading goes on, or None when the body holds
    anything but options, option groups, and rules."""
    size = len(text)
    while True:
        start = text.find("<", position)
        if start < 0:
            return size, size
        tag_match = _TAG.match(text, start)
        if tag_match is None:
            if text.startswith(("<!", "<?", "</"), start):
                return None
            position = start + 1
            continue
        rest = _TAG_REST.match(text, tag_match.end())
        if rest is None:
            return None
        name = tag_match.group(2).translate(_ASCII_LOWER)
        if name == "select":
            return (start, rest.end()) if tag_match.group(1) else None
        if name not in _SELECT_PARTS:
            return None
        position = rest.end()


@dataclass(frozen=True)
class HtmlHidden:
    """HTML text a browser does not show, and the text it does.

    ``pieces`` are distinct, in document order. ``shown`` is the shown text with whitespace
    collapsed and case folded, for ``html_also_shown``; it is built only when there are pieces.
    """

    pieces: list[str]
    shown: str


def html_also_shown(hidden: HtmlHidden, piece: str) -> bool:
    """True when a hidden piece's whole text is also in the text the page shows.

    A share widget copies the article title into ``data-title`` and a mail preheader repeats the
    first line: the reader is shown the same words, so the copy hides nothing from them.
    """
    key = _HTML_SPACE.sub(" ", piece).strip().casefold()
    return bool(key) and key in hidden.shown


def html_hidden_texts(name: str, text: str, budget: Budget) -> HtmlHidden:
    """The text of an HTML document that a browser does not show when the document opens.

    Read from each element's own markup. Hidden, whatever else the document holds:
    ``display:none``; the ``hidden`` attribute on an HTML element with no inline ``display``;
    the content of a ``template``; ``visibility:hidden`` until a descendant sets it back; and
    a font size of zero until a descendant sets a size. Hidden where no style in the document
    draws text by a clip, a shadow, or a stroke: transparent text, and text within 12 steps of
    the background the same element declares, until an element with an attribute of its own.
    Hidden only when nothing in the document could show it: an opacity of zero in a document
    with no script and no animating style (a fade-in is written the same way). Hidden on an
    assumption the lexical rule also makes: a screen-reader-only class, in a document that
    has a stylesheet.

    Not claimed, because the markup does not settle it: a box of no size that clips its
    content, text moved off the page by an offset, a font of a pixel, and near-white text with
    no background of its own (a dark theme is written the same way). ``agent_hidden_html``
    still reads the offset and the small font as a cue beside a phrase.

    Each stretch of hidden element text is one piece: it ends at the next shown text that is
    not whitespace, and a block boundary inside it is a newline, so hidden halves on both
    sides of a shown word are never joined. Each comment is a piece of its own, and so is each
    ``data-*`` value of twelve characters or more that holds a space. Script and style bodies
    are not text. Pieces are distinct; more than ``MAX_TEXT_PIECES`` of them is incomplete.

    A document a browser reads as XML (an ``.svg`` or ``.xhtml`` name, or an XML start under
    any name but ``.html``) gives only its comments and ``data-*`` values: the element rules
    here are the HTML parser's.

    One linear pass. Input that ends inside a tag stops the reader, since a browser draws
    nothing after it. This is lexical visibility, not layout: a class or id whose stylesheet
    this reader cannot see is unknown, never hidden.
    """
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if suffix not in _HTML_SUFFIXES and not _opens_as_html(text[:8192]):
        return HtmlHidden([], "")
    if _ANY_HIDING.search(text) is None:
        return HtmlHidden([], "")
    out = _Pieces()
    tree = _Tree(_page_facts(text), out)
    # A browser picks its parser by the file's name; one with no HTML name is judged by how
    # it starts.
    head = text[:8192]
    as_xml = suffix in _XML_SUFFIXES or (
        suffix not in ("htm", "html")
        and _XML_START.match(head, _prologue_end(head, xml_too=False)) is not None
    )
    if as_xml:
        tree.lose_track()
    position = 0
    size = len(text)
    count = 0
    while position < size:
        count += 1
        if count % 4096 == 0:
            budget.check()
            if count > _MAX_TAGS and not tree.doubt:
                tree.lose_track()
        start = text.find("<", position)
        if start < 0:
            tree.text(text[position:])
            break
        if start > position:
            tree.text(text[position:start])
        if text.startswith("<!--", start):
            # An empty comment closes at once; any other runs to --> or --!>, or to the end.
            if text.startswith(">", start + 4):
                position = start + 5
                continue
            if text.startswith("->", start + 4):
                position = start + 6
                continue
            close = text.find("-->", start + 4)
            stop = size if close < 0 else close
            bang = text.find("--!>", start + 4, stop + 3)
            if bang >= 0:
                stop, position = bang, bang + 4
            else:
                position = size if close < 0 else close + 3
            body = text[start + 4 : stop]
            out.keep(_HTML_SPACE.sub(" ", html.unescape(body) if "&" in body else body))
            continue
        if (tree.foreign or as_xml) and text.startswith("<![CDATA[", start):
            close = text.find("]]>", start + 9)
            tree.text(text[start + 9 : size if close < 0 else close], entities=False)
            position = size if close < 0 else close + 3
            continue
        tag_match = _TAG.match(text, start)
        if tag_match is None:
            if text.startswith(("<!", "<?", "</"), start):
                # A declaration, a processing instruction, or a bogus comment: to the next >.
                close = text.find(">", start + 2)
                position = size if close < 0 else close + 1
            else:
                tree.text("<")
                position = start + 1
            continue
        rest = _TAG_REST.match(text, tag_match.end())
        if rest is None:
            # The input ends inside this tag. A browser draws nothing from here on, and no
            # later text is an element or shown text, so the reader stops.
            break
        position = rest.end()
        tag = tag_match.group(2).translate(_ASCII_LOWER)
        ending = bool(tag_match.group(1))
        if ending and tag != "br":
            tree.end(tag)
            if tag in _HTML_BLOCKS:
                out.boundary()
            continue
        # An end tag for br is read as a br.
        raw_attrs = "" if ending else text[tag_match.end() : position - 1]
        attrs = _NO_ATTRS
        if raw_attrs.strip("\t\n\f\r /"):
            attrs = {}
            for found in _ATTRIBUTE.finditer(raw_attrs):
                value = found.group(2) or found.group(3) or found.group(4) or ""
                attrs.setdefault(found.group(1).translate(_ASCII_LOWER), value)
            for key, value in attrs.items():
                if key.startswith("data-") and len(value) >= _DATA_MIN:
                    decoded = html.unescape(value) if "&" in value else value
                    out.keep(_HTML_SPACE.sub(" ", decoded), sentence=True)
        # In SVG a trailing slash closes the element; in HTML it is ignored. A slash that ends
        # an unquoted value belongs to the value.
        slashed = raw_attrs.endswith("/") and raw_attrs[-2:-1] in ("", " ", "\t", "\n", '"', "'")
        sight, body_kind = tree.start(tag, attrs, slashed)
        if tag in _HTML_BLOCKS or tag == "br":
            out.boundary()
        if body_kind == "rest":
            out.run(text[position:], sight, entities=False)
            break
        if body_kind == "select":
            options = _select_body(text, position)
            if options is None:
                # Something other than options is in it: where it ends is not followed.
                tree.lose_track()
                continue
            out.run(_SELECT_TAG.sub(" ", text[position : options[0]]), sight)
            out.boundary()
            position = options[1]
        elif body_kind in ("skip", "written"):
            ended = _RAW_END[tag].search(text, position)
            if body_kind == "written":
                body_end = size if ended is None else ended.start()
                # The document's title is shown on its tab, whatever hides the head it is in.
                seen = _PLAIN if tag == "title" else sight
                out.run(text[position:body_end], seen, entities=tag in ("textarea", "title"))
                out.boundary()
            close = -1 if ended is None else text.find(">", ended.end())
            if close < 0:
                # The body runs to the end of the input.
                break
            position = close + 1
    out.flush()
    if not out.pieces:
        return HtmlHidden([], "")
    budget.check()
    return HtmlHidden(out.pieces, _HTML_SPACE.sub(" ", " ".join(out.shown)).strip().casefold())
