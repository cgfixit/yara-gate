"""CI regression tripwire: 4 MiB inert inputs, 10 s per scan, 20 s process watchdog.

Run from the repository root with the locked environment. This is not a benchmark:
fixtures are synthetic, rules are bundled-only, and each scan runs once. Targets
are never executed, fetched, or extracted to disk.
"""

import argparse
import hashlib
import importlib.metadata
import io
import json
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path

from yara_gate.scanner import scan_bytes

ROOT = Path(__file__).resolve().parents[2]
SIZE = 4 * 1024 * 1024
SCAN_SECONDS = 10
PROCESS_SECONDS = 20


def cases() -> Iterator[tuple[str, bytes, str | None]]:
    """Fixed repeated tokens target the readers' failed-match and piece-count paths."""
    patterns = (
        ("html-comments.html", b"<html><!--", b"<!--", None),
        ("html-quotes.html", b'<html><p title="', b"'a=", None),
        ("html-tags.html", b"<html><p ", b"x=", None),
        # The hidden-text reader: a style to parse on every element, and inline elements
        # that end across a block, each of which rebuilds the open elements.
        (
            "html-styled-elements.html",
            b"<!doctype html><html><body>",
            b'<i style="color:rgb(255, 255, 255);background:hsl(0,0%,100%)">x</i>',
            None,
        ),
        (
            "html-misnested-inline.html",
            b'<!doctype html><html><body><div style="visibility:hidden">',
            b"<b><div></b></div>",
            None,
        ),
        (
            "zip-end-records.zip",
            b"",
            b"PK\x05\x06" + bytes(18),
            "zip end records exceed 64",
        ),
        ("json-escapes.json", b'{"cells":["', b"\\u005b", None),
        ("notebook-nesting.ipynb", b'{"nbformat":4,"cells":', b"[", None),
        ("comment-lines.py", b"", b"#\n", None),
        ("comment-block.py", b"", b"# ab\n", None),
        ("comment-pieces.py", b"", b"# a\n# b\n\n", "text pieces exceed 100000"),
        ("markdown-brackets.md", b"# Heading\n", b"[", None),
        ("markdown-lines.md", b"", b"**ab**\n", None),
        ("rtf-controls.rtf", b"{\\rtf1 ", b"{\\b ", "rtf group depth exceeds 128"),
        (
            "pdf-annotation-dictionary.pdf",
            b"%PDF-1.7\n<< /Type /Annot /Rect [",
            b"0 ",
            "pdf annotation dictionary exceeds 100000 tokens",
        ),
        ("svg-spans.svg", b"<svg><text>", b"<tspan>a</tspan>", None),
        ("small-capitals.txt", b"", "\u026a\u0262\u0274\u1d0f\u0280\u1d07 ".encode(), None),
    )
    for name, prefix, token, reason in patterns:
        count, rest = divmod(SIZE - len(prefix), len(token))
        yield name, prefix + token * count + b" " * rest, reason
    prefix, suffix = b"%PDF-1.7\n<< /Type /Annot /Contents <", b"> >>\n%%EOF\n"
    count, rest = divmod(SIZE - len(prefix) - len(suffix), 2)
    yield (
        "pdf-annotation-string.pdf",
        prefix + b"41" * count + b" " * rest + suffix,
        "pdf annotation string exceeds 1MiB",
    )
    prefix = b'{"nbformat":4,"cells":[{"cell_type":"markdown","source":['
    suffix = b'"last line"]}]}'
    token = b'"ab\\n",'
    count, rest = divmod(SIZE - len(prefix) - len(suffix), len(token))
    yield "notebook-lines.ipynb", prefix + token * count + b" " * rest + suffix, None
    yield (
        "ooxml-comment.zip",
        _stored(
            "xl/comments1.xml",
            b"<comments><comment><text>",
            b"<r><t>a</t></r>",
            b"</text></comment></comments>",
        ),
        None,
    )
    # Hidden and shown Word runs in turn: the most hidden-text pieces a part can hold.
    yield (
        "ooxml-hidden-runs.zip",
        _stored(
            "word/document.xml",
            b"<w:document><w:body><w:p>",
            b"<w:r><w:rPr><w:vanish/></w:rPr><w:t>a</w:t></w:r><w:r><w:t>b</w:t></w:r>",
            b"</w:p></w:body></w:document>",
        ),
        None,
    )
    # What plain_xml rewrites before the Office readers run. A comment inside one run, over
    # and over: every removal leaves a join mark and the run is rebuilt once.
    yield (
        "ooxml-xml-comments.zip",
        _stored(
            "word/document.xml",
            b"<w:document><w:body><w:p><w:r><w:t>",
            b"a<!--b-->",
            b"</w:t></w:r></w:p></w:body></w:document>",
        ),
        None,
    )
    # A tag whose quoted value never closes, at every tag: the quote-aware tag pattern and
    # the hint that looks for ">" inside a value each fail once per "<".
    yield (
        "ooxml-xml-open-quotes.zip",
        _stored(
            "word/document.xml",
            b"<!-- --><w:document><w:body>",
            b'<w:t a="b ',
            b"</w:body></w:document>",
        ),
        None,
    )
    # An internal entity referenced until the growth cap: the scan stops instead of expanding.
    yield (
        "ooxml-xml-entities.zip",
        _stored(
            "word/document.xml",
            b'<!DOCTYPE d [<!ENTITY w "previous">]><w:document><w:body><w:p><w:r><w:t>',
            b"&w;",
            b"</w:t></w:r></w:p></w:body></w:document>",
        ),
        "xml entity expansion exceeds 1MB",
    )
    # The Office readers by content. A part under no usual name whose root tag never closes:
    # the root is looked for in the first 64 KiB and then once in the whole part.
    word = b'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    drawing = b'xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"'
    slide = b'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main"'
    yield (
        "ooxml-root-unclosed.zip",
        _stored("word/body2.xml", b"<w:document " + word + b" ", b'a="b" ', b""),
        None,
    )
    # A file that is one long prolog: every comment is stepped over once, and no root follows.
    yield "xml-prolog-comments.xml", _filled(b'<?xml version="1.0"?>', b"<!-- a -->"), None
    # Every element under a prefix a writer chose, bound on the root: each tag is moved onto
    # the usual prefix.
    yield (
        "ooxml-other-prefix.zip",
        _stored(
            "word/document.xml",
            b"<x:document " + word.replace(b"xmlns:w", b"xmlns:x") + b"><x:body><x:p>",
            b"<x:r><x:t>a</x:t></x:r>",
            b"</x:p></x:body></x:document>",
        ),
        None,
    )
    # A namespace declared on every run: each one opens and closes a scope.
    yield (
        "ooxml-xmlns-every-run.zip",
        _stored(
            "word/document.xml",
            b"<w:document " + word + b"><w:body><w:p>",
            b"<x:r " + word.replace(b"xmlns:w", b"xmlns:x") + b"><x:t>a</x:t></x:r>",
            b"</w:p></w:body></w:document>",
        ),
        None,
    )
    # The same declaration on elements that never close: the scope cap ends the scan.
    yield (
        "ooxml-namespace-scopes.zip",
        _stored(
            "word/document.xml",
            b"<w:document " + word + b"><w:body>",
            b'<w:p xmlns:w="urn:example:other">',
            b"</w:body></w:document>",
        ),
        "ooxml namespace scopes exceed 256",
    )
    # Nothing but DrawingML line breaks, in a hidden shape: each is a new line in the joined
    # text and in the hidden piece, and both keep their earlier reading without it.
    yield (
        "ooxml-drawing-breaks.zip",
        _stored(
            "ppt/slides/slide1.xml",
            b"<p:sld " + drawing + b" " + slide + b'><p:sp><p:cNvPr hidden="1"/><p:txBody>'
            b"<a:p><a:r><a:t>a</a:t></a:r>",
            b"<a:br/>",
            b"<a:r><a:t>b</a:t></a:r></a:p></p:txBody></p:sp></p:sld>",
        ),
        None,
    )
    # End tags padded with white space that never reach their ">".
    yield (
        "ooxml-padded-end-tags.zip",
        _stored(
            "word/document.xml",
            b"<w:document " + word + b"><w:body><w:p>",
            b"<w:t>a</w:t \n",
            b"</w:p></w:body></w:document>",
        ),
        None,
    )
    # One text tag with megabytes of attribute, then a second run.
    yield (
        "ooxml-long-attribute.zip",
        _stored(
            "word/document.xml",
            b"<w:document " + word + b'><w:body><w:p><w:r><w:t a="',
            b"b ",
            b'">c</w:t></w:r><w:r><w:t>d</w:t></w:r></w:p></w:body></w:document>',
        ),
        None,
    )
    # A first tag that holds "xmlns" and then one run of name characters, in a file that is no
    # Office part: every scanned unit's root tag is read for its namespace, one name at a time.
    yield "xml-root-name-run.xml", _filled(b"<a xmlns ", b"b")[:-1] + b">", None
    # The same run in a tag inside a body whose prefixes take the exact pass.
    yield (
        "ooxml-tag-name-run.zip",
        _stored(
            "word/document.xml",
            b"<w:document "
            + word
            + b"><w:body><x:p "
            + word.replace(b"xmlns:w", b"xmlns:x")
            + b" xmlns ",
            b"b",
            b"><x:r><x:t>a</x:t></x:r><x:r><x:t>b</x:t></x:r></x:p></w:body></w:document>",
        ),
        None,
    )
    # A DOCTYPE that gives one element as many namespace declarations by default as a part
    # may have, and that element opened and closed to the end: each pair binds and restores
    # them all.
    defaults = b"".join(b'xmlns:p%d CDATA "u" ' % number for number in range(8))
    yield (
        "ooxml-doctype-namespaces.zip",
        _stored(
            "word/document.xml",
            b"<!DOCTYPE w:document [<!ATTLIST e "
            + defaults
            + b">]><w:document "
            + word
            + b"><w:body>",
            b"<e></e>",
            b"</w:body></w:document>",
        ),
        None,
    )
    # A worksheet as the Open XML SDK writes it, every SpreadsheetML element under x:. The
    # prefix is moved once for the part and the hidden-text reader reads it once.
    sheet = b'xmlns:x="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    yield (
        "ooxml-sdk-prefix.zip",
        _stored(
            "xl/worksheets/sheet1.xml",
            b"<x:worksheet " + sheet + b'><x:sheetViews><x:sheetView showGridLines="1"/>'
            b"</x:sheetViews><x:sheetData>",
            b'<x:row r="1"><x:c r="A1" s="1" t="s"><x:v>1</x:v></x:c>'
            b'<x:c r="B1" s="2"><x:v>2.5</x:v></x:c></x:row>',
            b"</x:sheetData></x:worksheet>",
        ),
        None,
    )
    # Hidden runs in a part that is a document by its name and a slide by its root, half of
    # them under a second prefix: two vocabularies, each read resolved and as written.
    yield (
        "ooxml-two-vocabularies.zip",
        _stored(
            "word/document.xml",
            b"<p:sld "
            + drawing
            + b" "
            + slide
            + b" "
            + word
            + b" "
            + word.replace(b"xmlns:w", b"xmlns:x")
            + b">",
            b"<w:r><w:rPr><w:vanish/></w:rPr><w:t>a</w:t></w:r><x:r><x:t>b</x:t></x:r>",
            b"</p:sld>",
        ),
        None,
    )
    odf = (
        b'<office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office'
        b':1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0"><office:body>'
        b"<office:text>"
    )
    odf_end = b"</office:text></office:body></office:document-content>"
    # The most OpenDocument paragraphs a part can hold, each joined across a span.
    yield (
        "odf-spans.zip",
        _stored("content.xml", odf, b"<text:p>a<text:span>b</text:span></text:p>", odf_end),
        None,
    )
    # One paragraph of elements readers treat differently: all three readings grow together.
    yield (
        "odf-unknown-elements.zip",
        _stored("content.xml", odf + b"<text:p>", b"a<text:q>b</text:q>", b"</text:p>" + odf_end),
        None,
    )
    # Paragraphs that never close: the nesting cap ends the scan.
    yield (
        "odf-nesting.zip",
        _stored("content.xml", odf, b"<text:p>a", odf_end),
        "odf paragraph nesting exceeds 64",
    )
    # One invisible stretch: every string goes to both the shown and the hidden grouping.
    # /Length lands on endstream so the annotation reader skips the body and the
    # page-text path is what the tripwire measures.
    yield (
        "pdf-hidden-stretch.pdf",
        _content_pdf(b"BT /F1 12 Tf 3 Tr ", b"(a) Tj "),
        None,
    )
    # White text that moves on every string, inside the union of the most painted areas a
    # stream keeps but on none of them, so no answer is reused.
    areas = b"".join(b"%d 0 1 1 re f " % (index * 100) for index in range(31))
    white = b"0 g " + areas + b"0 9000 1 1 re f BT /F1 12 Tf 50 4000 Td 1 1 1 rg "
    yield (
        "pdf-white-areas.pdf",
        _content_pdf(white, b"0 1 Td (a) Tj "),
        None,
    )
    # Hidden and shown strings in turn reach the text block cap. This /Length does not
    # land; the block cap is raised by the page-text reader before annotations run.
    stream = b"%PDF-1.4\n1 0 obj<</Length 0>>stream\n"
    yield (
        "pdf-hidden-blocks.pdf",
        _filled(stream + b"BT /F1 12 Tf ", b"3 Tr (a) Tj 0 Tr (b) Tj "),
        "pdf text blocks exceed 20000",
    )
    # Two content streams, so the /Contents continuation index runs over every match: once a
    # rescanned 4 KiB window per match (a 30 s timeout here), and once a page object apiece.
    # Each /Length is the body `BT ET \\n` and lands on that stream's own endstream.
    streams = (
        b"%PDF-1.4\n7 0 obj<</Length 7>>stream\nBT ET \nendstream endobj\n"
        b"8 0 obj<</Length 7>>stream\nBT ET \nendstream endobj\n"
    )
    yield (
        "pdf-contents-arrays.pdf",
        _filled(streams, b"/Contents["),
        None,
    )
    page = b"1 0 obj<</Type/Page/Contents[7 0 R 8 0 R]>>endobj\n"
    yield (
        "pdf-page-objects.pdf",
        _filled(streams, page),
        None,
    )
    # Inputs for the per-page font map. /F1 means two fonts (objects 3 and 4), so the map is
    # built. First, pages that all draw one stream, each naming ten fonts no other page names;
    # every second object is a page, which keeps the pages just under the 2 MiB the map
    # parses, and the others are the same bytes with the key misspelled. Second, one page and
    # an array of about 260,000 references to its content stream, which the map counts.
    cmap = b"begincmap 1 beginbfchar <61> <0061> endbfchar endcmap"
    text = (
        b"%PDF-1.7\n1 0 obj<</Length 22>>stream\nBT /F1 12 Tf (a) Tj ET\nendstream endobj\n"
        + b"2 0 obj<</Length %d>>stream\n" % len(cmap)
        + cmap
        + b"\nendstream endobj\n"
        + b"3 0 obj<</Type/Font/Subtype/Type1/ToUnicode 2 0 R>>endobj\n"
        + b"4 0 obj<</Type/Font/Subtype/Type1>>endobj\n"
        + b"5 0 obj<</Font<</F1 3 0 R>>>>endobj\n"
        + b"6 0 obj<</Font<</F1 4 0 R>>>>endobj\n"
    )

    def named(n: int) -> bytes:
        fonts = b"".join(b"/F%dx%d %d 0 R" % (n, index, n) for index in range(10))
        key = b"/Contents" if n % 2 else b"/Contentz  "
        return (
            b"%d 0 obj<</Type/Page" % n
            + key
            + b" 1 0 R/Resources<</Font<</F1 4 0 R"
            + fonts
            + b">>>>>>endobj\n"
        )

    yield "pdf-page-fonts.pdf", _numbered(text, named), None
    page = b"7 0 obj<</Type/Page/Contents 1 0 R/Resources<</Font<</F1 4 0 R>>>>>>endobj\n"
    opening, closing = text + page + b"8 0 obj[", b"]endobj\n%%EOF\n"
    # Padded so the annotation reader stays under its own token limit.
    reference = b"1 0 R".ljust(16)
    count, rest = divmod(SIZE - len(opening) - len(closing), len(reference))
    yield (
        "pdf-page-references.pdf",
        opening + reference * count + b" " * rest + closing,
        None,
    )
    # Ambiguous SVG scope above the proof budget must keep the strict result without
    # repeatedly counting tag offsets for each of the active-content matches.
    scope = b"<html>" + b"</svg><svg/>" * 1020 + b"<script " * 1024 + b"onload=" * 1024
    yield "svg-scope-cap.html", _filled(scope, b" "), None
    # 200 Type0 fonts, each with its own FlateDecode ToUnicode map writing 65,536 entries:
    # 13 s on 43aba2e, which had no per-file CMap budget.
    identity = b"1 beginbfrange\n<0000> <FFFF> <0000>\nendbfrange\n"
    yield (
        "pdf-cmap-fonts.pdf",
        _cmap_pdf(200, zlib.compress(identity), b"/Filter/FlateDecode"),
        "pdf cmap entries exceed 524288",
    )
    # One map of unclosed section markers: a lazy begin...end regex rescanned to the end from
    # each one, past the 20 s watchdog. Unfiltered, so the map is exactly what the file holds.
    yield (
        "pdf-cmap-sections.pdf",
        _cmap_pdf(1, b"beginbfchar ", b""),
        None,
    )
    yield (
        "pdf-cmap-tokens.pdf",
        _cmap_pdf(1, b"[", b"", b"beginbfrange ", b" endbfrange"),
        "pdf cmap tokens exceed 1572864",
    )
    # One resource name that means 64 Type0 fonts, each with its own ToUnicode map, as a
    # merged file of 64 sources would: every string is decoded in four of them, and the 60
    # past that cap make the text unmapped rather than unread without notice.
    fonts = b""
    for index in range(64):
        resources, font, cmap = (100 + 3 * index + offset for offset in range(3))
        body = (
            b"begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange "
            b"1 beginbfrange <0000> <00FF> <%04X> endbfrange endcmap" % (0x41 + index)
        )
        fonts += b"%d 0 obj<</Font<</F1 %d 0 R>>>>endobj\n" % (resources, font)
        fonts += b"%d 0 obj<</Type/Font/Subtype/Type0/Encoding/Identity-H/ToUnicode %d 0 R>>" % (
            font,
            cmap,
        )
        fonts += b"endobj\n%d 0 obj<</Length %d>>stream\n" % (cmap, len(body))
        fonts += body + b"\nendstream endobj\n"
    yield (
        "pdf-font-readings.pdf",
        _content_pdf(b"BT /F1 12 Tf ", b"<0001> Tj ", fonts),
        None,
    )
    # The same name with a font that has no map in place of the last of the 64: the reading
    # with no map is decoded beside the four the cap allows, so every string is decoded
    # five times.
    plain = b"289 0 obj<</Font<</F1 290 0 R>>>>endobj\n"
    plain += b"290 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n"
    yield (
        "pdf-font-readings-winansi.pdf",
        _content_pdf(b"BT /F1 12 Tf ", b"<0001> Tj ", fonts[: fonts.rindex(b"289 0 obj")] + plain),
        None,
    )
    # One font object defined until the file is full, over a ToUnicode map defined 1,900
    # times: 64 definitions of the font are read, each map definition is parsed once, and the
    # definitions past the cap make the text unmapped (2026-11-10-pdf-font-definitions.md).
    body = b"begincmap 1 beginbfchar <0048> <0048> endbfchar endcmap"
    page = (
        b"%PDF-1.7\n1 0 obj<</Type/Page/MediaBox[0 0 612 792]/Resources<</Font<</F1 6 0 R>>>>"
        b"/Contents 4 0 R>>endobj\n4 0 obj<</Length 39>>stream\n"
        b"BT /F1 12 Tf 72 700 Td <00480069> Tj ET\nendstream endobj\n"
    )
    maps = b"7 0 obj<</Length %d>>stream\n%s\nendstream endobj\n" % (len(body), body)
    font = b"6 0 obj<</Type/Font/Subtype/Type0/Encoding/Identity-H/ToUnicode 7 0 R>>endobj\n"
    yield "pdf-font-definitions.pdf", _filled(page + maps * 1900, font), None
    # Inputs for the reading of a font's own dictionary. Each font is named by a resource
    # dictionary of its own, so every one is read, and the page shows text in the first.
    shown = (
        b"%PDF-1.7\n1 0 obj<</Type/Page/MediaBox[0 0 612 792]/Resources 1000007 0 R"
        b"/Contents 4 0 R>>endobj\n4 0 obj<</Length 34>>stream\n"
        b"BT /F7 12 Tf 72 700 Td (Hi) Tj ET\nendstream endobj\n"
    )

    def fonts(entries: Callable[[int], bytes]) -> bytes:
        def named(n: int) -> bytes:
            return (
                b"%d 0 obj<</Font<</F%d %d 0 R>>>>endobj\n" % (1000000 + n, n, n)
                + b"%d 0 obj<</Type/Font" % n
                + entries(n)
                + b">>endobj\n"
            )

        return _numbered(shown, named)

    # First, fonts that each write /ToUnicode fifty times: more ways than are kept, so the
    # text is unmapped. Second, fonts that fill the 4 KB after their header with widths, so
    # the allowance for reading dictionaries token by token is spent; the first has no map
    # and stands before one that has, so the file's layout is read too. Third, the same
    # fonts with a form feed, which only the slower lenient lexer reads, until its own
    # allowance is spent.
    keys = b"".join(b"/ToUnicode %d 0 R" % (5000 + index) for index in range(50))
    widths = b"/W[" + b"10 " * 1320 + b"]"
    yield "pdf-font-keys.pdf", fonts(lambda n: b"/Subtype/Type1" + keys), None
    yield (
        "pdf-font-windows.pdf",
        fonts(lambda n: b"/Subtype/Type1" + (b"" if n == 7 else b"/ToUnicode 5 0 R" + widths)),
        None,
    )
    yield "pdf-font-lenient.pdf", fonts(lambda n: b"\x0c/Subtype/Type1" + widths + keys), None

    # Fonts defined 64 times each. Every definition has the same first key and four more
    # of its own, over 255 maps of 2,040 entries that differ in their last entry only, so
    # comparing two of them walks both. A way that definitions share is read once and a
    # font's further ways are bounded: collected and compared pair by pair, twelve such
    # fonts spent the 30 s scan deadline.
    def ranged(last: int) -> bytes:
        body = (
            b"begincmap 1 begincodespacerange <0000> <FFFF> endcodespacerange "
            b"1 beginbfrange <0000> <07F6> <0041> endbfrange "
            b"1 beginbfchar <FFFE> <%04X> endbfchar endcmap" % last
        )
        return b"<</Length %d>>stream\n%s\nendstream endobj\n" % (len(body), body)

    mapped = shown.replace(b"/Length 34", b"/Length 40").replace(b"(Hi)", b"<00010002>")
    mapped += b"500000 0 obj" + ranged(0x41)
    mapped += b"".join(b"%d 0 obj" % (500001 + m) + ranged(0x1000 + m) for m in range(255))

    def redefined(n: int) -> bytes:
        return b"%d 0 obj<</Font<</F%d %d 0 R>>>>endobj\n" % (1000000 + n, n, n) + b"".join(
            b"%d 0 obj<</Type/Font/Subtype/Type1/ToUnicode 500000 0 R" % n
            + b"".join(b"/ToUnicode %d 0 R" % (500001 + (4 * d + k) % 255) for k in range(4))
            + b">>endobj\n"
            for d in range(64)
        )

    yield "pdf-font-shared-ways.pdf", _numbered(mapped, redefined), None
    # Font dictionaries that write /Subtype and /Encoding 24,000 times each, under the
    # annotation reader's limit of tokens in one object. The repeats of the two keys were
    # combined pair by pair in one expression, which no deadline check interrupts: 20 s for
    # one such font.
    repeats = b"/Subtype /A\n" * 24_000 + b"/Encoding /B\n" * 24_000
    yield "pdf-font-repeated-keys.pdf", fonts(lambda n: b"/BaseFont/Helvetica" + repeats), None
    # One style attribute of 4 MiB whose every declaration opens a parenthesis: the style is
    # split once, without rescanning from each opener.
    prefix, suffix = b'<!doctype html><html><body><p style="', b'">x</p></body></html>'
    count, rest = divmod(SIZE - len(prefix) - len(suffix), 4)
    yield "html-style-parens.html", prefix + b"x:(;" * count + b" " * rest + suffix, None
    # One tool description that starts a phrase and then runs 4 MiB of spaces: each space in
    # the description pattern is a run of whitespace, read once.
    prefix, suffix = b'{"tools":[{"name":"a","description":"x do not tell', b' y"}]}'
    yield (
        "mcp-description-run.json",
        prefix + b" " * (SIZE - len(prefix) - len(suffix)) + suffix,
        None,
    )
    # Mail. A header block is read for 64 KiB and has to end there before the mail library
    # parses it, so a block that never ends costs two bounded passes whatever the file's size:
    # 55,000 header lines, then one Content-Type folded over 600,000 lines.
    mail = b"From: a@example.com\r\nSubject: Report\r\nMIME-Version: 1.0\r\n"
    yield (
        "mail-header-block.eml",
        _filled(mail + b"Content-Type: text/html\r\n", b"X-Trace: " + b"a" * 66 + b"\r\n"),
        None,
    )
    yield (
        "mail-folded-lines.eml",
        _filled(mail + b"Content-Type: text/html;\r\n", b" a=b;\r\n"),
        None,
    )
    # The most header a newly opened message can have: one Content-Type folded to the end of
    # the window, read once to open the message and once to read its part, then an HTML body.
    opening = mail + b"Content-Type: text/html;\r\n"
    folds = b" a=b;\r\n" * ((64 * 1024 - len(opening) - 16) // 7)
    yield (
        "mail-folded-window.eml",
        _filled(opening + folds + b" x=y\r\n\r\n<html><body><p>", b"<b>a</b>"),
        None,
    )
    # A part whose transfer-encoding value opens comments to the end of a 4 MiB line: every
    # parenthesis is one step forward, and the value is read once to its end.
    opening = (
        mail + b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\n"
        b"Content-Type: text/plain\r\nContent-Transfer-Encoding: "
    )
    closing = b"\r\n\r\nnotes\r\n--B--\r\n"
    yield (
        "mail-encoding-comment.eml",
        opening + b"(" * (SIZE - len(opening) - len(closing)) + closing,
        None,
    )
    # One HTML body with no transfer encoding, which is opened as a part and read as HTML: a
    # single paragraph of 500,000 inline elements, beside the raw message.
    yield (
        "mail-html-tags.eml",
        _filled(mail + b"Content-Type: text/html\r\n\r\n<html><body><p>", b"<b>a</b>"),
        None,
    )
    # The same body inside three such messages: a one-body message is opened once, and its
    # body is not opened as another, so the page is decoded and read as HTML one time.
    page = mail + b"Content-Type: text/html\r\n\r\n"
    yield ("mail-nested-bodies.eml", _filled(page * 3 + b"<html><body><p>", b"<b>a</b>"), None)
    # And in a legacy charset, where every level opened would transcode the text again.
    cyrillic = mail + b"Content-Type: text/plain; charset=windows-1251\r\n\r\n"
    words = "квартальные итоги пересмотрены\r\n".encode("cp1251")
    yield ("mail-nested-charset.eml", _filled(cyrillic * 3, words), None)
    # A header block of the shortest lines there are, filling the window, with no blank line
    # before the HTML body: the block's end is found in one pass and the message is opened.
    opening = mail + b"Content-Type: text/html\r\n"
    lines = b"a:\r\n" * ((64 * 1024 - len(opening) - 64) // 4)
    yield (
        "mail-header-lines.eml",
        _filled(opening + lines + b"<html><body><p>", b"<b>a</b>"),
        None,
    )
    # The mail library reads a parameter in time quadratic in its header's length, and 60,000
    # semicolons inside one quoted value are the worst of it. For a message opened for its
    # one body the header block ends inside 64 KiB, and the parameters are read twice, for
    # the body's name and for its charset.
    yield (
        "mail-quoted-parameter.eml",
        _filled(mail + b'Content-Type: text/html; x="' + b";" * 60000 + b'"\r\n\r\n<p>', b"a"),
        None,
    )
    # Python decodes punycode in quadratic time: 2 MiB is past the scan deadline. One 8bit
    # body declared punycode is not opened, since punycode is not a charset. A quoted-printable
    # body is a part, read through its declared codec, and for this codec only up to 16 KiB:
    # a larger part is unread, which is incomplete.
    words = b"quarterly totals revised "
    opening = mail + b"Content-Type: text/plain; charset=punycode\r\n"
    for name, encoding, token, reason in (
        ("mail-punycode-body.eml", b"8bit", words, None),
        (
            "mail-punycode-part.eml",
            b"quoted-printable",
            words + b"=\r\n",
            "archive unreadable or encrypted",
        ),
    ):
        head = opening + b"Content-Transfer-Encoding: " + encoding + b"\r\n\r\n"
        count, rest = divmod(SIZE - len(head) - 160001, len(token))
        yield name, head + token * count + b"-" + b"a" * (160000 + rest), reason


def _content_pdf(prelude: bytes, token: bytes, objects: bytes = b"") -> bytes:
    """A 4 MiB content stream whose `/Length` lands on its `endstream`, then ``objects``."""
    marker = b"\nendstream\nendobj\n" + objects + b"%%EOF\n"
    for digits in range(1, 9):
        header_len = len(b"%PDF-1.4\n1 0 obj<</Length ") + digits + len(b">>stream\n")
        body_len = SIZE - header_len - len(marker)
        if body_len <= len(prelude) or len(str(body_len)) != digits:
            continue
        header = b"%PDF-1.4\n1 0 obj<</Length " + str(body_len).encode() + b">>stream\n"
        filler_len = body_len - len(prelude)
        count, rest = divmod(filler_len, len(token))
        body = prelude + token * count + b" " * rest
        if len(body) != body_len or b"endstream" in body:
            raise RuntimeError("content stream is not one landed span")
        return header + body + marker
    raise RuntimeError("content stream length does not fit")


def _cmap_pdf(
    fonts: int, cmap: bytes, filters: bytes, prefix: bytes = b"", suffix: bytes = b""
) -> bytes:
    """A 4 MiB page naming ``fonts`` Type0 fonts with one ToUnicode stream each.

    With ``filters`` each stream is ``cmap`` and a comment pads the file. Without, one stream
    repeats ``cmap`` between ``prefix`` and ``suffix`` to fill the file, and its `/Length`
    lands on `endstream`.
    """
    body = b"BT /F0 12 Tf 72 700 Td <00480069> Tj ET"
    names = b" ".join(b"/F%d %d 0 R" % (index, 100 + index) for index in range(fonts))
    head = b"".join(
        [
            b"%PDF-1.7\n1 0 obj<</Type/Page/MediaBox[0 0 612 792]/Resources<</Font<<",
            names + b">>>>/Contents 4 0 R>>endobj\n",
            b"4 0 obj<</Length %d>>stream\n%s\nendstream endobj\n" % (len(body), body),
            *(
                b"%d 0 obj<</Type/Font/Subtype/Type0/Encoding/Identity-H/ToUnicode %d 0 R>>"
                b"endobj\n" % (100 + index, 5000 + index)
                for index in range(fonts)
            ),
        ]
    )
    tail = b"\nendstream endobj\n%%EOF\n"
    if filters:
        streams = b"".join(
            b"%d 0 obj<</Length %d%s>>stream\n%s" % (5000 + index, len(cmap), filters, cmap) + tail
            for index in range(fonts)
        )
        return _filled(head + streams + b"%", b" ")[:-1] + b"\n"
    for digits in range(1, 9):
        start = b"5000 0 obj<</Length %s>>stream\n" % (b"0" * digits)
        length = SIZE - len(head) - len(start) - len(tail)
        if len(str(length)) != digits:
            continue
        count, rest = divmod(length - len(prefix) - len(suffix), len(cmap))
        stream = prefix + cmap * count + b" " * rest + suffix
        return head + b"5000 0 obj<</Length %d>>stream\n" % length + stream + tail
    raise RuntimeError("cmap stream length does not fit")


def _numbered(prefix: bytes, objects: Callable[[int], bytes]) -> bytes:
    """``prefix``, then ``objects(n)`` for n from 7 while they fit, padded to 4 MiB."""
    out = bytearray(prefix)
    number = 7
    while len(out) + len(body := objects(number)) <= SIZE - 6:
        out += body
        number += 1
    return bytes(out + b" " * (SIZE - 6 - len(out)) + b"%%EOF\n")


def _filled(prefix: bytes, token: bytes) -> bytes:
    count, rest = divmod(SIZE - len(prefix), len(token))
    return prefix + token * count + b" " * rest


def _stored(name: str, prefix: bytes, token: bytes, suffix: bytes) -> bytes:
    """A one-member stored ZIP of exactly 4 MiB, ZIP metadata included."""
    stream = io.BytesIO()
    info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
    overhead = 22 + 30 + 46 + 2 * len(info.filename)
    count, rest = divmod(SIZE - overhead - len(prefix) - len(suffix), len(token))
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr(info, prefix + token * count + b" " * rest + suffix)
    return stream.getvalue()


def scan_case(name: str, rules: Path) -> dict[str, object]:
    _, data, reason = next(case for case in cases() if case[0] == name)
    if len(data) != SIZE:
        raise RuntimeError(f"{name}: fixture is not 4 MiB")
    # Compile/load once outside the scan timer; the outer watchdog includes this work.
    warm = scan_bytes(b"Ordinary meeting notes.", name="warm.txt", rules_dir=rules)
    if warm.verdict.value != "clean" or not warm.compiled_rules or warm.skipped_rule_files:
        raise RuntimeError("bundled rule warmup failed")
    started = time.perf_counter()
    result = scan_bytes(data, name=name, rules_dir=rules)
    seconds = time.perf_counter() - started
    row = {
        "case": name,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "seconds": round(seconds, 6),
        "verdict": result.verdict.value,
        "incomplete_reason": result.incomplete_reason,
        "compiled_rules": result.compiled_rules,
        "skipped_rule_files": result.skipped_rule_files,
        "views_scanned": result.views_scanned,
        "engine": result.engine_version,
        "ruleset_sha256": result.ruleset_sha256,
    }
    print(json.dumps(row), flush=True)
    if seconds > SCAN_SECONDS:
        raise RuntimeError(f"{name}: {seconds:.3f}s exceeds {SCAN_SECONDS}s")
    if result.incomplete_reason != reason:
        raise RuntimeError(f"{name}: expected incomplete reason {reason!r}")
    view = {
        "comment-block.py": "comment-text",
        "markdown-lines.md": "markdown-text",
        "notebook-lines.ipynb": "notebook-text",
        "ooxml-hidden-runs.zip": "ooxml-hidden-text",
        "ooxml-xml-comments.zip": "ooxml-text",
        "ooxml-other-prefix.zip": "ooxml-text",
        "ooxml-xmlns-every-run.zip": "ooxml-text",
        "ooxml-drawing-breaks.zip": "ooxml-hidden-text",
        "ooxml-long-attribute.zip": "ooxml-text",
        "ooxml-tag-name-run.zip": "ooxml-text",
        "ooxml-two-vocabularies.zip": "ooxml-hidden-text",
        "odf-spans.zip": "odf-text",
        "odf-unknown-elements.zip": "odf-text",
        "pdf-font-definitions.pdf": "pdf-text",
        "pdf-font-keys.pdf": "pdf-text",
        "pdf-font-lenient.pdf": "pdf-text",
        "pdf-font-readings.pdf": "pdf-text",
        "pdf-font-readings-winansi.pdf": "pdf-text",
        "pdf-font-repeated-keys.pdf": "pdf-text",
        "pdf-font-shared-ways.pdf": "pdf-text",
        "pdf-font-windows.pdf": "pdf-text",
        "pdf-page-fonts.pdf": "pdf-text",
        "pdf-page-references.pdf": "pdf-text",
        "pdf-hidden-stretch.pdf": "pdf-hidden-text",
        "pdf-white-areas.pdf": "pdf-hidden-text",
        "mail-folded-window.eml": "html-text",
        "mail-html-tags.eml": "html-text",
        "mail-nested-bodies.eml": "html-text",
        "mail-header-lines.eml": "html-text",
    }.get(name)
    if view is not None and not result.views_scanned.get(view):
        raise RuntimeError(f"{name}: required reader {view} did not run")
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=[name for name, _, _ in cases()], help=argparse.SUPPRESS)
    parser.add_argument("--rules", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.case:
        if args.rules is None:
            parser.error("worker requires --rules")
        scan_case(args.case, args.rules)
        return
    revision = subprocess.check_output(  # fixed argv, repository metadata
        ["git", "rev-parse", "HEAD"],  # noqa: S607
        cwd=ROOT,
        text=True,
    ).strip()
    print(
        json.dumps(
            {
                "revision": revision,
                "python": sys.version.split()[0],
                "engine": importlib.metadata.version("yara-x"),
                "scan_ceiling_seconds": SCAN_SECONDS,
                "process_watchdog_seconds": PROCESS_SECONDS,
            }
        ),
        flush=True,
    )
    with tempfile.TemporaryDirectory(prefix="yara-timing-") as temporary:
        rules = Path(temporary) / "rules"
        shutil.copytree(ROOT / "rules/local", rules / "local")
        for name, _, _ in cases():
            command = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--case",
                name,
                "--rules",
                str(rules),
            ]
            try:
                subprocess.run(command, check=True, timeout=PROCESS_SECONDS)  # noqa: S603
            except subprocess.TimeoutExpired:
                raise SystemExit(f"FAIL {name}: process exceeded {PROCESS_SECONDS}s") from None
            except subprocess.CalledProcessError:
                raise SystemExit(f"FAIL {name}: worker failed") from None
    print(f"PASS: {len(list(cases()))} adversarial inputs, each exactly 4 MiB", flush=True)


if __name__ == "__main__":
    main()
