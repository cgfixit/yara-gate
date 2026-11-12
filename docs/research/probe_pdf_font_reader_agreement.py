"""Check how the text reader takes a PDF font dictionary against real PDF readers.

``pdftext`` reads a font through its own dictionary. The 4 KB window after the object's header
runs into the next object, so its first ``/ToUnicode`` can be the next font's, or sit in a
string, a comment, or a nested dictionary. Where the font's dictionary is one plainly written
value, of a simple font whose text this reader decodes as readers do, and the file is written
plainly throughout, the map that window gives is dropped. That is safe only when no reader
shows text through what was dropped. This probe asks readers instead of modelling them.

Every fixture is one page whose text only a ToUnicode map, or reading the bytes as WinAnsi,
turns into the phrase, so the raw and inflated views do not hold it. For each file the text
reader runs as shipped (``own``) and with the narrowing turned off (``wide``: every definition
keeps the window's reading beside its own, which holds everything the reader gave before it
read the dictionary), and each installed reader extracts the text:

- ``MISS``: a reader shows the phrase, the wide reading has it, and the shipped one does not.
  The probe exits 1.
- ``gap``: a reader shows the phrase and neither reading has it.

``fixtures`` runs the hand-written shapes; ``--all`` prints one row for each. ``fuzz`` builds
random font objects and files (structure choices, then token mutations), keeps the ones where
the shipped reading holds less than the wide one, and runs the readers on those only. With
``--gaps`` it also runs them on the files where neither reading holds the phrase, which is
how a spelling of the font's own map that some reader does not follow is found.

It uses the builders and the reader workers of ``probe_pdf_reader_agreement.py``, which sits
beside it; the readers and how to install them are described there::

    uv run --with pypdf --with pdfminer.six --with pypdfium2 \\
        python docs/research/probe_pdf_font_reader_agreement.py fixtures --all
    uv run --with pypdf --with pdfminer.six --with pypdfium2 \\
        python docs/research/probe_pdf_font_reader_agreement.py fuzz --seed 1 --count 15000

Nothing is executed from a fixture and no URL is fetched; readers only parse bytes this script
wrote.
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from collections.abc import Iterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import probe_pdf_reader_agreement as agreement

PHRASE = agreement.PHRASE
CODE = agreement.CODE
CODED = agreement.CODED
PAGE = agreement.page(b"/Contents 5 0 R", b"/Resources << /Font << /F1 6 0 R >> >>")
# The phrase as WinAnsi bytes, a word per string, in a Flate stream: no view holds it whole.
KERNED = agreement.flate(
    b"BT /F1 12 Tf 72 700 Td ["
    + b" -278 ".join(b"(" + word.encode() + b")" for word in PHRASE.split(" "))
    + b"] TJ ET"
)
SHOWN = agreement.stream(b"BT /F1 12 Tf 72 700 Td (" + CODED + b") Tj ET")
# The same codes as two-byte hex, for a composite font.
GLYPHS = agreement.stream(
    b"BT /F1 12 Tf 72 700 Td <" + b"".join(b"%04X" % code for code in CODED) + b"> Tj ET"
)
PHRASE_MAP = b"/ToUnicode 8 0 R"
DECOY_MAP = b"/ToUnicode 9 0 R"
# 4.4 KB of widths: with them a font dictionary runs past the 4 KB window after its header.
LONG = b"/Widths [" + b"500 " * 1100 + b"]"
PAD = b"<< /Pad (" + b"notes for the review. " * 230 + b") >>"
TYPE0 = (
    b"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Arial /Encoding /Identity-H"
    b" /DescendantFonts [12 0 R] %s>>"
)
CIDFONT = (
    b"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Arial"
    b" /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>"
    b" /FontDescriptor 13 0 R /DW 600 %s>>"
)
DESCRIPTOR = (
    b"<< /Type /FontDescriptor /FontName /AAAAAA+Arial /Flags 4 /FontBBox [0 -200 1000 900]"
    b" /ItalicAngle 0 /Ascent 900 /Descent -200 /CapHeight 700 /StemV 80 >>"
)
# A composite font as reportlab writes one of its Adobe CJK set: a predefined CMap of two-byte
# Unicode codes and no ToUnicode map, with its descendant font and descriptor, and the phrase
# in those codes. A reader that has the CMap shows the text with no map at all.
CJK = (
    b"<< /Type /Font /Subtype /Type0 /BaseFont /STSong-Light /Encoding /UniGB-UCS2-H"
    b" /DescendantFonts [12 0 R] >>"
)
CJK_CIDFONT = (
    b"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /STSong-Light"
    b" /CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 2 >>"
    b" /FontDescriptor 13 0 R /DW 1000 >>"
)
CJK_DESCRIPTOR = (
    b"<< /Type /FontDescriptor /FontName /STSong-Light /Flags 6 /FontBBox [-25 -254 1000 880]"
    b" /ItalicAngle 0 /Ascent 880 /Descent -120 /CapHeight 880 /StemV 93 >>"
)
UCS2 = agreement.stream(
    b"BT /F1 12 Tf 72 700 Td <" + PHRASE.encode("utf-16-be").hex().encode() + b"> Tj ET"
)


# An encoding that shows the codes as the phrase by glyph name, with no ToUnicode map.
GLYPH_NAMES = {" ": b"space", ".": b"period"}
DIFFERENCES = (
    b"<< /Type /Encoding /Differences [ "
    + b" ".join(
        b"%d /%s" % (code, GLYPH_NAMES.get(char, char.encode())) for char, code in CODE.items()
    )
    + b" ] >>"
)
WINANSI = b"/Encoding /WinAnsiEncoding"


def simple(*entries: bytes, subtype: bytes = b"/Type1", encoding: bytes = WINANSI) -> bytes:
    """A simple font's dictionary with ``entries`` after the usual ones."""
    return (
        b"<< /Type /Font /Subtype "
        + subtype
        + b" /BaseFont /Helvetica "
        + encoding
        + b" "
        + b" ".join(entries)
        + b" >>"
    )


def decoy_map() -> bytes:
    """Every printable byte to another letter: WinAnsi text read through it is noise too."""
    rows = b"".join(b"<%02X> <%04X>\n" % (code, 0x61 + (code * 7) % 26) for code in range(32, 127))
    return (
        b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
        b"1 begincodespacerange\n<00> <FF>\nendcodespacerange\n95 beginbfchar\n"
        + rows
        + b"endbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n"
    )


def wide_map(codespace: bool = True) -> bytes:
    """The phrase map for two-byte codes, with or without its codespace range."""
    rows = b"".join(b"<%04X> <%04X>\n" % (code, ord(char)) for char, code in CODE.items())
    return (
        b"/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
        + (b"1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n" if codespace else b"")
        + b"%d beginbfchar\n" % len(CODE)
        + rows
        + b"endbfchar\nendcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n"
    )


def page_file(
    content: bytes,
    *fonts: tuple[int, bytes],
    odd: bytes = b"",
    version: bytes = b"1.7",
    moved: dict[int, int] | None = None,
) -> bytes:
    """One page that draws ``content`` in /F1, object 6. ``fonts`` are the objects after the
    content stream, in order; the phrase map is object 8 and the decoy map object 9. ``odd``
    is written between the last object and the cross-reference table."""
    objects: dict[object, object] = {
        1: agreement.CATALOG,
        2: agreement.PAGES,
        3: PAGE,
        5: content,
    }
    objects.update(fonts)
    objects.setdefault(8, agreement.stream(agreement.cmap()))
    objects.setdefault(9, agreement.stream(decoy_map()))
    if odd:
        objects["odd"] = odd
    return agreement.build(objects, moved=moved).replace(b"%PDF-1.7", b"%PDF-" + version, 1)


def shapes() -> dict[str, bytes]:
    """The hand-written shapes. ``W`` in a comment: the text is WinAnsi bytes, shown when the
    font is read with no map. ``C``: it is codes, shown through the phrase map."""
    out: dict[str, bytes] = {}
    plain = simple()
    mapped = (7, simple(PHRASE_MAP))
    type0 = [(7, TYPE0 % DECOY_MAP), (12, CIDFONT % b""), (13, DESCRIPTOR)]

    # --- the next object's map (W)
    out["next-control-font-alone"] = page_file(KERNED, (6, plain))
    out["next-type0-font-with-a-map"] = page_file(KERNED, (6, plain), *type0)
    out["next-simple-font-with-a-map"] = page_file(KERNED, (6, plain), (7, simple(DECOY_MAP)))
    out["next-type0-font-5KB-away"] = page_file(KERNED, (6, plain), (10, PAD), *type0)
    out["next-type0-font-with-no-map"] = page_file(
        KERNED, (6, plain), (7, TYPE0 % b""), (12, CIDFONT % b""), (13, DESCRIPTOR)
    )
    out["next-long-font-then-type0-with-a-map"] = page_file(KERNED, (6, simple(LONG)), *type0)
    # the same in a file that is not plain, and in a font that is not: a form feed
    out["next-type0-map-file-not-plain"] = page_file(KERNED, (6, plain), *type0, odd=b"\x0c\n")
    out["next-type0-map-font-not-plain"] = page_file(
        KERNED, (6, plain.replace(b" /Encoding", b"\x0c/Encoding")), *type0
    )
    out["next-type0-map-font-odd-number"] = page_file(
        KERNED, (6, simple(b"/X 5.0e0")), (7, simple(DECOY_MAP))
    )
    # --- readings only the window gives: each has to stay (C, through the next font's map)
    out["window-xref-sends-the-font-to-the-next"] = page_file(
        SHOWN, (6, plain), mapped, moved={6: 7}
    )
    out["window-font-with-no-closing-bracket"] = page_file(SHOWN, (6, plain[:-3]), mapped)
    out["window-string-where-a-key-belongs"] = page_file(SHOWN, (6, simple(b"(/ToUnicode 8 0 R)")))
    out["window-key-after-the-closing-bracket"] = page_file(
        SHOWN, (6, plain + b" /ToUnicode 8 0 R >>")
    )
    out["window-second-header-in-vertical-tabs"] = page_file(
        SHOWN, (6, plain + b"\nendobj\n6\x0b0\x0bobj\n" + simple(PHRASE_MAP))
    )
    out["window-font-is-a-reference-to-the-next"] = page_file(SHOWN, (6, b"7 0 R"), mapped)
    # a composite font: pdf.js takes the map from its descendant font's dictionary first
    wide = (8, agreement.stream(wide_map()))
    out["window-type0-control-own-map"] = page_file(
        GLYPHS, (6, TYPE0 % PHRASE_MAP), (12, CIDFONT % b""), (13, DESCRIPTOR), wide
    )
    out["window-type0-map-in-the-next-descendant"] = page_file(
        GLYPHS, (6, TYPE0 % b""), (12, CIDFONT % PHRASE_MAP), (13, DESCRIPTOR), wide
    )
    out["window-type0-map-in-a-far-descendant"] = page_file(
        GLYPHS, (6, TYPE0 % b""), (10, PAD), (12, CIDFONT % PHRASE_MAP), (13, DESCRIPTOR), wide
    )
    out["window-type0-decoy-map-descendant-has-the-map"] = page_file(
        GLYPHS, (6, TYPE0 % DECOY_MAP), (12, CIDFONT % PHRASE_MAP), (13, DESCRIPTOR), wide
    )
    # --- a key written more than once (C)
    out["key-control-once"] = page_file(SHOWN, (6, simple(PHRASE_MAP)))
    out["key-twice-phrase-last"] = page_file(SHOWN, (6, simple(DECOY_MAP, PHRASE_MAP)))
    out["key-twice-phrase-first"] = page_file(SHOWN, (6, simple(PHRASE_MAP, DECOY_MAP)))
    out["key-three-times-phrase-middle"] = page_file(
        SHOWN, (6, simple(DECOY_MAP, PHRASE_MAP, DECOY_MAP))
    )
    filler = [b"/K%02d 0" % index for index in range(40)]
    for index, where in enumerate(("first", "middle", "last")):
        keys = [DECOY_MAP] * 3
        keys[index] = PHRASE_MAP
        font = simple(keys[0], *filler[:20], keys[1], *filler[20:], keys[2])
        out[f"key-three-times-40-entries-phrase-{where}"] = page_file(SHOWN, (6, font))
    out["key-six-times-phrase-fourth"] = page_file(
        SHOWN,
        (6, simple(*[b"/ToUnicode %d 0 R" % number for number in (9, 20, 21, 8, 22, 23)])),
        *[(number, agreement.stream(agreement.cmap(decoy=True))) for number in (20, 21, 22, 23)],
    )
    out["key-then-null"] = page_file(KERNED, (6, simple(DECOY_MAP, b"/ToUnicode null")))
    out["key-null-then-map"] = page_file(SHOWN, (6, simple(b"/ToUnicode null", PHRASE_MAP)))
    out["key-twice-phrase-last-long-font"] = page_file(
        SHOWN, (6, simple(LONG, DECOY_MAP, PHRASE_MAP))
    )
    out["key-in-the-window-phrase-key-past-it"] = page_file(
        SHOWN, (6, simple(DECOY_MAP, LONG, PHRASE_MAP))
    )
    out["key-twice-phrase-last-font-not-plain"] = page_file(
        SHOWN, (6, simple(b"\x0c" + DECOY_MAP, PHRASE_MAP))
    )
    out["key-twice-phrase-last-file-not-plain"] = page_file(
        SHOWN, (6, simple(DECOY_MAP, PHRASE_MAP)), odd=b"\x0c\n"
    )
    out["key-twice-in-an-object-stream"] = agreement.xref_stream_file(
        {
            1: agreement.CATALOG,
            2: agreement.PAGES,
            3: PAGE,
            5: SHOWN,
            8: agreement.stream(agreement.cmap()),
            9: agreement.stream(decoy_map()),
            10: agreement.objstm([(6, simple(DECOY_MAP, PHRASE_MAP))]),
        },
        {6: (10, 0)},
    )
    # --- the font's own map, in a spelling only some lexers follow (W: read with no map)
    out["reference-control-plain"] = page_file(KERNED, (6, simple(DECOY_MAP)))
    for label, reference in REFERENCES.items():
        key = b"/ToUnicode " + reference
        out[f"reference-{label}"] = page_file(KERNED, (6, simple(key)))
        out[f"reference-{label}-next-font-has-a-map"] = page_file(
            KERNED, (6, simple(key)), (7, simple(b"/ToUnicode 20 0 R")), (20, DECOY)
        )
    out["reference-comment-before-the-value"] = page_file(
        KERNED, (6, simple(b"/ToUnicode %a comment\n9 0 R"))
    )
    # pypdf reads a number where a comment splits the reference
    out["reference-comment-inside-next-font-has-a-map"] = page_file(
        KERNED,
        (6, simple(b"/ToUnicode 9 %a comment\n0 R")),
        (7, simple(b"/ToUnicode 20 0 R")),
        (20, DECOY),
    )
    digits = {"4301-digits": b"1" * 4301, "5000-zeros": b"0" * 5000 + b"9"}
    for label, number in digits.items():
        out[f"reference-of-{label}"] = page_file(
            KERNED, (6, simple(b"/ToUnicode " + number + b" 0 R"))
        )
        out[f"reference-of-{label}-font-not-plain"] = page_file(
            KERNED, (6, simple(b"\x0c/ToUnicode " + number + b" 0 R"))
        )
    # --- /Subtype written twice (W)
    twice = b"<< /Type /Font /Subtype %s /Subtype %s /BaseFont /Helvetica >>"
    out["subtype-type0-then-type1"] = page_file(KERNED, (6, twice % (b"/Type0", b"/Type1")))
    out["subtype-type1-then-type0"] = page_file(KERNED, (6, twice % (b"/Type1", b"/Type0")))
    # --- a decoy that is not a key of the font dictionary (W: the font has no map; C: it has)
    decoys = {
        "string": b"/Note (/ToUnicode 9 0 R)",
        "comment": b"%/ToUnicode 9 0 R\n",
        "nested-dictionary": b"/Note << /ToUnicode 9 0 R >>",
        "array": b"/Note [/ToUnicode 9 0 R]",
    }
    for label, decoy in decoys.items():
        out[f"decoy-in-a-{label}"] = page_file(KERNED, (6, simple(decoy)))
        out[f"decoy-in-a-{label}-then-the-key"] = page_file(SHOWN, (6, simple(decoy, PHRASE_MAP)))
    out["decoy-control-key-then-string"] = page_file(
        SHOWN, (6, simple(PHRASE_MAP, decoys["string"]))
    )
    out["decoy-type0-in-a-string"] = page_file(KERNED, (6, simple(b"/Note (/Subtype /Type0)")))
    out["decoy-identity-in-a-nested-dictionary"] = page_file(
        KERNED, (6, simple(b"/Note << /Encoding /Identity-H >>"))
    )
    out["decoy-in-a-string-long-font"] = page_file(KERNED, (6, simple(LONG, decoys["string"])))
    out["decoy-in-a-string-then-the-key-long-font"] = page_file(
        SHOWN, (6, simple(decoys["string"], LONG, PHRASE_MAP))
    )
    out["decoy-in-a-string-font-not-plain"] = page_file(
        KERNED, (6, simple(b"\x0c" + decoys["string"]))
    )
    out["decoy-in-a-string-file-not-plain"] = page_file(
        KERNED, (6, simple(decoys["string"])), odd=b"\x0c\n"
    )
    # --- the bytes ``endobj`` inside the font dictionary, before its key (C)
    out["endobj-control-in-a-string"] = page_file(SHOWN, (6, simple(b"/Note (endobj)", PHRASE_MAP)))
    for label, inside in {"string": b"/Note (endobj)", "name": b"/Note /endobj"}.items():
        out[f"endobj-in-a-{label}-long-font"] = page_file(
            SHOWN, (6, simple(inside, LONG, PHRASE_MAP))
        )
    out["endobj-in-a-comment-long-font"] = page_file(
        SHOWN, (6, simple(b"%endobj\n", LONG, PHRASE_MAP))
    )
    out["endobj-in-a-string-long-font-not-plain"] = page_file(
        SHOWN, (6, simple(b"\x0c/Note (endobj)", LONG, PHRASE_MAP))
    )
    out["long-control-key-past-the-window"] = page_file(SHOWN, (6, simple(LONG, PHRASE_MAP)))
    # --- a key written with a # escape (C unless a decoy)
    escapes = {
        "valid": b"/To#55nicode 8 0 R",
        "valid-lower-hex": b"/To#55nic#6fde 8 0 R",
        "nul-then-more": b"/ToUnicode#00x 8 0 R",
        "hash-then-space": b"/ToUnicode# 8 0 R",
        "hash-one-digit": b"/ToUnicode#4 8 0 R",
        "hash-not-hex": b"/ToUnicode#ZZ 8 0 R",
        "hash-20": b"/ToUnicode#20 8 0 R",
    }
    for label, key in escapes.items():
        out[f"escape-{label}"] = page_file(SHOWN, (6, simple(key)))
    out["escape-valid-in-pdf-1.1"] = page_file(SHOWN, (6, simple(escapes["valid"])), version=b"1.1")
    out["escape-valid-font-not-plain"] = page_file(SHOWN, (6, simple(b"\x0c" + escapes["valid"])))
    out["escape-key-then-escaped-key"] = page_file(SHOWN, (6, simple(DECOY_MAP, escapes["valid"])))
    out["escape-escaped-key-then-key"] = page_file(SHOWN, (6, simple(escapes["valid"], DECOY_MAP)))
    out["escape-decoy-nul-then-more"] = page_file(KERNED, (6, simple(b"/ToUnicode#00x 9 0 R")))
    out["escape-decoy-hash-then-space"] = page_file(KERNED, (6, simple(b"/ToUnicode# 9 0 R")))
    out["escape-type1-escaped-type0-in-a-string"] = page_file(
        KERNED, (6, simple(b"/Note (/Subtype /Type0)", subtype=b"/Type#31"))
    )
    out["escape-in-the-base-font-next-map"] = page_file(
        KERNED, (6, plain.replace(b"/Helvetica", b"/Helvetica#20Neue")), *type0
    )
    # --- text this reader does not decode from the font's own dictionary: the window's
    # reading stays, so nothing it held is lost (C)
    differences = simple(encoding=b"/Encoding " + DIFFERENCES)
    out["encoding-differences-next-font-has-the-map"] = page_file(SHOWN, (6, differences), mapped)
    out["encoding-in-another-object-next-font-has-the-map"] = page_file(
        SHOWN, (6, simple(encoding=b"/Encoding 10 0 R")), mapped, (10, DIFFERENCES)
    )
    out["encoding-of-a-font-program-next-font-has-the-map"] = page_file(
        SHOWN, (6, simple(b"/FontDescriptor 13 0 R", encoding=b"")), mapped, (13, DESCRIPTOR)
    )
    bare = (8, agreement.stream(wide_map(codespace=False)))
    cid = [(12, CIDFONT % b""), (13, DESCRIPTOR)]
    out["codespace-missing-two-byte-string-next-type0"] = page_file(
        GLYPHS, (6, simple(PHRASE_MAP)), (7, TYPE0 % b""), *cid, bare
    )
    out["codespace-missing-two-byte-string-type0-in-a-string"] = page_file(
        GLYPHS, (6, simple(b"/Note (/Subtype /Type0)", PHRASE_MAP)), bare
    )
    # --- gaps this reader had before and still has: no reading holds the phrase
    out["gap-encoding-differences-alone"] = page_file(SHOWN, (6, differences))
    out["gap-codespace-missing-one-byte-string"] = page_file(SHOWN, (6, simple(PHRASE_MAP)), bare)
    out["gap-codespace-missing-two-byte-string"] = page_file(GLYPHS, (6, simple(PHRASE_MAP)), bare)
    # a generation no definition of the map has: poppler and pypdf read the font with no map
    out["gap-reference-generation-no-definition"] = page_file(
        KERNED, (6, simple(b"/ToUnicode 9 1 R"))
    )
    # the keyword ``endobj`` inside the dictionary: PDFium, poppler, and pypdf read on to the
    # key after it, and this reader takes the dictionary to end there
    out["gap-escaped-key-after-a-bare-endobj"] = page_file(
        SHOWN, (6, simple(b"/X endobj /To#55nicode 8 0 R"))
    )
    # backlog B8: a composite font that names no map. PDFium, pdfminer.six, and pypdf show
    # this one's text through its predefined CMap. Alone it is reported as unmapped. Before
    # an object that has a map it keeps the one reading through that map, as before its
    # dictionary was read, and nothing is reported: the reading with no map would report
    # ordinary documents that pypdf or pdfseparate wrote
    cjk = [(12, CJK_CIDFONT), (13, CJK_DESCRIPTOR)]
    out["gap-type0-predefined-cmap-alone"] = page_file(UCS2, (6, CJK), *cjk)
    out["gap-type0-predefined-cmap-next-font-has-a-map"] = page_file(
        UCS2, (6, CJK), (7, simple(DECOY_MAP)), *cjk
    )
    # the same for a simple font whose /Encoding is an Identity CMap, which this reader
    # takes for a composite font: PDFium, pdfminer.six, and poppler show its WinAnsi text
    identity = simple(encoding=b"/Encoding /Identity-H")
    out["gap-identity-encoding-simple-font-alone"] = page_file(KERNED, (6, identity))
    out["gap-identity-encoding-simple-font-next-font-has-a-map"] = page_file(
        KERNED, (6, identity), (7, simple(DECOY_MAP))
    )
    # and for a /Type0 font with no descendant fonts: poppler shows its WinAnsi text
    orphan = simple(subtype=b"/Type0")
    out["gap-type0-no-descendants-alone"] = page_file(KERNED, (6, orphan))
    out["gap-type0-no-descendants-next-font-has-a-map"] = page_file(
        KERNED, (6, orphan), (7, simple(DECOY_MAP))
    )
    return out


# The decoy map as the object after a font, and the font's own map in the spellings of a
# reference that lexers do not all take. The strict lexer of ``pdfpages`` reads each of
# these as a reference to object 9.
DECOY = agreement.stream(decoy_map())
REFERENCES = {
    "no-space-before-R": b"9 0R",
    "generation-six-digits": b"9 123456 R",
    "generation-65536": b"9 065536 R",
    "generation-eleven-digits": b"9 99999999999 R",
    "generation-six-zeros": b"9 000000 R",
    "number-eleven-digits": b"00000000009 0 R",
}
# What the fuzz writes for the value of the font's own /ToUnicode.
SPELLINGS = [
    *REFERENCES.values(),
    b"9 0 R",
    b"9 00000 R",
    b"9 1 R",
    b"9 65535 R",
    b"09 0 R",
    b"9\n0\nR",
    b"9 0 R%c\n",
    b"%c\n9 0 R",
    b"9 %c\n0 R",
    b"+9 0 R",
    b"9.0 0 R",
    b"9 0.0 R",
    b"9 0 r",
    b"9 0 RR",
    b"9 0 R 0 R",
    b"[ 9 0 R ]",
    b"<< >>",
    b"(9 0 R)",
    b"/Identity-H",
    b"1" * 4301 + b" 0 R",
    b"0" * 4400 + b"9 0 R",
]


# What a fuzzed font dictionary may hold besides its usual entries. The phrase map is object
# 8: the wide reading finds it wherever its bytes are, a reader only where it is a key.
PLACES = [
    b"/Note (/ToUnicode 8 0 R)",
    b"/Note (a \\( /ToUnicode 8 0 R)",
    b"/Note ((x) /ToUnicode 8 0 R)",
    b"%/ToUnicode 8 0 R\n",
    b"/Note << /ToUnicode 8 0 R >>",
    b"/Note [ /ToUnicode 8 0 R ]",
    b"/Note [ << /ToUnicode 8 0 R >> ]",
    b"/FontDescriptor << /Type /FontDescriptor /ToUnicode 8 0 R >>",
    b"(/ToUnicode 8 0 R)",
    b"/To#55nicode 8 0 R",
    b"/ToUnicode#00x 8 0 R",
    b"/ToUnicode# 8 0 R",
    b"/Note /ToUnicode /X 8 0 R",
    b"/Note <2F546F556E69636F646520382030205220>",
]
COMPOSITE_CUES = [
    b"/Note (/Subtype /Type0)",
    b"/Note << /Subtype /Type0 >>",
    b"%/Subtype /Type0\n",
    b"/Note (/Encoding /Identity-H)",
    b"/Note << /Encoding /Identity-H >>",
    b"/Subtype /Type#30",
    b"/Subtype /Type0#00x",
    b"/Encoding /Identity-H",
]
SUBTYPES = [b"/Type1", b"/Type1", b"/TrueType", b"/Type3", b"/MMType1", b"/Type0", b"10 0 R", b""]
# How a fuzzed font is encoded. Through the last three a reader shows the codes as the
# phrase with no map at all, which this reader does not decode.
ENCODINGS: list[list[bytes]] = [
    [WINANSI],
    [WINANSI],
    [WINANSI],
    [b"/Encoding /MacRomanEncoding"],
    [],
    [b"/FontDescriptor 13 0 R"],
    [WINANSI, b"/FontDescriptor 13 0 R"],
    [b"/Encoding /MacExpertEncoding"],
    [b"/Encoding " + DIFFERENCES],
    [b"/Encoding 11 0 R"],
    [WINANSI, b"/Encoding " + DIFFERENCES],
]
BETWEEN = [
    b"",
    b"",
    b"%a comment\n",
    b"10 0 obj\n<< /Foo /Bar >>\nendobj\n",
    b"10 0 obj\n[ 1 2 3 ]\nendobj\n",
    b"\x0c",
    b"\x00",
    b"garbage\n",
    b"endobj\n",
]
ENDINGS = [b"\nendobj\n", b"\nendobj\n", b"\nendobj\n", b" endobj ", b"\n", b" ", b"\nendobj", b""]
HEADERS = [b"6 0 obj", b"6 0 obj", b"6 0 obj", b"6 0obj", b"06 0 obj", b"6\x0b0\x0bobj", b"6 1 obj"]


def make(rng: random.Random) -> tuple[str, bytes]:
    """One mutant: its label and its bytes.

    Object 6 is the font the page names. What makes the wide reading hold the phrase is one
    of: the object after it has the phrase map; its own dictionary holds the bytes of a
    /ToUnicode entry where they are not a key; only a composite reading decodes the text
    and the window alone says the font is composite; or the text is WinAnsi bytes and the
    font's own /ToUnicode names the decoy map in a spelling the window's search, or some
    reader, does not take for a reference.
    """
    family = rng.choice(["next", "next", "place", "place", "composite", "spelling"])
    label = [family]
    subtype = rng.choice(SUBTYPES)
    entries: list[bytes] = [b"/Type /Font"]
    if subtype:
        entries.append(b"/Subtype " + subtype)
    entries += [b"/BaseFont /Helvetica", *rng.choice(ENCODINGS)]
    content = SHOWN
    maps: dict[object, object] = {
        8: agreement.stream(agreement.cmap()),
        9: agreement.stream(decoy_map()),
        11: DIFFERENCES,
        13: DESCRIPTOR,
    }
    following: list[tuple[object, object]] = []
    if family == "next":
        if rng.random() < 0.3:
            entries.append(DECOY_MAP if rng.random() < 0.5 else b"/ToUnicode null")
        kind = rng.randrange(5)
        label.append(f"k{kind}")
        if kind == 0:
            following = [(7, simple(PHRASE_MAP))]
        elif kind == 1:
            following = [(7, b"<< /Foo /Bar /ToUnicode 8 0 R >>")]
        elif kind == 2:
            following = [(7, agreement.stream(b"/ToUnicode 8 0 R"))]
        elif kind == 3:
            following = [("raw", b"%/ToUnicode 8 0 R\n")]
        else:
            following = [(7, b"[ /ToUnicode 8 0 R ]")]
    elif family == "spelling":
        content = KERNED
        entries.insert(rng.randrange(1, len(entries) + 1), b"/ToUnicode " + rng.choice(SPELLINGS))
        if rng.random() < 0.4:
            # the next font has a map of its own, which is not this font's
            following = [(7, simple(b"/ToUnicode 20 0 R")), (20, DECOY)]
    elif family == "place":
        place = rng.choice(PLACES)
        own = rng.choice([b"", b"", DECOY_MAP, b"/ToUnicode null"])
        parts = [place, own] if rng.random() < 0.7 else [own, place]
        at = rng.randrange(1, len(entries) + 1)
        entries[at:at] = [part for part in parts if part]
    else:
        # Two-byte codes: only a composite reading of the font decodes them.
        content = GLYPHS
        maps[8] = agreement.stream(wide_map(codespace=rng.random() < 0.3))
        entries.append(PHRASE_MAP)
        if rng.random() < 0.5:
            entries.insert(rng.randrange(1, len(entries)), rng.choice(COMPOSITE_CUES))
        else:
            following = [(7, TYPE0 % b""), (12, CIDFONT % b""), (13, DESCRIPTOR)]
    if rng.random() < 0.15:
        entries.insert(rng.randrange(1, len(entries) + 1), LONG)
        label.append("long")
    font = b"<< " + b" ".join(entries) + b" >>"
    if rng.random() < 0.5:
        font = agreement.mutate(font, rng, rng.choice([1, 1, 2, 3]))
        label.append("m")
    if rng.random() < 0.08:
        font = font.rstrip(b"> ")
        label.append("open")
    between = rng.choice(BETWEEN)
    ending = rng.choice(ENDINGS)
    header = rng.choice(HEADERS)
    xref = rng.choice(["classic", "classic", "none", "stream"])
    label.append(xref)
    objects: dict[object, object] = {1: agreement.CATALOG, 2: agreement.PAGES, 3: PAGE, 5: content}
    structure = rng.randrange(8)
    label.append(f"s{structure}")
    if structure == 0 and xref == "stream" and b"stream" not in font:
        # the font, and what follows it, as object-stream members
        members = [(6, font)] + [
            (number, bytes(body))  # type: ignore[call-overload]
            for number, body in following
            if isinstance(number, int) and b"stream" not in bytes(body)  # type: ignore[call-overload]
        ]
        pad = PHRASE_MAP + b"\n" if rng.random() < 0.3 else b""
        objects.update(maps)
        objects[14] = agreement.objstm(members, pad=pad)
        compressed = {number: (14, index) for index, (number, _) in enumerate(members)}
        if len(members) > 1 and rng.random() < 0.3:
            compressed[6] = (14, 1)
        return "-".join(label), agreement.xref_stream_file(objects, compressed)
    # the font written raw, with its header, what ends it, and what comes before the next
    objects["font"] = header + b"\n" + font + ending + between
    objects.update(following)
    objects.update(maps)
    if structure == 1:
        # a second definition of the font: the phrase font
        objects["again"] = b"6 0 obj\n" + simple(PHRASE_MAP) + b"\nendobj\n"
    return "-".join(label), _file(objects, xref, structure, rng)


def _file(objects: dict[object, object], xref: str, structure: int, rng: random.Random) -> bytes:
    """``objects`` in order with the cross-reference table ``xref`` names. The font, written
    as raw bytes under the key ``font``, is object 6: its entry is at its header, or, by
    ``structure``, at the next object's header, a few bytes off, free, or under generation 1.
    """
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets: dict[int, int] = {}
    for key, body in objects.items():
        if isinstance(key, int):
            offsets[key] = len(out)
            out += b"%d 0 obj\n" % key + bytes(body) + b"\nendobj\n"  # type: ignore[call-overload]
        else:
            if key == "font":
                offsets[6] = len(out)
            out += bytes(body)  # type: ignore[call-overload]
    if xref == "none":
        return bytes(out + b"trailer\n<< /Size 16 /Root 1 0 R >>\n%%EOF\n")
    generation = 0
    if structure == 2 and 7 in offsets:
        offsets[6] = offsets[7]
    elif structure == 3:
        offsets[6] = max(0, offsets[6] + rng.choice([1, 2, 8, -1]))
    elif structure == 4:
        del offsets[6]
    elif structure == 5:
        generation = 1
    start = len(out)
    if xref == "classic":
        out += b"xref\n0 15\n0000000000 65535 f \n"
        for number in range(1, 15):
            if number in offsets:
                out += b"%010d %05d n \n" % (offsets[number], generation if number == 6 else 0)
            else:
                out += b"0000000000 00001 f \n"
        out += b"trailer\n<< /Size 15 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % start
        return bytes(out)
    offsets[15] = start
    rows = b""
    for number in range(16):
        if number in offsets:
            rows += b"\x01" + offsets[number].to_bytes(4, "big")
            rows += (generation if number == 6 else 0).to_bytes(2, "big")
        else:
            rows += b"\x00\x00\x00\x00\x00\xff\xff"
    table = agreement.stream(rows, b" /Type /XRef /Size 16 /W [1 4 2] /Root 1 0 R")
    out += b"15 0 obj\n" + table + b"\nendobj\nstartxref\n%d\n%%%%EOF\n" % start
    return bytes(out)


def generate(seed: int, count: int) -> Iterator[tuple[str, bytes]]:
    rng = random.Random(seed)  # noqa: S311 - a repeatable fuzzing seed, not a secret
    for index in range(count):
        try:
            label, data = make(rng)
        except Exception as error:  # a mutation that cannot be assembled is skipped
            label, data = f"skip-{type(error).__name__}", b""
        if data:
            yield f"f{seed}-{index:06d}-{label}", data


def _level(data: bytes, narrow: bool) -> int:
    """3 held as incomplete, 2 the phrase is read, 1 flagged unmapped, 0 nothing."""
    from yara_gate import pdfpages, pdftext
    from yara_gate.content import Budget, ContentLimit, PdfObjects, pdf_streams

    get = pdfpages.PlainFile.get
    if not narrow:
        # No file counts as plain: every definition keeps the window's reading.
        pdfpages.PlainFile.get = _never  # type: ignore[method-assign]
    budget = Budget(time.monotonic() + 30)
    try:
        objects = PdfObjects(data, budget)
        result = pdftext.pdf_text(data, pdf_streams(data, budget, objects.decoded), objects, budget)
    except (ContentLimit, ValueError):
        # The scanner holds any failure of a reader as an incomplete scan.
        return 3
    finally:
        pdfpages.PlainFile.get = get  # type: ignore[method-assign]
    text = "".join("".join(block.split()) for block in [*result.blocks, *result.hidden_blocks])
    if agreement.KEY in text.lower():
        return 2
    return 1 if result.unmapped else 0


def _never(self: object) -> None:
    return None


def _report(files: dict[str, bytes], pdfjs: Path | None, show_all: bool) -> int:
    answers = agreement._readers(files, pdfjs)
    order = sorted({label for row in answers.values() for label in row})
    if not order:
        print("no PDF reader is installed; see probe_pdf_reader_agreement.py")
        return 2
    print(f"{'file':48} " + " ".join(f"{label[:8]:8}" for label in order) + "  wide       own")
    counts: Counter[str] = Counter()
    for name in sorted(files):
        row = answers.get(name, {})
        wide, own = _level(files[name], False), _level(files[name], True)
        shown = any(answer == "yes" for answer in row.values())
        verdict = ""
        if shown and own < 2:
            verdict = "MISS" if wide == 2 else "gap"
        counts[verdict or "ok"] += 1
        if verdict or show_all:
            cells = " ".join(f"{row.get(label, '?'):8}" for label in order)
            levels = f"{agreement.LEVELS[wide]:10} {agreement.LEVELS[own]:10}"
            print(f"{name:48} {cells}  {levels} {verdict}")
    print(
        f"{len(files)} files, readers: {', '.join(order)}; "
        f"MISS {counts['MISS']}, gap {counts['gap']}, ok {counts['ok']}"
    )
    return 1 if counts["MISS"] else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    fixtures = commands.add_parser("fixtures", help="the hand-written shapes")
    fuzz = commands.add_parser("fuzz", help="random font objects the shipped reader narrows")
    fuzz.add_argument("--seed", type=int, default=1)
    fuzz.add_argument("--seeds", type=int, default=1, help="how many seeds, counting up")
    fuzz.add_argument("--count", type=int, default=15000, help="mutants per seed")
    fuzz.add_argument(
        "--gaps",
        type=int,
        default=0,
        metavar="N",
        help="also run the readers on up to N files where neither reading holds the phrase",
    )
    for command in (fixtures, fuzz):
        command.add_argument("--pdfjs", type=Path, help="directory with node_modules/pdfjs-dist")
        command.add_argument("--all", action="store_true", help="print every file, not only misses")
        command.add_argument("--keep", type=Path, help="also write the checked files here")
    args = parser.parse_args()
    if args.command == "fixtures":
        files = shapes()
    else:
        files = {}
        unread: dict[str, bytes] = {}
        states: Counter[str] = Counter()
        total = 0
        for seed in range(args.seed, args.seed + args.seeds):
            for name, data in generate(seed, args.count):
                total += 1
                wide, own = _level(data, False), _level(data, True)
                states[f"wide {agreement.LEVELS[wide]}, own {agreement.LEVELS[own]}"] += 1
                if own < wide or (own == wide == 0 and len(unread) < args.gaps):
                    (files if own < wide else unread)[name] = data
        print(f"{total} mutants; the shipped reading holds less than the wide one in {len(files)}")
        files.update(unread)
        for state, count in sorted(states.items()):
            print(f"  {state:36} {count}")
    if args.keep:
        args.keep.mkdir(parents=True, exist_ok=True)
        for name, data in files.items():
            (args.keep / f"{name}.pdf").write_bytes(data)
    return _report(files, args.pdfjs, args.all)


if __name__ == "__main__":
    raise SystemExit(main())
