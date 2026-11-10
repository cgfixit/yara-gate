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
from collections.abc import Iterator
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
        "pdf-font-definitions.pdf": "pdf-text",
        "pdf-font-readings.pdf": "pdf-text",
        "pdf-hidden-stretch.pdf": "pdf-hidden-text",
        "pdf-white-areas.pdf": "pdf-hidden-text",
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
