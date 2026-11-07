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
        ("rtf-controls.rtf", b"{\\rtf1 ", b"{\\b ", None),
        ("svg-spans.svg", b"<svg><text>", b"<tspan>a</tspan>", None),
        ("small-capitals.txt", b"", "\u026a\u0262\u0274\u1d0f\u0280\u1d07 ".encode(), None),
    )
    for name, prefix, token, reason in patterns:
        count, rest = divmod(SIZE - len(prefix), len(token))
        yield name, prefix + token * count + b" " * rest, reason
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
    stream = b"%PDF-1.4\n1 0 obj<</Length 0>>stream\n"
    # One invisible stretch: every string goes to both the shown and the hidden grouping.
    yield "pdf-hidden-stretch.pdf", _filled(stream + b"BT /F1 12 Tf 3 Tr ", b"(a) Tj "), None
    # White text that moves on every string, inside the union of the most painted areas a
    # stream keeps but on none of them, so no answer is reused.
    areas = b"".join(b"%d 0 1 1 re f " % (index * 100) for index in range(31))
    white = stream + b"0 g " + areas + b"0 9000 1 1 re f BT /F1 12 Tf 50 4000 Td 1 1 1 rg "
    yield "pdf-white-areas.pdf", _filled(white, b"0 1 Td (a) Tj "), None
    # Hidden and shown strings in turn reach the text block cap.
    yield (
        "pdf-hidden-blocks.pdf",
        _filled(stream + b"BT /F1 12 Tf ", b"3 Tr (a) Tj 0 Tr (b) Tj "),
        "pdf text blocks exceed 20000",
    )
    # Two content streams, so the /Contents continuation index runs over every match: once a
    # rescanned 4 KiB window per match (a 30 s timeout here), and once a page object apiece.
    streams = (
        b"%PDF-1.4\n7 0 obj<</Length 8>>stream\nBT ET \nendstream endobj\n"
        b"8 0 obj<</Length 8>>stream\nBT ET \nendstream endobj\n"
    )
    yield "pdf-contents-arrays.pdf", _filled(streams, b"/Contents["), None
    page = b"1 0 obj<</Type/Page/Contents[7 0 R 8 0 R]>>endobj\n"
    yield "pdf-page-objects.pdf", _filled(streams, page), None


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
    revision = subprocess.check_output(  # noqa: S603 - fixed argv, repository metadata
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
