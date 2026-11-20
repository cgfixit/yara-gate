"""Build an agreement capture: your reader's text for each conformance fixture.

``yara-gate conform --export DIR`` writes the fixtures. This script stands in for a
consumer's extractor: it reads each exported PDF with ``pdftotext`` (poppler) and each
HTML page with a text-node reader that never looks at ``style``, and prints one capture
line per file it could read. Replace ``extract`` with a call to your own reader.

    yara-gate conform --export kit
    python docs/examples/conform_agreement.py kit > extraction.jsonl
    yara-gate conform --agreement extraction.jsonl > agreement.jsonl

Commit ``agreement.jsonl`` and compare it after every extractor change and every gate pin
bump. The fixtures are inert, but they are written like attacks: keep the export out of
any folder an agent reads.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

SKIPPED = {"script", "style", "noscript", "template"}


class _TextNodes(HTMLParser):
    """Text nodes only. An element with ``hidden`` is dropped; inline CSS is not read."""

    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self.open: list[bool] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.open.append(tag in SKIPPED or any(name == "hidden" for name, _ in attrs))

    def handle_endtag(self, tag: str) -> None:
        if self.open:
            self.open.pop()

    def handle_data(self, data: str) -> None:
        if not any(self.open) and data.strip():
            self.parts.append(data.strip())


def extract(path: Path) -> tuple[str, str] | None:
    """The reader's name and the text it takes from ``path``, or None when it has no reader."""
    if path.suffix == ".pdf" and shutil.which("pdftotext"):
        done = subprocess.run(  # noqa: S603 - a fixed argv; the fixture is this package's own
            ["pdftotext", "-q", str(path), "-"],  # noqa: S607 - poppler from PATH, as a user has it
            capture_output=True,
            timeout=30,
            check=False,
        )
        return (
            ("pdftotext", done.stdout.decode("utf-8", "replace")) if not done.returncode else None
        )
    if path.suffix == ".html":
        reader = _TextNodes()
        reader.feed(path.read_bytes().decode("utf-8", "replace"))
        return "text-nodes", " ".join(reader.parts)
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: conform_agreement.py EXPORT_DIR", file=sys.stderr)
        return 2
    kit = Path(argv[0])
    for line in (kit / "fixtures.jsonl").read_text(encoding="utf-8").splitlines():
        item = json.loads(line)
        taken = extract(kit / item["path"])
        if taken is None:
            continue
        reader, text = taken
        print(
            json.dumps(
                {
                    "source_id": item["id"],
                    "channel": "extraction",
                    "text": text,
                    "original_sha256": item["sha256"],
                    "extractor": reader,
                    "extractor_version": "example",
                }
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
