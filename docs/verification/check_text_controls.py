"""Fail when a tracked text file contains a bidi or invisible control character.

Escapes such as a backslash-u sequence can be decoded into the real character on the way
into a file. ZWNJ and ZWJ are allowed: Persian and Indic text uses them. Nothing is executed.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

from yara_gate.filetype import name_has_controls

REPO = Path(__file__).resolve().parents[2]


def main() -> None:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required to list tracked files")
    listed = subprocess.run(  # noqa: S603 - fixed read-only argv, no shell
        [git, "ls-files", "-z"], cwd=REPO, check=True, capture_output=True
    ).stdout.split(b"\0")
    failures: list[str] = []
    checked = 0
    for raw in filter(None, listed):
        path = REPO / raw.decode("utf-8")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        checked += 1
        for number, line in enumerate(text.splitlines(), 1):
            if name_has_controls(line):
                points = sorted({f"U+{ord(c):04X}" for c in line if name_has_controls(c)})
                failures.append(f"{raw.decode()}:{number}: {', '.join(points)}")
    if failures:
        raise SystemExit("bidi or invisible controls found:\n" + "\n".join(failures))
    print(f"text control check passed ({checked} files)")


if __name__ == "__main__":
    sys.exit(main())
