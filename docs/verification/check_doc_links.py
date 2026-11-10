"""Fail when a tracked Markdown file links to a repository path or heading that is not there.

Checks inline links, images, and reference definitions whose target is a relative path. The
target must be a tracked file or a directory holding one, compared by exact case so the result
is the same on a case-insensitive checkout. A ``#fragment`` on a Markdown target must match a
heading there, by GitHub's anchor rules, or an explicit ``id``/``name`` attribute. Links with
a scheme (``https:``, ``mailto:``) are not fetched or checked. Code blocks and code spans are
skipped. Nothing is executed.
"""

from __future__ import annotations

import posixpath
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote

REPO = Path(__file__).resolve().parents[2]

FENCE = re.compile(r"^(?P<indent> {0,3})(?P<mark>`{3,}|~{3,})")
CODE_SPAN = re.compile(r"(`+)(?!`).*?(?<!`)\1(?!`)")
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^\s<>()]+)>?(?:\s+[\"'(][^)]*)?\)")
DEFINITION = re.compile(r"^ {0,3}\[[^\]]+\]:\s+<?(\S+?)>?(?:\s|$)")
SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*:")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$")
EXPLICIT = re.compile(r"<[^>]*?\b(?:id|name)=[\"']([^\"']+)[\"']")
MARKUP = re.compile(r"!?\[((?:[^\[\]]|\[[^\[\]]*\])*)\]\([^)]*\)|<[^>]+>")
DROPPED = re.compile(r"[^\w\- ]")


def _prose(text: str) -> list[tuple[int, str]]:
    """Numbered lines outside fenced code, with code spans blanked."""
    lines: list[tuple[int, str]] = []
    closing: str | None = None
    for number, line in enumerate(text.splitlines(), 1):
        fence = FENCE.match(line)
        if closing is not None:
            if fence and fence["mark"].startswith(closing) and not line.strip().strip(closing[0]):
                closing = None
            continue
        if fence:
            closing = fence["mark"]
            continue
        lines.append((number, CODE_SPAN.sub("", line)))
    return lines


def _anchors(text: str) -> set[str]:
    """The fragments GitHub gives a Markdown file's headings, plus explicit ids."""
    found: set[str] = set()
    seen: dict[str, int] = {}
    closing: str | None = None
    for line in text.splitlines():
        fence = FENCE.match(line)
        if closing is not None:
            if fence and fence["mark"].startswith(closing) and not line.strip().strip(closing[0]):
                closing = None
            continue
        if fence:
            closing = fence["mark"]
            continue
        found.update(EXPLICIT.findall(line))
        heading = HEADING.match(line)
        if heading is None:
            continue
        title = MARKUP.sub(lambda match: match[1] or "", heading[1])
        title = title.replace("`", "").replace("*", "")
        slug = DROPPED.sub("", title.strip().lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        found.add(slug if count == 0 else f"{slug}-{count}")
    return found


def _targets(line: str) -> list[str]:
    definition = DEFINITION.match(line)
    return INLINE.findall(line) + ([definition[1]] if definition else [])


def check(files: list[str]) -> tuple[int, list[str]]:
    """Return the number of relative links checked and one message per broken link."""
    tracked = set(files)
    directories: set[str] = set()
    for name in files:
        parent = posixpath.dirname(name)
        while parent:
            directories.add(parent)
            parent = posixpath.dirname(parent)
    texts = {
        name: (REPO / name).read_text(encoding="utf-8") for name in files if name.endswith(".md")
    }
    anchors: dict[str, set[str]] = {}
    failures: list[str] = []
    checked = 0
    for name, text in sorted(texts.items()):
        for number, line in _prose(text):
            for target in _targets(line):
                if SCHEME.match(target) or target.startswith("//"):
                    continue
                checked += 1
                path, _, fragment = target.partition("#")
                path = unquote(path.split("?", 1)[0])
                if not path:
                    resolved = name
                elif path.startswith("/"):
                    resolved = posixpath.normpath(path.lstrip("/"))
                else:
                    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), path))
                where = f"{name}:{number}: {target}"
                if resolved == ".":
                    continue
                if resolved.startswith(".."):
                    failures.append(f"{where} (leaves the repository)")
                elif resolved not in tracked and resolved not in directories:
                    failures.append(f"{where} (no tracked file or directory)")
                elif fragment and resolved in texts:
                    if resolved not in anchors:
                        anchors[resolved] = _anchors(texts[resolved])
                    if unquote(fragment).lower() not in anchors[resolved]:
                        failures.append(f"{where} (no such heading in {resolved})")
    return checked, failures


def main() -> None:
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required to list tracked files")
    listed = subprocess.run(  # noqa: S603 - fixed read-only argv, no shell
        [git, "ls-files", "-z"], cwd=REPO, check=True, capture_output=True
    ).stdout.split(b"\0")
    # A file deleted in the working tree but not yet staged is still listed; drop it.
    files = [
        name for name in (raw.decode("utf-8") for raw in listed if raw) if (REPO / name).is_file()
    ]
    checked, failures = check(files)
    if failures:
        raise SystemExit("broken relative links:\n" + "\n".join(failures))
    print(f"doc link check passed ({checked} relative links)")


if __name__ == "__main__":
    main()
