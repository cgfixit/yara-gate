"""Scan installed text files with two rule trees and report every file whose findings change.

A rule edit is checked against files nobody wrote with the rules in mind: documentation,
scripts, source, and configuration already on this machine. Each file is read in place and
scanned in memory twice, once with the base rules and once with the working tree's rules.
Nothing is executed, moved, or written beside the scanned files, and vendor packs are not
loaded. The manifest holds paths, hashes, and rule ids, never file contents; read it before
sharing it, because a path can name a private file.

    uv run python docs/verification/sweep_rule_changes.py /usr/share/doc /usr/lib/python3.12

The base is ``rules/`` at ``--base-ref`` (default ``HEAD``), or a directory given with
``--base-rules``. The exit code is 1 when any file's findings differ, so an expected change
needs ``--allow-changes`` and an explanation of each file in the record.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from multiprocessing import Pool
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MAX_BYTES = 512 * 1024
# Suffixes and bare names the rules are written for. Binary formats have their own corpus.
SUFFIXES = frozenset(
    ".1 .awk .bash .bat .c .cfg .cjs .cmake .cmd .conf .css .csv .desktop .fish .gemspec .go .h "
    ".htm .html .ini .java .js .json .jsx .lock .lua .markdown .md .mjs .mk .php .pl .plist .pm "
    ".pod .ps1 .psm1 .py .rb .rs .rst .service .sh .sql .svg .tcl .toml .ts .tsx .txt .vbs .vim "
    ".xhtml .xml .yaml .yml .zsh".split()
)
NAMES = frozenset(
    "AUTHORS CHANGELOG COPYING Dockerfile INSTALL LICENSE Makefile NEWS README".split()
)
_RULES: dict[str, Path] = {}


def _copy_rules(source: Path, target: Path) -> None:
    shutil.copytree(source, target, ignore=shutil.ignore_patterns("vendor"))
    (target / "vendor").mkdir(exist_ok=True)


def _export(ref: str, target: Path) -> None:
    """Write ``rules/`` as committed at ``ref`` under ``target``."""
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is needed to read the base rules; pass --base-rules instead")
    archive = subprocess.run(  # noqa: S603 - fixed read-only argv, no shell
        [git, "archive", "--format=tar", ref, "rules"], cwd=REPO, capture_output=True, check=False
    )
    if archive.returncode != 0:
        raise SystemExit(f"cannot read rules at {ref}: {archive.stderr.decode(errors='replace')}")
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
        tar.extractall(target, filter="data")


def _start(base: str, new: str) -> None:
    """Give each worker its own disposable copy of both trees."""
    root = Path(tempfile.mkdtemp(prefix="yara-gate-sweep-"))
    for label, source in (("base", base), ("new", new)):
        _copy_rules(Path(source), root / label)
        _RULES[label] = root / label


def _scan(path: str) -> tuple[str, str, list[str], list[str]] | None:
    from yara_gate.scanner import scan_bytes

    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    found: dict[str, list[str]] = {}
    for label, rules in _RULES.items():
        result = scan_bytes(data, name=os.path.basename(path), rules_dir=rules, timeout_s=20)
        ids = sorted({item.rule_id for item in result.findings})
        if result.incomplete_reason:
            ids.append(f"incomplete:{result.incomplete_reason}")
        found[label] = ids
    return path, hashlib.sha256(data).hexdigest(), found["base"], found["new"]


def collect(roots: list[Path], limit: int) -> list[str]:
    """Regular text-like files under the roots, evenly thinned to ``limit``."""
    seen: set[tuple[int, str]] = set()
    files: list[str] = []
    for root in roots:
        for directory, subdirectories, names in os.walk(root):
            subdirectories[:] = [d for d in subdirectories if d not in {".git", "__pycache__"}]
            for name in names:
                if Path(name).suffix.lower() not in SUFFIXES and name not in NAMES:
                    continue
                path = os.path.join(directory, name)
                try:
                    status = os.lstat(path)
                except OSError:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if not 0 < status.st_size <= MAX_BYTES:
                    continue
                # Vendored copies of one file share a size and a name; one is enough.
                if (status.st_size, name) in seen:
                    continue
                seen.add((status.st_size, name))
                files.append(path)
    files.sort()
    if len(files) > limit:
        step = len(files) / limit
        files = [files[int(index * step)] for index in range(limit)]
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n", 1)[0])
    parser.add_argument("roots", nargs="+", type=Path, help="directories to read in place")
    parser.add_argument("--base-ref", default="HEAD", help="git revision of the base rules")
    parser.add_argument("--base-rules", type=Path, help="a rules directory to use as the base")
    parser.add_argument("--rules", type=Path, default=REPO / "rules", help="the rules under test")
    parser.add_argument("--output", type=Path, help="write the JSON manifest here")
    parser.add_argument("--limit", type=int, default=20000, help="most files to scan")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    parser.add_argument("--allow-changes", action="store_true", help="exit 0 on differences")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="yara-gate-sweep-base-") as directory:
        if args.base_rules is not None:
            base = args.base_rules
        else:
            _export(args.base_ref, Path(directory))
            base = Path(directory) / "rules"
        files = collect(args.roots, args.limit)
        started = time.monotonic()
        changed: list[dict[str, object]] = []
        hits: dict[str, dict[str, int]] = {"base": {}, "new": {}}
        scanned = 0
        with Pool(args.jobs, initializer=_start, initargs=(str(base), str(args.rules))) as pool:
            for row in pool.imap_unordered(_scan, files, chunksize=16):
                if row is None:
                    continue
                scanned += 1
                path, digest, before, after = row
                for label, ids in (("base", before), ("new", after)):
                    for rule_id in ids:
                        hits[label][rule_id] = hits[label].get(rule_id, 0) + 1
                if before != after:
                    changed.append({"path": path, "sha256": digest, "base": before, "new": after})
    manifest = {
        "roots": [str(root) for root in args.roots],
        "files_scanned": scanned,
        "seconds": round(time.monotonic() - started, 1),
        "files_with_changed_findings": len(changed),
        "hits_by_rule_base": dict(sorted(hits["base"].items())),
        "hits_by_rule_new": dict(sorted(hits["new"].items())),
        "changed": sorted(changed, key=lambda item: str(item["path"])),
    }
    if args.output is not None:
        args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(
        f"{scanned} files, {len(changed)} with changed findings, "
        f"{sum(hits['base'].values())} hits before and {sum(hits['new'].values())} after"
    )
    for item in manifest["changed"][:20]:
        added = sorted(set(item["new"]) - set(item["base"]))
        removed = sorted(set(item["base"]) - set(item["new"]))
        print(f"  {item['path']}: +{added} -{removed}")
    if changed and not args.allow_changes:
        sys.exit(1)


if __name__ == "__main__":
    main()
