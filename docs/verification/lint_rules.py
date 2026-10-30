"""Compile the local pack with YARA-X and require each rule's metadata."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from yara_gate.rules import compile_sources

REPO = Path(__file__).resolve().parents[2]
_RULE = re.compile(r"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z0-9_]+)\s*\{")
_META = ("intent", "severity", "verdict_on_match", "reference")


def _blocks(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in _RULE.finditer(text):
        start = match.end()
        end = text.find("\n}", start)
        found.append((match.group(1), text[start:end]))
    return found


def main() -> None:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="yara-gate-lint-") as directory:
        rules = Path(directory) / "rules"
        shutil.copytree(REPO / "rules/local", rules / "local")
        shutil.copy2(REPO / "rules/rules.lock", rules / "rules.lock")
        _compiled, skipped, error, count, _skip_count = compile_sources(rules)
        if error or skipped:
            failures.append(f"compile failed: {error or skipped}")
        declared = 0
        for path in sorted((REPO / "rules/local").iterdir()):
            if path.suffix not in {".yar", ".yara"}:
                continue
            text = path.read_text(encoding="utf-8")
            for name, body in _blocks(text):
                declared += 1
                meta = body.split("strings:", 1)[0].split("condition:", 1)[0]
                for key in _META:
                    if f"{key} =" not in meta:
                        failures.append(f"{path.name}:{name} missing {key}")
                tiers = tuple(f'"{tier}"' for tier in ("note", "advisory", "block"))
                verdict_ok = any(f"verdict_on_match = {tier}" in meta for tier in tiers)
                severity_ok = any(f"severity = {tier}" in meta for tier in tiers)
                if not verdict_ok:
                    failures.append(f"{path.name}:{name} verdict is not note, advisory, or block")
                if not severity_ok:
                    failures.append(f"{path.name}:{name} severity is not note, advisory, or block")
                if verdict_ok and severity_ok:
                    verdict = meta.split("verdict_on_match = ", 1)[1].split('"')[1]
                    severity = meta.split("severity = ", 1)[1].split('"')[1]
                    if verdict != severity:
                        failures.append(f"{path.name}:{name} severity {severity} is not {verdict}")
        if count != declared:
            failures.append(f"compiled {count} of {declared}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"local rules compiled and linted ({declared})")


if __name__ == "__main__":
    main()
