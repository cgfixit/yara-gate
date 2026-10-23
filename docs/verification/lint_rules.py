"""Compile the local pack with YARA-X and require each rule's metadata."""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path

from yara_gate.rules import compile_sources

REPO = Path(__file__).resolve().parents[2]
_RULE = re.compile(r"(?m)^rule\s+([A-Za-z0-9_]+)\s*\{")
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
                verdict_ok = (
                    'verdict_on_match = "advisory"' in meta or 'verdict_on_match = "block"' in meta
                )
                severity_ok = 'severity = "advisory"' in meta or 'severity = "block"' in meta
                if not verdict_ok:
                    failures.append(f"{path.name}:{name} verdict is not advisory or block")
                if not severity_ok:
                    failures.append(f"{path.name}:{name} severity is not advisory or block")
        if count != declared:
            failures.append(f"compiled {count} of {declared}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"local rules compiled and linted ({declared})")


if __name__ == "__main__":
    main()
