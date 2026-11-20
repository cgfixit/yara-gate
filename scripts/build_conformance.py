"""Write the conformance manifest that ``yara-gate conform`` checks an install against.

Run it from the repository root after a change that moves a fixture or what a fixture
reports, then add a row to the change list in ``docs/conformance.md``. It scans every
fixture with a disposable copy of the bundled rules and refuses to write when a verdict
is not the one the catalog lists.

    uv run python scripts/build_conformance.py          # write
    uv run python scripts/build_conformance.py --check  # exit 1 when the file is stale
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from yara_gate import conform


def main(argv: list[str]) -> int:
    with tempfile.TemporaryDirectory(prefix="yara-gate-conform-") as tmp:
        try:
            text = conform.manifest_text(conform.build_manifest(conform.bundled_rules(Path(tmp))))
        except conform.KitError as exc:
            print(f"refusing: {exc}", file=sys.stderr)
            return 2
    target = conform.MANIFEST
    if "--check" in argv:
        current = target.read_bytes() if target.is_file() else b""
        if current != text.encode():
            print(f"stale: {target.name}; run scripts/build_conformance.py", file=sys.stderr)
            return 1
        print(f"current: {target.name}")
        return 0
    target.write_bytes(text.encode())
    print(f"wrote {target.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
