"""In-place scans that must behave the same on Linux, macOS, and Windows.

CI runs this on all three. It uses no inbox intake, symlinks, or watcher: those need
POSIX no-follow opens and link counts. Inputs are inert and are not executed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from yara_gate.samples import EICAR, clean_text, eicar_bytes, injection_markdown
from yara_gate.scanner import scan_file

REPO = Path(__file__).resolve().parents[2]
UNSUPPORTED_7Z = b"7z\xbc\xaf\x27\x1c" + bytes(32)

# name, payload, policy, verdict, exit code
CASES = [
    ("notes.txt", clean_text(), "default", "clean", 0),
    ("eicar.com", eicar_bytes(), "default", "block", 1),
    ("note.md", injection_markdown(), "default", "advisory", 0),
    ("note.md", injection_markdown(), "agent-ingest", "block", 1),
    ("invoice.pdf.exe", b"inert text\n", "default", "block", 1),
    ("\u06af\u0632\u0627\u0631\u0634.txt", clean_text(), "default", "clean", 0),
    ("archive.7z", UNSUPPORTED_7Z, "default", "incomplete", 2),
]


def _cli() -> str:
    found = shutil.which("yara-gate", path=str(Path(sys.executable).parent))
    if found is None:
        raise SystemExit("yara-gate console script is not next to this interpreter")
    return found


def _scan(path: Path, home: Path, rules: Path, policy: str) -> tuple[int, list[dict[str, object]]]:
    command = [_cli(), "scan", str(path), "--home", str(home), "--rules", str(rules)]
    command += ["--policy", policy, "--json"]
    done = subprocess.run(command, capture_output=True, check=False)  # noqa: S603
    records = [json.loads(line) for line in done.stdout.decode("utf-8").splitlines()]
    return done.returncode, records


def main() -> None:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="yara-gate-scan-only-") as directory:
        root = Path(directory)
        rules = root / "rules"
        shutil.copytree(REPO / "rules" / "local", rules / "local")
        home = root / "gate"
        for index, (name, payload, policy, verdict, code) in enumerate(CASES):
            folder = root / "inputs" / str(index)
            folder.mkdir(parents=True)
            path = folder / name
            path.write_bytes(payload)
            library = scan_file(path, rules_dir=rules, policy=policy)
            returned, records = _scan(path, home, rules, policy)
            got = records[0]["verdict"] if len(records) == 1 else f"{len(records)} records"
            label = f"{name} {policy}"
            if library.verdict.value != verdict:
                failures.append(f"{label}: library {library.verdict.value}, want {verdict}")
            if returned != code or got != verdict:
                failures.append(f"{label}: cli {got}/{returned}, want {verdict}/{code}")
            if path.read_bytes() != payload:
                failures.append(f"{label}: input changed or moved")
        returned, records = _scan(root / "inputs", home, rules, "default")
        if returned != 2 or len(records) != len(CASES):
            failures.append(f"folder: exit {returned} with {len(records)} records, want 2")
        reports = list((home / "reports").glob("*.json"))
        if not reports:
            failures.append("no reports written")
        for report in (home / "reports").iterdir():
            if EICAR.decode() in report.read_text(encoding="utf-8", errors="replace"):
                failures.append(f"{report.name} contains the matched EICAR bytes")
        for folder in ("inbox", "quarantine", "clean", "blocked"):
            if any((home / folder).iterdir()):
                failures.append(f"in-place scans wrote into {folder}/")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"scan-only checks passed ({len(CASES)} cases, {sys.platform})")


if __name__ == "__main__":
    main()
