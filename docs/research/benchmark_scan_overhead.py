"""Measure what a scan costs outside the scan: process startup and per-file rule bookkeeping.

Uses inert synthetic text and rules in a disposable directory with a disposable cache and gate
home. It makes no network request and never touches the operator's gate or rules.
"""

import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

VENDOR_COUNTS = (0, 300, 800)
PROCESS_RUNS = 9
SCANS_PER_COUNT = 30


def main() -> None:
    import importlib.metadata

    source = Path(__file__).resolve().parents[2]
    output: dict[str, object] = {
        "engine": importlib.metadata.version("yara-x"),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpus": os.cpu_count(),
    }
    with tempfile.TemporaryDirectory(prefix="yara-overhead-") as temporary:
        root = Path(temporary)
        os.environ["XDG_CACHE_HOME"] = str(root / "cache")
        sample = root / "note.txt"
        sample.write_text("Ordinary meeting notes, numbers 123, and punctuation.\n")
        trees = {
            count: _rules_tree(source, root / f"rules_{count}", count) for count in VENDOR_COUNTS
        }
        output["process"] = _process_costs(root, sample, trees[0])
        output["per_file"] = _per_file_costs(sample, trees)
    print(json.dumps(output, indent=2))


def _rules_tree(source: Path, rules: Path, vendor_files: int) -> Path:
    """Copy the shipped rules and add synthetic one-rule vendor files with a recorded inventory."""
    shutil.copytree(source / "rules" / "local", rules / "local")
    names = []
    for index in range(vendor_files):
        path = rules / "vendor" / "pack" / f"r{index}.yar"
        path.parent.mkdir(parents=True, exist_ok=True)
        marker = f"synthetic-marker-{index}-zzzz"
        path.write_text(f'rule synth_{index} {{ strings: $a = "{marker}" condition: $a }}\n')
        names.append(f"pack/r{index}.yar")
    lock = {"packs": [], "installed_vendor_files": sorted(names)} if names else {"packs": []}
    (rules / "rules.lock").write_text(json.dumps(lock))
    return rules


def _process_costs(root: Path, sample: Path, rules: Path) -> dict[str, float]:
    """Wall-clock seconds for fresh processes, as a caller that shells out per file sees them."""
    exe = Path(sys.executable).with_name("yara-gate")
    scan = [
        str(exe), "scan", str(sample), "--json", "--policy", "agent-ingest",
        "--home", str(root / "home"), "--rules", str(rules),
    ]  # fmt: skip
    commands = {
        "bare_interpreter": [sys.executable, "-c", "pass"],
        "yara_gate_version": [str(exe), "--version"],
        "scan_one_file": scan,
    }
    # Compile and cache the rules once. The argv is fixed and owned, with no shell.
    subprocess.run(scan, capture_output=True, check=False)  # noqa: S603
    costs = {}
    for label, command in commands.items():
        runs = []
        for _ in range(PROCESS_RUNS):
            start = time.perf_counter()
            subprocess.run(command, capture_output=True, check=False)  # noqa: S603
            runs.append(time.perf_counter() - start)
        costs[label] = round(statistics.median(runs), 4)
    return costs


def _per_file_costs(sample: Path, trees: dict[int, Path]) -> dict[str, float]:
    """Milliseconds per scanned file, in one process, as a directory scan or `watch` pays them."""
    from yara_gate import scanner
    from yara_gate.rules import compile_sources

    costs = {}
    for count, rules in trees.items():
        _rules, _skipped, error, _compiled, skips = compile_sources(rules)
        if error or skips:
            raise RuntimeError(f"rule compilation failed for {count} vendor files")
        scanner.scan_file(sample, rules_dir=rules)  # warm the in-process compiled set
        start = time.perf_counter()
        for _ in range(SCANS_PER_COUNT):
            result = scanner.scan_file(sample, rules_dir=rules)
            if result.verdict.value != "clean":
                raise RuntimeError("unexpected verdict")
        costs[f"vendor_files_{count}"] = round(
            (time.perf_counter() - start) / SCANS_PER_COUNT * 1000, 2
        )
    return costs


if __name__ == "__main__":
    main()
