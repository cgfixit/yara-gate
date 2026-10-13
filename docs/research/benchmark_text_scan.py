"""Measure real scans of inert text with a disposable rules tree (no network)."""

import hashlib
import importlib.metadata
import json
import shutil
import statistics
import tempfile
import time
from pathlib import Path

from yara_gate import scanner
from yara_gate.rules import compile_sources


def main() -> None:
    source = Path(scanner.__file__).resolve().parents[2]
    line = "Ordinary meeting notes, numbers 123, and punctuation.\n"
    text = (line * (4 * 1024 * 1024 // len(line) + 1))[: 4 * 1024 * 1024]
    cases = {
        "ascii.txt": text.encode(),
        "utf16.txt": text.encode("utf-16"),
        "entities.html": text.replace("and", "&amp;").encode(),
    }
    output: dict[str, object] = {
        "source": str(source),
        "engine": importlib.metadata.version("yara-x"),
        "cases": [],
    }
    rows = []
    with tempfile.TemporaryDirectory(prefix="yara-text-benchmark-") as temporary:
        root = Path(temporary)
        rules = root / "rules"
        shutil.copytree(source / "rules/local", rules / "local")
        _, skipped, error, compiled, _ = compile_sources(rules)
        if error or skipped or not compiled:
            raise RuntimeError("local rule compilation failed")
        for name, data in cases.items():
            target = root / name
            target.write_bytes(data)
            times = []
            results = []
            for _ in range(3):
                start = time.perf_counter()
                result = scanner.scan_file(target, rules_dir=rules)
                times.append(time.perf_counter() - start)
                if result.verdict.value != "clean":
                    raise RuntimeError(f"unexpected verdict for {name}")
                results.append(result.model_dump(exclude={"path"}))
            if results[1:] != results[:-1]:
                raise RuntimeError("inconsistent scan results")
            rows.append(
                {
                    "case": name,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "seconds": times,
                    "median_seconds": statistics.median(times),
                    "result": results[0],
                }
            )
    output["cases"] = rows
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
