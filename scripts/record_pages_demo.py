"""Record the public demo's results by running the real scanner on fixed inert inputs.

Run from the repository root in the locked environment:

    uv run python scripts/record_pages_demo.py --output web-demo/recordings.json

Every input is a fixed, inert byte string from ``yara_gate.showcase``, the catalog the
loopback workbench also scans: detections, the benign near-twins paired with them, and one
failure. Each is scanned in memory with ``scan_bytes`` against a disposable
copy of ``rules/local`` and ``rules/rules.lock`` (bundled rules only, no vendor packs, no
network). The failure case uses its own copy with one deliberately invalid rule file. Each
expected verdict is asserted before anything is written, and only the fields the
Pages builder allowlists are kept: no input text, matched bytes, paths, namespaces, or
timings. The scanner sources must match ``HEAD`` so the recorded revision is the code that
ran.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from yara_gate.models import exit_code
from yara_gate.scanner import scan_bytes
from yara_gate.showcase import CASES, POLICIES

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_pages import FINDING_KEYS, RESULT_KEYS, validate_recordings  # noqa: E402

# A change under any of these paths changes what the scanner reports.
SCANNER_INPUTS = ("src", "rules/local", "rules/rules.lock", "pyproject.toml", "uv.lock")


def git(*args: str) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise SystemExit("refusing: git is needed to record the source revision")
    # Fixed read-only subcommands from this script; no scanned input reaches the command line.
    return subprocess.run(  # noqa: S603
        [executable, *args], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()


def source_revision() -> str:
    dirty = git("status", "--porcelain", "--", *SCANNER_INPUTS)
    if dirty:
        raise SystemExit(
            "refusing: scanner sources differ from HEAD, so no revision describes them:\n" + dirty
        )
    return git("rev-parse", "HEAD")


def rules_copy(parent: Path, *, broken: bool) -> Path:
    root = parent / ("broken" if broken else "bundled")
    shutil.copytree(ROOT / "rules" / "local", root / "local")
    shutil.copy2(ROOT / "rules" / "rules.lock", root / "rules.lock")
    if broken:
        (root / "local" / "zz_demo_broken.yar").write_text("not a rule\n", encoding="utf-8")
    return root


def curated(result: Any) -> dict[str, Any]:
    data = {k: v for k, v in result.model_dump().items() if k in RESULT_KEYS}
    data["findings"] = [{k: v for k, v in f.items() if k in FINDING_KEYS} for f in data["findings"]]
    data["exit_code"] = exit_code(result)
    return data


# Fields that say which scanner produced a record, not what it decided. A deploy re-records and
# may refresh them; any other difference is a changed public outcome that needs a reviewed commit.
PROVENANCE = frozenset({"source_revision", "captured_at"})
RESULT_PROVENANCE = frozenset(
    {"ruleset_sha256", "compiled_rules", "engine_version", "tool_version"}
)


def outcomes(data: dict[str, Any]) -> dict[str, Any]:
    """The dataset without provenance: what the page claims each input produced."""
    view = {key: value for key, value in data.items() if key not in PROVENANCE}
    view["cases"] = [
        {
            **case,
            "results": {
                policy: {k: v for k, v in result.items() if k not in RESULT_PROVENANCE}
                for policy, result in case["results"].items()
            },
        }
        for case in data["cases"]
    ]
    return view


def _flatten(value: Any, path: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        flat: dict[str, Any] = {}
        for key, item in value.items():
            flat.update(_flatten(item, f"{path}/{key}"))
        return flat or {path: {}}
    if isinstance(value, list):
        flat = {}
        for index, item in enumerate(value):
            label = item.get("id", index) if isinstance(item, dict) else index
            flat.update(_flatten(item, f"{path}[{label}]"))
        return flat or {path: []}
    return {path: value}


def outcome_changes(fresh: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    """Paths whose reviewed outcome differs between a fresh recording and the baseline."""
    new, old = _flatten(outcomes(fresh)), _flatten(outcomes(baseline))
    return sorted(path for path in new.keys() | old.keys() if new.get(path) != old.get(path))


def record() -> dict[str, Any]:
    revision = source_revision()
    cases = []
    with tempfile.TemporaryDirectory(prefix="yara-gate-pages-") as tmp:
        roots = {flag: rules_copy(Path(tmp), broken=flag) for flag in (False, True)}
        for case in CASES:
            results = {}
            for policy, verdict in zip(POLICIES, case.expected, strict=True):
                result = scan_bytes(
                    case.payload, name=case.name, rules_dir=roots[case.broken], policy=policy
                )
                if result.verdict.value != verdict:
                    observed = result.verdict.value
                    raise SystemExit(f"refusing: {case.id}/{policy} is {observed}, not {verdict}")
                if (result.incomplete_reason is not None) != (verdict == "incomplete"):
                    raise SystemExit(f"refusing: {case.id}/{policy} completeness changed")
                if not case.broken and result.skipped_rule_files:
                    raise SystemExit(f"refusing: {case.id}/{policy} skipped rule files")
                results[policy] = curated(result)
            cases.append(
                {
                    "id": case.id,
                    "kind": case.kind,
                    "channel": case.channel,
                    "pair": case.pair,
                    "title": case.title,
                    "description": case.description,
                    "results": results,
                }
            )
    data = {
        "schema": 2,
        "source_revision": revision,
        "captured_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "cases": cases,
    }
    validate_recordings(data)
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--output", type=Path, required=True, help="recordings JSON to write")
    parser.add_argument(
        "--baseline",
        type=Path,
        help="reviewed recordings the fresh outcomes must match; only provenance may differ",
    )
    args = parser.parse_args()
    output = args.output
    recording = record()
    if args.baseline is not None:
        try:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            validate_recordings(baseline)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"refusing: invalid baseline {args.baseline}: {exc}") from None
        changes = outcome_changes(recording, baseline)
        if changes:
            shown = "\n  ".join(changes[:12])
            more = f"\n  (+{len(changes) - 12} more)" if len(changes) > 12 else ""
            raise SystemExit(
                f"refusing: recorded outcomes differ from {args.baseline} at:\n  {shown}{more}\n"
                "Re-record locally, review the public JSON, and commit it before publishing."
            )
        print(f"Outcomes match the reviewed baseline {args.baseline}; only provenance refreshed")
    output.write_text(json.dumps(recording, indent=2) + "\n", encoding="utf-8")
    rules = {c["results"]["default"]["compiled_rules"] for c in recording["cases"]} - {0}
    print(
        f"Recorded {len(recording['cases'])} scenarios x {len(POLICIES)} policies "
        f"at {recording['source_revision'][:12]} ({', '.join(map(str, sorted(rules)))} rules) "
        f"into {output}"
    )
