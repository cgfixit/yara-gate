"""Scan candidate files beside a control, with a disposable copy of the rules, under each policy.

    uv run python .claude/skills/yara-gate-detection-research/scripts/probe_candidate.py \
        --control caught.txt miss.txt near_miss.txt

This is the reproduction step of a detection lead: the control is an input the gate already
catches, and each candidate is an inert file you wrote (a suspected miss, or the nearest benign
text). Inputs are read as bytes and handed to `scan_bytes`; nothing is executed, moved, or
fetched, no gate home is touched, and the rules are copied to a temporary root so a scan cannot
change the tree. The output holds rule ids, severities, views, and container positions, never
matched bytes.

`--rules-from` takes another `rules/local` directory, such as the one in a worktree of the base
revision, so the same files can be read by two rule sets. `--name` sets the logical file name
for every input when the suffix under test differs from the fixture's own.

Exit 0 when the control is caught and every scan completed. Exit 2 when the control is not
caught or any scan is incomplete: an incomplete scan is a failed probe, never a miss.
"""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

POLICIES = ("default", "agent-document", "agent-ingest")


def _repo() -> Path:
    for folder in Path(__file__).resolve().parents:
        if (folder / "pyproject.toml").is_file() and (folder / "rules/local").is_dir():
            return folder
    raise SystemExit("no pyproject.toml and rules/local above this script")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("candidates", nargs="+", type=Path, help="inert files to scan")
    parser.add_argument("--control", required=True, type=Path, help="a file the gate catches")
    parser.add_argument("--rules-from", type=Path, help="a rules/local directory to copy")
    parser.add_argument("--name", help="logical file name for every input")
    parser.add_argument("--timeout", type=int, default=30, help="seconds for one scan")
    args = parser.parse_args()

    from yara_gate import scan_bytes
    from yara_gate.models import exit_code
    from yara_gate.rules import yara_x_version

    source = args.rules_from or _repo() / "rules/local"
    if not source.is_dir():
        raise SystemExit(f"{source} is not a directory")
    failed: list[str] = []
    with tempfile.TemporaryDirectory(prefix="yara-gate-candidate-") as directory:
        rules = Path(directory) / "rules"
        shutil.copytree(source, rules / "local")
        print(f"engine: YARA-X {yara_x_version()}  rules copied from: {source}")
        for role, path in [("control", args.control), *(("candidate", p) for p in args.candidates)]:
            data = path.read_bytes()
            name = args.name or path.name
            print(f"\n{role}: {path.name} ({len(data)} bytes, scanned as {name})")
            for policy in POLICIES:
                result = scan_bytes(
                    data, name=name, rules_dir=rules, timeout_s=args.timeout, policy=policy
                )
                reason = f" ({result.incomplete_reason})" if result.incomplete_reason else ""
                print(f"  {policy:15s} {result.verdict.value}{reason}  exit {exit_code(result)}")
                if policy == POLICIES[0]:
                    print(f"  {result.compiled_rules} rules compiled; findings:")
                    for item in result.findings:
                        where = "/".join(item.member_path) or "-"
                        print(f"    {item.rule_id}  {item.severity.value}  {item.view}  {where}")
                    if not result.findings:
                        print("    none")
                    if role == "control" and not result.findings:
                        failed.append("the control has no finding: check it and the rules copy")
                if result.incomplete_reason:
                    failed.append(f"{path.name} under {policy}: {result.incomplete_reason}")
    if failed:
        print("\nPROBE FAILED, nothing above is evidence of a miss:")
        for line in failed:
            print(f"  {line}")
        return 2
    print("\nprobe complete: control caught, every scan finished")
    return 0


if __name__ == "__main__":
    sys.exit(main())
