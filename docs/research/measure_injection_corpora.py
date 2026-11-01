"""Measure hold rates on public prompt-injection corpora. Inert text; nothing is executed.

This script never downloads. Fetch the corpora yourself into an empty directory, then run from
the repository root:

    uv run python docs/research/measure_injection_corpora.py \\
        --llmail DIR --deepset FILE.jsonl [--candidates RULES.yar] [--json OUT]

``--llmail`` is a directory holding ``labelled_unique_submissions_phase2.json`` and
``emails_for_fp_tests.json`` from https://huggingface.co/datasets/microsoft/llmail-inject-challenge
(MIT). ``--deepset`` is a JSON Lines export (``{"text": ..., "label": 0|1}`` per line) of both
splits of https://huggingface.co/datasets/deepset/prompt-injections (Apache-2.0); its files are
parquet, so convert them once, for example with ``uv run --no-project --with pyarrow``.
``--benign-dir`` (repeatable) adds every regular file under a directory as benign text.

Each sample is scanned once with ``scan_bytes`` (message corpora as ``message.txt``, files
under ``--benign-dir`` by their own name) under the default policy against a disposable
copy of ``rules/local``. Policies are a deterministic function of the strongest finding:
agent-ingest holds any finding, agent-document holds advisory, block, and incomplete. With
``--candidates``, the research rules are also run on the raw bytes, and the union with the shipped
rules is reported. The JSON record holds counts, rule ids, and input SHA-256 values; never text.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from collections import Counter
from collections.abc import Iterable
from pathlib import Path

import yara_x

from yara_gate import scan_bytes
from yara_gate.rules import compile_ruleset, yara_x_version

REPO = Path(__file__).resolve().parents[2]
RANK = {"clean": 0, "note": 1, "advisory": 2, "block": 3, "incomplete": 4}
ATTACK, BENIGN = "attack", "benign"
# Message-shaped corpora are scanned as a chat or mail body would be.
MESSAGE = "message.txt"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def llmail_sets(directory: Path) -> Iterable[tuple[str, str, list[tuple[str, bytes]]]]:
    labelled = json.loads((directory / "labelled_unique_submissions_phase2.json").read_text())
    groups: dict[str, list[tuple[str, bytes]]] = {}
    for text, label in labelled.items():
        attempt, reason = str(label.get("attack_attempt")), label.get("reason")
        category = str(label.get("judge_category") or "").lower()
        if reason == "api_triggered":
            key = "llmail_api_triggered"
        elif attempt == "True" and category == "direct instructions":
            key = "llmail_direct_instructions"
        elif attempt == "True" and "obfuscation" in category:
            key = "llmail_obfuscation"
        elif attempt == "Unclear" and category == "social engineering":
            key = "llmail_social_engineering_unclear"
        else:
            continue
        groups.setdefault(key, []).append((MESSAGE, text.encode("utf-8", "surrogatepass")))
    for key, items in groups.items():
        yield key, ATTACK, items
    emails = json.loads((directory / "emails_for_fp_tests.json").read_text())
    yield "llmail_benign_fp_emails", BENIGN, [(MESSAGE, text.encode()) for text in emails]


def deepset_sets(path: Path) -> Iterable[tuple[str, str, list[tuple[str, bytes]]]]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    for label, key, kind in ((1, "deepset_injection", ATTACK), (0, "deepset_benign", BENIGN)):
        items = [(MESSAGE, r["text"].encode()) for r in rows if int(r["label"]) == label]
        yield key, kind, items


def tier(result: object) -> str:
    if getattr(result, "incomplete_reason", None):
        return "incomplete"
    best = "clean"
    for finding in getattr(result, "findings", []):
        if RANK[finding.severity.value] > RANK[best]:
            best = finding.severity.value
    return best


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--llmail", type=Path)
    parser.add_argument("--deepset", type=Path)
    parser.add_argument("--benign-dir", type=Path, action="append", default=[])
    parser.add_argument("--candidates", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    sets: list[tuple[str, str, list[tuple[str, bytes]]]] = []
    inputs: dict[str, str] = {}
    if args.llmail:
        sets.extend(llmail_sets(args.llmail))
        for name in ("labelled_unique_submissions_phase2.json", "emails_for_fp_tests.json"):
            inputs[f"llmail/{name}"] = sha256(args.llmail / name)
    if args.deepset:
        sets.extend(deepset_sets(args.deepset))
        inputs[f"deepset/{args.deepset.name}"] = sha256(args.deepset)
    for directory in args.benign_dir:
        files = sorted(p for p in directory.rglob("*") if p.is_file() and not p.is_symlink())
        # The real file name, so suffix-based type checks behave as they do for a caller.
        items = [(p.name, p.read_bytes()) for p in files]
        sets.append((f"benign_dir:{directory.name}", BENIGN, items))
    if not sets:
        parser.error("give at least one corpus")
    candidates = None
    if args.candidates:
        candidates = yara_x.Scanner(yara_x.compile(args.candidates.read_text()))
    summary: dict[str, dict[str, object]] = {}
    with tempfile.TemporaryDirectory(prefix="yara-gate-corpora-") as directory:
        rules = Path(directory) / "rules"
        shutil.copytree(REPO / "rules/local", rules / "local")
        shutil.copy(REPO / "rules/rules.lock", rules / "rules.lock")
        _rules, _skipped, error, compiled, skipped, _fingerprint = compile_ruleset(rules)
        if error:
            raise SystemExit(f"rules did not compile: {error}")
        for name, kind, items in sets:
            tiers: Counter[str] = Counter()
            shipped: Counter[str] = Counter()
            research: Counter[str] = Counter()
            research_any = union = 0
            for label, data in items:
                result = scan_bytes(data, name=label, rules_dir=rules)
                level = tier(result)
                tiers[level] += 1
                shipped.update({finding.rule_id for finding in result.findings})
                if candidates is not None:
                    hits = {rule.identifier for rule in candidates.scan(data).matching_rules}
                    research.update(hits)
                    research_any += bool(hits)
                    union += bool(hits) or level != "clean"
            total = len(items)
            held_ingest = total - tiers["clean"]
            held_document = tiers["advisory"] + tiers["block"] + tiers["incomplete"]
            row: dict[str, object] = {
                "kind": kind,
                "n": total,
                "tiers": dict(tiers),
                "held_agent_ingest_pct": round(100 * held_ingest / total, 2),
                "held_agent_document_pct": round(100 * held_document / total, 2),
                "shipped_rules": shipped.most_common(),
            }
            if candidates is not None:
                row["candidate_any_pct"] = round(100 * research_any / total, 2)
                row["union_any_pct"] = round(100 * union / total, 2)
                row["candidate_rules"] = research.most_common()
            summary[name] = row
            extra = ""
            if candidates is not None:
                extra = f" candidates={row['candidate_any_pct']}% union={row['union_any_pct']}%"
            print(
                f"{name:36} {kind:6} n={total:6} ingest={row['held_agent_ingest_pct']}% "
                f"document={row['held_agent_document_pct']}%{extra}"
            )
    record = {
        "source": "docs/research/measure_injection_corpora.py",
        "yara_x": yara_x_version(),
        "python": sys.version.split()[0],
        "compiled_rules": compiled,
        "skipped_files": skipped,
        "candidates": str(args.candidates) if args.candidates else None,
        "inputs_sha256": inputs,
        "sets": summary,
    }
    if args.json:
        args.json.write_text(json.dumps(record, indent=1) + "\n")


if __name__ == "__main__":
    main()
