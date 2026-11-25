"""Score the gate on a labelled web-page benchmark, one read rule per row.

The input is a Parquet file with a ``content`` column (the page, as raw HTML) and a
``label`` column (``yes`` for an injected page, ``no`` for a benign one), the layout of
BrowseSafe-Bench. The script downloads nothing: fetch the split yourself and pass its path.
Each page is scanned in memory as ``page.html`` under ``agent-ingest`` and ``agent-document``
with a disposable copy of the bundled rules, and the hold decision is ``replay.proposed_decision``.
A third row scores a candidate read rule from the same ``agent-document`` records, with no
second scan: hold an advisory or a block finding, and a note from the three phrase rules.

    uv run --with pyarrow python docs/research/probe_web_benchmark.py test.parquet \
        --records test.records.jsonl

The records file holds a digest, the label, and per policy the verdict and each finding's
rule id and severity. It never holds page text. The corpus is synthetic and fixed: a rate
here is a regression baseline for one ruleset, not an attack-prevention rate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import shutil
import statistics
import sys
import tempfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Any

POLICIES = ("agent-ingest", "agent-document")
# A note from one of these is held by the candidate read rule; every other note is recorded.
PHRASE_RULES = frozenset(
    {
        "agent_override_imperative",
        "agent_prompt_injection_multilingual",
        "agent_prompt_injection_phrases",
    }
)
HIDDEN_RULES = frozenset({"agent_hidden_html", "heuristic_hidden_text"})
IDENTITY = (
    "ruleset_sha256",
    "detector_sha256",
    "engine_version",
    "tool_version",
    "compiled_rules",
    "skipped_rule_files",
)
_RULES: Path | None = None


def _start(rules: str) -> None:
    global _RULES
    _RULES = Path(rules)


def scan_page(page: tuple[str, str]) -> dict[str, Any]:
    """One page under both policies: digests, verdicts, rule ids, and decisions. No text."""
    from yara_gate.replay import COMPLETE, TRUNCATED, ShadowScan, proposed_decision
    from yara_gate.report import compact_report
    from yara_gate.scanner import scan_bytes

    content, label = page
    data = content.encode("utf-8", "surrogatepass")
    digest = hashlib.sha256(data).hexdigest()
    row: dict[str, Any] = {"sha256": digest, "bytes": len(data), "label": label, "policies": {}}
    for policy in POLICIES:
        report = dict(
            compact_report(scan_bytes(data, name="page.html", rules_dir=_RULES, policy=policy))
        )
        scan = ShadowScan(
            status=TRUNCATED if report["verdict"] == "incomplete" else COMPLETE,
            status_reason=report["incomplete_reason"],
            sha256=digest,
            record=report,
            wall_seconds=0.0,
        )
        row["policies"][policy] = {
            "identity": {key: report[key] for key in IDENTITY},
            "verdict": report["verdict"],
            "incomplete_reason": report["incomplete_reason"],
            "decision": proposed_decision(scan, policy),
            "findings": sorted({(f["rule_id"], f["severity"]) for f in report["findings"]}),
            "scan_seconds": report["scan_seconds"],
        }
    # Keep the common identity for existing records consumers only when both scans agree.
    first, second = (row["policies"][policy]["identity"] for policy in POLICIES)
    row["identity"] = first if first == second else None
    return row


def candidate_holds(record: dict[str, Any]) -> bool:
    """The candidate read rule, from an ``agent-document`` record."""
    if record["verdict"] == "incomplete":
        return True
    return any(
        severity in ("advisory", "block") or rule in PHRASE_RULES
        for rule, severity in record["findings"]
    )


def wilson(hits: int, total: int) -> tuple[float, float]:
    """The 95% Wilson interval for ``hits`` of ``total``, in percent."""
    z = 1.959964
    p = hits / total
    centre = p + z * z / (2 * total)
    spread = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))
    low, high = (centre - spread) / (1 + z * z / total), (centre + spread) / (1 + z * z / total)
    return (100 * max(low, 0.0), 100 * min(high, 1.0))


def _rate(hits: int, total: int) -> str:
    if not total:
        return "n/a (no pages with this label)"
    low, high = wilson(hits, total)
    share = 100 * hits / total
    return f"{hits:,} of {total:,}, {share:.1f}% ({low:.1f} to {high:.1f})"


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    from yara_gate.replay import _identified

    attack = [row for row in rows if row["label"] == "yes"]
    benign = [row for row in rows if row["label"] == "no"]
    records = [row["policies"][policy] for row in rows for policy in POLICIES]
    identities = sorted({json.dumps(record["identity"], sort_keys=True) for record in records})
    unidentified = sum(not _identified(record["identity"]) for record in records)
    incomplete = sum(record["verdict"] == "incomplete" for record in records)
    summary = {
        "pages": len(rows),
        "attack": len(attack),
        "benign": len(benign),
        "identities": identities,
        "incomplete": incomplete,
        "unidentified": unidentified,
    }
    if incomplete or unidentified or len(identities) != 1:
        return summary
    rules: dict[str, Any] = {}
    for name in (*POLICIES, "candidate"):
        policy = "agent-document" if name == "candidate" else name

        def held(row: dict[str, Any], policy: str = policy, name: str = name) -> bool:
            record = row["policies"][policy]
            return candidate_holds(record) if name == "candidate" else record["decision"] == "hold"

        hit, false = sum(map(held, attack)), sum(map(held, benign))
        causes = Counter(
            "+".join(sorted({rule for rule, _ in row["policies"][policy]["findings"]})) or "none"
            for row in benign
            if held(row)
        )
        rules[name] = {
            "attack_held": hit,
            "benign_held": false,
            "precision": round(100 * hit / (hit + false), 1) if hit + false else None,
            "benign_hold_causes": causes.most_common(8),
        }

    def hidden(row: dict[str, Any]) -> bool:
        return any(
            rule in HIDDEN_RULES for rule, _ in row["policies"]["agent-document"]["findings"]
        )

    seconds = sorted(row["policies"]["agent-document"]["scan_seconds"] for row in rows)
    return {
        **summary,
        "read_rules": rules,
        "hidden_html_attack": sum(map(hidden, attack)),
        "hidden_html_benign": sum(map(hidden, benign)),
        "benign_with_phrase_finding": sum(
            any(rule in PHRASE_RULES for rule, _ in row["policies"]["agent-document"]["findings"])
            for row in benign
        ),
        "scan_seconds": {
            "median": round(statistics.median(seconds), 3),
            "p95": round(seconds[int(0.95 * (len(seconds) - 1))], 3),
            "max": round(seconds[-1], 3),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("parquet", type=Path)
    parser.add_argument("--records", type=Path, help="write one JSON line per page (no text)")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, help="scan only the first N pages")
    args = parser.parse_args()
    try:
        import pyarrow.parquet as parquet
    except ImportError:
        print("needs pyarrow: uv run --with pyarrow python ...", file=sys.stderr)
        return 2
    from yara_gate.rules import shipped_local_dir

    table = parquet.read_table(args.parquet, columns=["content", "label"])
    pages = list(
        zip(table.column("content").to_pylist(), table.column("label").to_pylist(), strict=True)
    )[: args.limit]
    if not pages or (args.limit is not None and args.limit < 1):
        parser.error("select at least one page")
    for number, (content, label) in enumerate(pages, start=1):
        if not isinstance(content, str) or label not in ("yes", "no"):
            parser.error(f"row {number} requires text content and a yes/no label")
    file_digest = hashlib.sha256(args.parquet.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="yara-gate-web-") as tmp:
        rules = Path(tmp) / "rules"
        shutil.copytree(shipped_local_dir(), rules / "local")
        (rules / "vendor").mkdir()
        with ProcessPoolExecutor(args.workers, initializer=_start, initargs=(str(rules),)) as pool:
            rows = list(pool.map(scan_page, pages, chunksize=16))
    if args.records:
        with args.records.open("w", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n")
    summary = summarize(rows)
    print(f"input sha256 {file_digest}")
    print(f"pages {summary['pages']:,}: attack {summary['attack']:,}, benign {summary['benign']:,}")
    for identity in summary["identities"]:
        print(f"identity {identity}")
    print(f"incomplete scans {summary['incomplete']}")
    if "read_rules" not in summary:
        print(f"scans without usable identity {summary['unidentified']}")
        print("rates withheld: all scans must complete with one usable identity", file=sys.stderr)
        return 2
    for name, scored in summary["read_rules"].items():
        print(f"{name}:")
        print(f"  attack held  {_rate(scored['attack_held'], summary['attack'])}")
        print(f"  benign held  {_rate(scored['benign_held'], summary['benign'])}")
        precision = scored["precision"]
        display = f"{precision}%" if precision is not None else "n/a (no holds)"
        print(f"  precision    {display}")
        for cause, count in scored["benign_hold_causes"]:
            print(f"    benign cause {count:>5}  {cause}")
    print(
        "hidden-HTML finding: "
        f"attack {summary['hidden_html_attack']:,}, benign {summary['hidden_html_benign']:,}"
    )
    print(f"benign pages with a phrase finding: {summary['benign_with_phrase_finding']:,}")
    print(f"scan seconds per page (agent-document): {summary['scan_seconds']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
