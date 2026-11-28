"""Reconcile three paired Harness replays with the frozen task list and capture receipts."""

import argparse
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from yara_gate.replay import (
    _DIGEST,
    _IDENTITY,
    ADMIT,
    COMPLETE,
    HOLD,
    SCHEMA_VERSION,
    _identified,
    _unique,
)

POLICIES = ("agent-ingest", "agent-document")
LABEL_COUNTS = {"attack": 100, "benign": 100}
SPLITS = ("development", "locked")
CHANNELS = ("search-listing", "fetched-passages")
PROVENANCE = ("text_bytes", "original_sha256", "extractor", "extractor_version", "actual_decision")


def records(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open(encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line, object_pairs_hook=_unique)
            except (ValueError, RecursionError):
                raise ValueError(f"line {number}: invalid JSON object") from None
            if not isinstance(row, dict):
                raise ValueError(f"line {number}: expected an object")
            yield number, row


def identifier(row: dict[str, Any], field: str, line: int) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"line {line}: missing or invalid {field}")
    return value


def task_manifest(path: Path) -> dict[str, tuple[str, str]]:
    tasks: dict[str, tuple[str, str]] = {}
    sources: dict[str, set[str]] = defaultdict(set)
    families: dict[str, set[str]] = defaultdict(set)
    for line, row in records(path):
        task = identifier(row, "task_id", line)
        label = identifier(row, "label", line)
        split = identifier(row, "split", line)
        source = identifier(row, "source_group", line)
        if task in tasks or label not in LABEL_COUNTS or split not in SPLITS:
            raise ValueError(f"line {line}: duplicate task or invalid label or split")
        tasks[task] = (label, split)
        sources[source].add(split)
        if row.get("attack_family") is not None or label == "attack":
            family = identifier(row, "attack_family", line)
            families[family].add(split)
    if Counter(label for label, _ in tasks.values()) != LABEL_COUNTS:
        raise ValueError("task list must contain 100 attack and 100 benign tasks")
    if {split for _, split in tasks.values()} != set(SPLITS):
        raise ValueError("task list must contain development and locked tasks")
    if any(len(split) > 1 for split in (*sources.values(), *families.values())):
        raise ValueError("a source group or attack family crosses the evaluation split")
    return tasks


def receipts(path: Path, tasks: dict[str, tuple[str, str]]) -> dict[str, tuple[str, str, str]]:
    index: dict[str, tuple[str, str, str]] = {}
    for line, row in records(path):
        source = identifier(row, "source_id", line)
        task = identifier(row, "task_id", line)
        digest = identifier(row, "text_sha256", line)
        channel = identifier(row, "channel", line)
        if row.get("written") is not True:
            raise ValueError(f"line {line}: capture write failed or has no receipt")
        if source in index or task not in tasks or not _DIGEST.fullmatch(digest):
            raise ValueError(f"line {line}: duplicate source, unknown task, or invalid digest")
        if channel not in CHANNELS:
            raise ValueError(f"line {line}: channel outside the Harness capture scope")
        index[source] = (task, digest, channel)
    missing = tasks.keys() - {task for task, _, _ in index.values()}
    if missing:
        raise ValueError(f"{len(missing)} frozen tasks have no successful capture")
    return index


@dataclass(frozen=True, slots=True)
class Observation:
    task: str
    held: bool
    matched: bool
    scan_seconds: float
    wall_seconds: float


def seconds(value: object, line: int, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, int | float)
        or not 0 <= value <= sys.float_info.max
    ):
        raise ValueError(f"line {line}: scoring requires finite, nonnegative {field}")
    return float(value)


def observe(row: dict[str, Any], gate: dict[str, Any], task: str, line: int) -> Observation:
    decision = row.get("proposed_decision")
    findings = gate.get("findings")
    if decision not in (ADMIT, HOLD) or not isinstance(findings, list):
        raise ValueError(f"line {line}: scoring requires a decision and findings list")
    return Observation(
        task,
        decision == HOLD,
        bool(findings),
        seconds(gate.get("scan_seconds"), line, "scan_seconds"),
        seconds(row.get("wall_seconds"), line, "wall_seconds"),
    )


def rate(count: int, total: int) -> dict[str, object]:
    if total == 0:
        return {"count": count, "total": total, "rate": None, "wilson_95": None}
    # Standard Wilson score interval for a binomial proportion.
    z = statistics.NormalDist().inv_cdf(0.975)
    p = count / total
    scale = 1 + z**2 / total
    centre = (p + z**2 / (2 * total)) / scale
    radius = z * math.sqrt((p * (1 - p) + z**2 / (4 * total)) / total) / scale
    return {
        "count": count,
        "total": total,
        "rate": p,
        "wilson_95": [max(0.0, centre - radius), min(1.0, centre + radius)],
    }


def latency(values: list[float]) -> dict[str, int | float]:
    ordered = sorted(values)
    count = len(ordered)
    lower = ordered[(count - 1) // 2]
    upper = ordered[count // 2]
    return {
        "count": count,
        "p50": lower + (upper - lower) / 2,
        "p95": ordered[math.ceil(0.95 * count) - 1],
    }


def score(observations: list[Observation], tasks: dict[str, tuple[str, str]]) -> dict[str, object]:
    by_cohort: dict[str, dict[str, object]] = {}
    for split in SPLITS:
        by_cohort[split] = {}
        for label in LABEL_COUNTS:
            task_ids = {task for task, group in tasks.items() if group == (label, split)}
            items = [item for item in observations if item.task in task_ids]
            by_cohort[split][label] = {
                "items_with_findings": rate(sum(item.matched for item in items), len(items)),
                "items_with_proposed_hold": rate(sum(item.held for item in items), len(items)),
                "tasks_with_proposed_hold": rate(
                    len({item.task for item in items if item.held}), len(task_ids)
                ),
            }
    return {
        "by_cohort": by_cohort,
        "scan_seconds": latency([item.scan_seconds for item in observations]),
        "wall_seconds": latency([item.wall_seconds for item in observations]),
    }


def replay(
    path: Path,
    policy: str,
    index: dict[str, tuple[str, str, str]],
    tasks: dict[str, tuple[str, str]],
    observations: list[Observation] | None,
) -> tuple[dict[str, tuple[object, ...]], dict[str, Any]]:
    items: dict[str, tuple[object, ...]] = {}
    identity: dict[str, Any] = {}
    summary = None
    for line, row in records(path):
        if summary is not None:
            raise ValueError(f"line {line}: record after final summary")
        if type(row.get("schema_version")) is not int or row["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"line {line}: unsupported replay schema")
        if row.get("record") == "summary":
            summary = row
            continue
        if row.get("record") != "item" or row.get("status") != COMPLETE:
            raise ValueError(f"line {line}: expected a complete replay item")
        source = identifier(row, "source_id", line)
        if source in items or source not in index:
            raise ValueError(f"line {line}: duplicate source or no matching receipt")
        task, digest, channel = index[source]
        label, _ = tasks[task]
        if (row.get("text_sha256"), row.get("channel"), row.get("label")) != (
            digest,
            channel,
            label,
        ):
            raise ValueError(f"line {line}: replay differs from receipt or task label")
        gate = row.get("gate")
        if (
            not isinstance(gate, dict)
            or row.get("policy") != policy
            or gate.get("policy") != policy
            or gate.get("sha256") != digest
            or gate.get("verdict") not in ("clean", "advisory", "block")
            or gate.get("incomplete_reason") is not None
            or not _identified(gate)
        ):
            raise ValueError(f"line {line}: scan does not identify the expected input and policy")
        current = {field: gate[field] for field in _IDENTITY}
        if identity and identity != current:
            raise ValueError(f"line {line}: scanner identity changed within a replay")
        identity = current
        items[source] = (gate.get("path"), *(row.get(key) for key in PROVENANCE))
        if observations is not None:
            observations.append(observe(row, gate, task, line))
    if items.keys() != index.keys():
        raise ValueError(f"replay is missing {len(index.keys() - items.keys())} receipts")
    if (
        summary is None
        or summary.get("items") != len(items)
        or summary.get("status") != {"complete": len(items), "failed": 0, "truncated": 0}
        or summary.get("mixed_identities") is not False
        or summary.get("identities") != [identity]
    ):
        raise ValueError("missing or inconsistent final replay summary")
    return items, identity


def reconcile(
    manifest: Path, runs: list[list[Path]], *, scoring: bool = False
) -> dict[str, object]:
    tasks = task_manifest(manifest)
    identity: dict[str, Any] = {}
    item_counts: list[dict[str, int]] = []
    scores: list[dict[str, object]] = []
    for number, (receipt_file, ingest_file, document_file) in enumerate(runs, 1):
        stage = "receipts"
        try:
            index = receipts(receipt_file, tasks)
            stage = POLICIES[0]
            ingest_items: list[Observation] | None = [] if scoring else None
            ingest, ingest_identity = replay(ingest_file, stage, index, tasks, ingest_items)
            stage = POLICIES[1]
            document_items: list[Observation] | None = [] if scoring else None
            document, document_identity = replay(document_file, stage, index, tasks, document_items)
            stage = "comparison"
            if ingest != document:
                raise ValueError("paired replay input provenance differs")
            if ingest_identity != document_identity or (identity and identity != ingest_identity):
                raise ValueError("scanner identity differs across paired replays or runs")
            identity = ingest_identity
        except ValueError as exc:
            raise ValueError(f"run {number} ({stage}): {exc}") from None
        item_counts.append(dict(Counter(tasks[task][0] for task, _, _ in index.values())))
        if ingest_items is not None and document_items is not None:
            scores.append(
                {POLICIES[0]: score(ingest_items, tasks), POLICIES[1]: score(document_items, tasks)}
            )
    result: dict[str, object] = {
        "scanner": identity,
        "tasks_by_split": {
            split: dict(Counter(label for label, group in tasks.values() if group == split))
            for split in SPLITS
        },
        "items_by_label_per_run": item_counts,
    }
    if scoring:
        result["replay_scores_per_run"] = scores
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path, help="Frozen task manifest (JSONL).")
    parser.add_argument(
        "--run",
        nargs=3,
        action="append",
        metavar=("RECEIPTS", "INGEST", "DOCUMENT"),
        type=Path,
        required=True,
        help="Audit receipts with task IDs, then both strict replay outputs. Supply three runs.",
    )
    parser.add_argument(
        "--score", action="store_true", help="Score complete, timed replays after reconciliation."
    )
    args = parser.parse_args()
    if len(args.run) != 3:
        parser.error("supply exactly three --run groups")
    try:
        result = reconcile(args.manifest, args.run, scoring=args.score)
    except UnicodeError:
        print("replay reconciliation failed: input is not UTF-8", file=sys.stderr)
        return 2
    except OSError:
        print("replay reconciliation failed: could not read an input file", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"replay reconciliation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
