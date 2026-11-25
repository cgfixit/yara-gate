"""Reconcile three paired Harness replays with the frozen task list and capture receipts."""

import argparse
import json
import sys
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from yara_gate.replay import _DIGEST, _IDENTITY, COMPLETE, SCHEMA_VERSION, _identified, _unique

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


def replay(
    path: Path,
    policy: str,
    index: dict[str, tuple[str, str, str]],
    tasks: dict[str, tuple[str, str]],
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


def reconcile(manifest: Path, runs: list[list[Path]]) -> dict[str, object]:
    tasks = task_manifest(manifest)
    identity: dict[str, Any] = {}
    item_counts: list[dict[str, int]] = []
    for number, (receipt_file, ingest_file, document_file) in enumerate(runs, 1):
        stage = "receipts"
        try:
            index = receipts(receipt_file, tasks)
            stage = POLICIES[0]
            ingest, ingest_identity = replay(ingest_file, stage, index, tasks)
            stage = POLICIES[1]
            document, document_identity = replay(document_file, stage, index, tasks)
            stage = "comparison"
            if ingest != document:
                raise ValueError("paired replay input provenance differs")
            if ingest_identity != document_identity or (identity and identity != ingest_identity):
                raise ValueError("scanner identity differs across paired replays or runs")
            identity = ingest_identity
        except ValueError as exc:
            raise ValueError(f"run {number} ({stage}): {exc}") from None
        item_counts.append(dict(Counter(tasks[task][0] for task, _, _ in index.values())))
    return {
        "scanner": identity,
        "tasks_by_split": {
            split: dict(Counter(label for label, group in tasks.values() if group == split))
            for split in SPLITS
        },
        "items_by_label_per_run": item_counts,
    }


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
    args = parser.parse_args()
    if len(args.run) != 3:
        parser.error("supply exactly three --run groups")
    try:
        result = reconcile(args.manifest, args.run)
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
