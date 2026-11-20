"""The consumer conformance kit behind ``yara-gate conform``.

A consumer pins a version of this package and runs the kit when the pin moves. The kit
builds the inert fixtures from this package (the demo catalog of ``showcase.py`` and a few
of its own), checks each against the SHA-256 the packaged manifest records, scans it under
every policy with the bundled rules alone, and compares the verdict and exit code with the
manifest. A changed verdict or exit fails; a changed rule id or view is printed and passes.

Agreement mode adds the consumer's own reader: a capture, in the format ``replay`` reads,
of the text that reader took from each fixture. Each line is scanned in a child process by
the replay core and set beside the scan of the fixture file, so a finding the extraction
lost, or gained, is visible. Nothing here is executed, fetched, admitted, or moved.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from yara_gate import samples, showcase
from yara_gate.models import ScanPolicy
from yara_gate.replay import COMPLETE, FAILED, TRUNCATED, ShadowScan, proposed_decision

SCHEMA_VERSION = 1
POLICIES = showcase.POLICIES
MANIFEST = Path(__file__).with_name("conformance.json")
EXPORT_INDEX = "fixtures.jsonl"
_EXITS = {"clean": 0, "advisory": 0, "block": 1, "incomplete": 2}
# What a consumer may gate on, and what is printed for information only.
_HARD = ("verdict", "exit_code")
_SOFT = ("incomplete_reason", "rule_ids", "views", "pdf_content_unread")


class KitError(Exception):
    """The kit could not run. The message names a fixture or a file, never its content."""


@dataclass(frozen=True, slots=True)
class Fixture:
    """One inert input and the verdict each policy must give it, in ``POLICIES`` order."""

    id: str
    name: str
    kind: str
    channel: str
    pair: str | None
    payload: bytes
    expected: tuple[str, str, str]

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


def _own() -> tuple[Fixture, ...]:
    # The integration guide tells a consumer to send a PDF with a non-empty
    # ``pdf_content_unread`` to its own extractor; this pair lets it test that route.
    return (
        Fixture(
            "kit_pdf_unread",
            "scan.pdf",
            "detection",
            "Document",
            "kit_pdf_read",
            samples.pdf_unread_content(),
            showcase.NOTE,
        ),
        Fixture(
            "kit_pdf_read",
            "scan.pdf",
            "control",
            "Document",
            "kit_pdf_unread",
            samples.pdf_read_content(),
            showcase.CLEAN,
        ),
    )


def fixtures() -> tuple[Fixture, ...]:
    """Every fixture of the kit: the demo catalog, less its broken-rule case, then the kit's own."""
    catalog = tuple(
        Fixture(c.id, c.name, c.kind, c.channel, c.pair, c.payload, c.expected)
        for c in showcase.CASES
        if not c.broken
    )
    return catalog + _own()


def bundled_rules(parent: Path) -> Path:
    """A disposable rules root under ``parent`` that holds the shipped local rules only."""
    from yara_gate.rules import shipped_local_dir

    root = parent / "rules"
    try:
        shutil.copytree(shipped_local_dir(), root / "local")
        (root / "vendor").mkdir()
    except OSError as exc:
        raise KitError("bundled rules missing") from exc
    return root


def observe(fixture: Fixture, policy: str, rules_dir: Path | None) -> dict[str, Any]:
    """Scan one fixture and keep what the manifest records, plus the full compact report."""
    from yara_gate.report import compact_report
    from yara_gate.scanner import scan_bytes

    result = scan_bytes(fixture.payload, name=fixture.name, rules_dir=rules_dir, policy=policy)
    report: dict[str, Any] = dict(compact_report(result))
    found = report["findings"]
    return {
        "verdict": report["verdict"],
        "exit_code": report["exit_code"],
        "incomplete_reason": report["incomplete_reason"],
        "rule_ids": sorted({item["rule_id"] for item in found}),
        "views": sorted({item["view"] for item in found if item["view"]}),
        "pdf_content_unread": report["pdf_content_unread"],
        "report": report,
    }


def _expectation(seen: dict[str, Any]) -> dict[str, Any]:
    return {key: seen[key] for key in _HARD + _SOFT}


def build_manifest(rules_dir: Path) -> dict[str, Any]:
    """Scan every fixture and return the manifest. Refuses a verdict the catalog does not list."""
    entries = []
    for fixture in fixtures():
        expected = {}
        for policy, verdict in zip(POLICIES, fixture.expected, strict=True):
            seen = observe(fixture, policy, rules_dir)
            report = seen["report"]
            if seen["verdict"] != verdict or seen["exit_code"] != _EXITS[verdict]:
                raise KitError(f"{fixture.id}/{policy} is {seen['verdict']}, not {verdict}")
            if (seen["incomplete_reason"] is not None) != (verdict == "incomplete"):
                raise KitError(f"{fixture.id}/{policy} completeness changed")
            if report["skipped_rule_files"]:
                raise KitError(f"{fixture.id}/{policy} skipped a bundled rule file")
            expected[policy] = _expectation(seen)
        entries.append(
            {
                "id": fixture.id,
                "name": fixture.name,
                "kind": fixture.kind,
                "channel": fixture.channel,
                "pair": fixture.pair,
                "source": "kit" if fixture.id.startswith("kit_") else "showcase",
                "sha256": fixture.sha256,
                "bytes": len(fixture.payload),
                "expected": expected,
            }
        )
    return {"schema_version": SCHEMA_VERSION, "policies": list(POLICIES), "fixtures": entries}


def manifest_text(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def load_manifest(path: Path = MANIFEST) -> tuple[dict[str, Any], str]:
    """The packaged manifest and the SHA-256 of its bytes."""
    try:
        raw = path.read_bytes()
        manifest = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise KitError("manifest missing or unreadable") from exc
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema_version") != SCHEMA_VERSION
        or manifest.get("policies") != list(POLICIES)
        or not isinstance(manifest.get("fixtures"), list)
    ):
        raise KitError("manifest is not this kit's")
    return manifest, hashlib.sha256(raw).hexdigest()


def checked_fixtures(manifest: dict[str, Any]) -> dict[str, tuple[Fixture, dict[str, Any]]]:
    """Each fixture beside its manifest entry, once its bytes are the ones the manifest names."""
    entries = {entry["id"]: entry for entry in manifest["fixtures"]}
    built = {fixture.id: fixture for fixture in fixtures()}
    if set(entries) != set(built):
        odd = sorted(set(entries) ^ set(built))
        raise KitError(f"fixture list changed: {', '.join(odd[:5])}")
    for fixture in built.values():
        entry = entries[fixture.id]
        if entry["sha256"] != fixture.sha256 or entry["name"] != fixture.name:
            raise KitError(f"fixture changed: {fixture.id}")
    return {key: (built[key], entries[key]) for key in entries}


@dataclass(slots=True)
class Section:
    """One pass over the kit: what was compared and what differed."""

    name: str
    checks: int = 0
    mismatches: int = 0
    differences: int = 0
    unfinished: int = 0
    identity: dict[str, Any] | None = None


def _identity(report: dict[str, Any]) -> dict[str, Any]:
    keys = ("ruleset_sha256", "detector_sha256", "engine_version", "tool_version", "compiled_rules")
    return {key: report[key] for key in keys}


def compare(
    kit: dict[str, tuple[Fixture, dict[str, Any]]],
    rules_dir: Path | None,
    section: Section,
    seen_by: dict[tuple[str, str], dict[str, Any]] | None = None,
) -> Iterator[dict[str, Any]]:
    """Scan the kit with ``rules_dir`` and yield one record per fixture and policy that differs.

    ``mismatch`` is a changed verdict or exit code. ``difference`` is a changed rule id, view,
    or unread count under the same verdict. The pass stops at the first scan that gives no
    answer where one was recorded: rules that do not compile fail every scan the same way,
    and each would compile them again.
    """
    for fixture, entry in kit.values():
        for policy in POLICIES:
            seen = observe(fixture, policy, rules_dir)
            if seen_by is not None:
                seen_by[fixture.id, policy] = seen
            section.checks += 1
            section.identity = section.identity or _identity(seen["report"])
            want = entry["expected"][policy]
            hard = any(seen[key] != want[key] for key in _HARD)
            if not hard and all(seen[key] == want[key] for key in _SOFT):
                continue
            if hard:
                section.mismatches += 1
                # No answer is not a changed answer: the kit did not finish.
                if seen["verdict"] == "incomplete":
                    section.unfinished += 1
            else:
                section.differences += 1
            was, now = set(want["rule_ids"]), set(seen["rule_ids"])
            yield {
                "record": "mismatch" if hard else "difference",
                "section": section.name,
                "id": fixture.id,
                "policy": policy,
                "expected": {key: want[key] for key in _HARD},
                "observed": {key: seen[key] for key in _HARD},
                "incomplete_reason": seen["incomplete_reason"],
                "rule_ids_missing": sorted(was - now),
                "rule_ids_added": sorted(now - was),
                "views_missing": sorted(set(want["views"]) - set(seen["views"])),
                "views_added": sorted(set(seen["views"]) - set(want["views"])),
                "pdf_content_unread": seen["pdf_content_unread"],
            }
            if section.unfinished:
                return


def _side(report: dict[str, Any] | None, decision: str) -> dict[str, Any]:
    found = report["findings"] if report else []
    return {
        "verdict": report["verdict"] if report else None,
        "decision": decision,
        "rule_ids": sorted({item["rule_id"] for item in found}),
    }


def agreement(
    handle: BinaryIO,
    kit: dict[str, tuple[Fixture, dict[str, Any]]],
    seen_by: dict[tuple[str, str], dict[str, Any]],
    *,
    rules_dir: Path,
    policy: ScanPolicy = ScanPolicy.agent_document,
    timeout_s: int = 30,
    kill_after_s: float | None = None,
) -> Iterator[dict[str, Any]]:
    """One record per capture line: the scan of the extraction beside the scan of its fixture.

    ``source_id`` names the fixture. ``result`` is ``same`` when both sides give the same
    decision with the same rule ids, ``findings-differ`` when only the ids differ,
    ``file-holds-only`` or ``extraction-holds-only`` when the decisions differ, and
    ``failed`` when the line gave no record to compare.
    """
    from yara_gate.replay import replay_capture

    for envelope in replay_capture(
        handle,
        policy=policy,
        rules_dir=rules_dir,
        timeout_s=timeout_s,
        kill_after_s=kill_after_s,
        timings=False,
    ):
        gate = envelope["gate"]
        record: dict[str, Any] = {
            "record": "agreement",
            "line": envelope["line"],
            "id": envelope["source_id"],
            "policy": envelope["policy"],
            "extractor": envelope["extractor"],
            "extractor_version": envelope["extractor_version"],
            "text_sha256": envelope["text_sha256"],
            "text_bytes": envelope["text_bytes"],
            "status": envelope["status"],
            "status_reason": envelope["status_reason"],
            "result": "failed",
            "file": None,
            "extraction": _side(gate, envelope["proposed_decision"]),
            "only_in_file": [],
            "only_in_extraction": [],
        }
        known = kit.get(envelope["source_id"] or "")
        if envelope["status"] == FAILED:
            yield record
            continue
        if known is None:
            yield {**record, "status": FAILED, "status_reason": "unknown fixture"}
            continue
        fixture, _ = known
        original = envelope["original_sha256"]
        if original is not None and original != fixture.sha256:
            yield {**record, "status": FAILED, "status_reason": "extraction is of other bytes"}
            continue
        report = seen_by[fixture.id, envelope["policy"]]["report"]
        whole = ShadowScan(
            status=TRUNCATED if report["verdict"] == "incomplete" else COMPLETE,
            status_reason=report["incomplete_reason"],
            sha256=fixture.sha256,
            record=report,
            wall_seconds=0.0,
        )
        file_side = _side(report, proposed_decision(whole, envelope["policy"]))
        text_side = record["extraction"]
        in_file, in_text = set(file_side["rule_ids"]), set(text_side["rule_ids"])
        if file_side["decision"] != text_side["decision"]:
            result = (
                "file-holds-only" if file_side["decision"] == "hold" else "extraction-holds-only"
            )
        else:
            result = "same" if in_file == in_text else "findings-differ"
        yield {
            **record,
            "result": result,
            "file": file_side,
            "only_in_file": sorted(in_file - in_text),
            "only_in_extraction": sorted(in_text - in_file),
        }


def export(target: Path) -> int:
    """Write every fixture to ``target/<id>/<name>`` with an index. Returns the count written."""
    try:
        if target.exists() and (not target.is_dir() or any(target.iterdir())):
            raise KitError("export directory is not empty")
        target.mkdir(parents=True, exist_ok=True)
        lines = []
        for fixture in fixtures():
            folder = target / fixture.id
            folder.mkdir()
            (folder / fixture.name).write_bytes(fixture.payload)
            lines.append(
                json.dumps(
                    {
                        "id": fixture.id,
                        "path": f"{fixture.id}/{fixture.name}",
                        "sha256": fixture.sha256,
                        "bytes": len(fixture.payload),
                        "kind": fixture.kind,
                        "channel": fixture.channel,
                        "pair": fixture.pair,
                    },
                    separators=(",", ":"),
                    ensure_ascii=True,
                )
            )
        (target / EXPORT_INDEX).write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError as exc:
        raise KitError(f"export failed ({exc.__class__.__name__})") from exc
    return len(lines)


def _vendor_installed(root: Path) -> bool:
    """True when ``root`` records a vendor inventory and every recorded file is present."""
    from yara_gate.rules import installed_inventory

    try:
        installed = installed_inventory(root)
    except (OSError, ValueError):
        return False
    if not installed:
        return False
    return all((root / "vendor" / name).is_file() for name in installed)


def _counts(section: Section) -> dict[str, Any]:
    return {
        "checks": section.checks,
        "mismatches": section.mismatches,
        "differences": section.differences,
        **(section.identity or {}),
    }


def run(
    capture: BinaryIO | None = None,
    *,
    rules: Path | None = None,
    policy: ScanPolicy = ScanPolicy.agent_document,
    timeout_s: int = 30,
) -> Iterator[dict[str, Any]]:
    """The whole kit: every record that differs, each agreement record, then one summary.

    The bundled section decides ``result``: ``pass``, ``fail`` for a changed verdict or exit
    code, ``incomplete`` when a scan gave no answer or a capture line gave no record. The
    installed section runs only when ``rules`` (or the default rules tree) records installed
    vendor packs, and is reported without changing ``result``.
    """
    from yara_gate.rules import default_rules_dir

    manifest, digest = load_manifest()
    kit = checked_fixtures(manifest)
    bundled, installed = Section("bundled"), None
    seen_by: dict[tuple[str, str], dict[str, Any]] = {}
    results: dict[str, int] = {}
    with tempfile.TemporaryDirectory(prefix="yara-gate-conform-") as tmp:
        root = bundled_rules(Path(tmp))
        yield from compare(kit, root, bundled, seen_by)
        if not bundled.unfinished and not (bundled.identity or {}).get("compiled_rules"):
            raise KitError("bundled rules missing")
        tree = rules or default_rules_dir()
        if _vendor_installed(tree):
            installed = Section("installed")
            yield from compare(kit, tree, installed)
        if capture is not None:
            for record in agreement(
                capture, kit, seen_by, rules_dir=root, policy=policy, timeout_s=timeout_s
            ):
                results[record["result"]] = results.get(record["result"], 0) + 1
                yield record
    if bundled.unfinished or results.get("failed"):
        result = "incomplete"
    else:
        result = "fail" if bundled.mismatches else "pass"
    yield {
        "record": "summary",
        "schema_version": SCHEMA_VERSION,
        "result": result,
        "fixtures": len(kit),
        "policies": list(POLICIES),
        "manifest_sha256": digest,
        "bundled": _counts(bundled),
        "installed": _counts(installed) if installed else None,
        "agreement": dict(sorted(results.items())) if capture is not None else None,
    }


def headline(summary: dict[str, Any]) -> str:
    """One line for a person: the result and the counts behind it."""
    bundled = summary["bundled"]
    return (
        f"CONFORM {summary['result'].upper()}: {summary['fixtures']} fixtures, "
        f"{bundled['checks']} checks, {bundled['mismatches']} changed verdicts, "
        f"{bundled['differences']} changed findings"
    )
