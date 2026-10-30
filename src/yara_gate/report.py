"""SARIF 2.1.0 and a compact JSON verdict. Matched bytes are never stored."""

import json
import os
import secrets
from pathlib import Path

from yara_gate import __version__
from yara_gate.models import Finding, ScanResult, exit_code


def write_reports(
    report_dir: Path, result: ScanResult, *, stem: str | None = None
) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    digest = stem or result.sha256 or "0" * 64
    sarif_path = report_dir / f"{digest}.sarif"
    json_path = report_dir / f"{digest}.json"
    _replace_text(sarif_path, json.dumps(_sarif(result), indent=2) + "\n")
    _replace_text(json_path, json.dumps(compact_report(result), indent=2) + "\n")
    return sarif_path, json_path


def _replace_text(path: Path, text: str) -> None:
    # A reader polling the directory sees the previous report or the new one, never part of one.
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def redact(path: str) -> str:
    home = str(Path.home()).rstrip(os.sep) or os.sep
    if path == home:
        return "~"
    if home != os.sep and path.startswith(home + os.sep):
        return "~" + path[len(home) :]
    return path


def compact_report(result: ScanResult) -> dict[str, object]:
    """Return the shared JSON report schema, without matched bytes or home prefixes."""
    return {
        "sha256": result.sha256,
        "verdict": result.verdict.value,
        "advisory": result.advisory,
        "exit_code": exit_code(result),
        "incomplete_reason": result.incomplete_reason,
        "path": redact(result.path),
        "ruleset_sha256": result.ruleset_sha256,
        "engine_version": result.engine_version,
        "skipped_rule_files": result.skipped_rule_files,
        "policy": result.policy.value,
        "policy_reason": result.policy_reason,
        "compiled_rules": result.compiled_rules,
        "tool_version": result.tool_version,
        "scan_seconds": result.scan_seconds,
        "units_scanned": result.units_scanned,
        "views_scanned": result.views_scanned,
        "bytes_scanned": result.bytes_scanned,
        "yara_seconds": result.yara_seconds,
        "findings": [_finding(item) for item in result.findings],
    }


def _finding(item: Finding) -> dict[str, object]:
    return {
        "rule_id": item.rule_id,
        "offset": item.offset,
        "length": item.length,
        "severity": item.severity.value,
        "source": item.source.value,
        "member_path": item.member_path,
        "view": item.view,
        "namespace": item.namespace,
    }


def _sarif(result: ScanResult) -> dict[str, object]:
    rules = []
    seen: set[str] = set()
    results = []
    for item in result.findings:
        if item.rule_id not in seen:
            seen.add(item.rule_id)
            rules.append(
                {
                    "id": item.rule_id,
                    "shortDescription": {"text": item.rule_id},
                }
            )
        region: dict[str, int] = {}
        if item.offset is not None and not item.member_path and item.view == "raw":
            region["byteOffset"] = item.offset
        if item.length is not None and not item.member_path and item.view == "raw":
            region["byteLength"] = item.length
        results.append(
            {
                "ruleId": item.rule_id,
                "level": "error" if item.severity.value == "block" else "warning",
                "message": {"text": item.rule_id},
                "properties": _finding(item),
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": redact(result.path)},
                            "region": region,
                        }
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "yara-gate",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "ruleset_sha256": result.ruleset_sha256,
                    "engine_version": result.engine_version,
                    "skipped_rule_files": result.skipped_rule_files,
                    "compiled_rules": result.compiled_rules,
                    "scan_seconds": result.scan_seconds,
                    "units_scanned": result.units_scanned,
                    "views_scanned": result.views_scanned,
                    "bytes_scanned": result.bytes_scanned,
                    "yara_seconds": result.yara_seconds,
                    "verdict": result.verdict.value,
                    "policy": result.policy.value,
                    "policy_reason": result.policy_reason,
                    "incomplete_reason": result.incomplete_reason,
                },
            }
        ],
    }
