"""SARIF 2.1.0 and a compact JSON verdict. Matched bytes are never stored."""

import json
from pathlib import Path

from yara_gate import __version__
from yara_gate.models import Finding, ScanResult, exit_code


def write_reports(report_dir: Path, result: ScanResult) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    digest = result.sha256 or "0" * 64
    sarif_path = report_dir / f"{digest}.sarif"
    json_path = report_dir / f"{digest}.json"
    sarif_path.write_text(json.dumps(_sarif(result), indent=2) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(_compact(result), indent=2) + "\n", encoding="utf-8")
    return sarif_path, json_path


def redact(path: str) -> str:
    home = str(Path.home())
    if path.startswith(home):
        return "~" + path[len(home) :]
    return path


def _compact(result: ScanResult) -> dict[str, object]:
    return {
        "sha256": result.sha256,
        "verdict": result.verdict.value,
        "advisory": result.advisory,
        "exit_code": exit_code(result),
        "incomplete_reason": result.incomplete_reason,
        "path": redact(result.path),
        "findings": [_finding(item) for item in result.findings],
    }


def _finding(item: Finding) -> dict[str, object]:
    return {
        "rule_id": item.rule_id,
        "offset": item.offset,
        "length": item.length,
        "severity": item.severity.value,
        "source": item.source.value,
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
        if item.offset is not None:
            region["byteOffset"] = item.offset
        if item.length is not None:
            region["byteLength"] = item.length
        results.append(
            {
                "ruleId": item.rule_id,
                "level": "error" if item.severity.value == "block" else "warning",
                "message": {"text": item.rule_id},
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
            }
        ],
    }
