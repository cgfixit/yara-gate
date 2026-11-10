"""Validate the curated demo and copy only its public files into a fresh artifact."""

import argparse
import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parents[1] / "web-demo"
POLICIES = {"default", "agent-ingest", "agent-document"}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; "
    "form-action 'none'; base-uri 'none'; object-src 'none'"
)
RESULT_KEYS = {
    "verdict",
    "sha256",
    "advisory",
    "note",
    "incomplete_reason",
    "findings",
    "policy",
    "policy_reason",
    "compiled_rules",
    "skipped_rule_files",
    "engine_version",
    "tool_version",
    "ruleset_sha256",
    "units_scanned",
    "views_scanned",
    "bytes_scanned",
    "exit_code",
}
FINDING_KEYS = {"rule_id", "offset", "length", "severity", "source", "view", "member_path"}
CASE_KEYS = {"id", "kind", "channel", "pair", "title", "description", "results"}
SCENARIOS = 70
KINDS = {"detection", "control", "failure"}
PAIRED = {"detection", "control"}
CHANNELS = {
    "Message",
    "SMS",
    "Tool result",
    "Web page",
    "Document",
    "Model file",
    "Repository",
    "Attachment",
    "Rules",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class PageCheck(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: list[str] = []
        self.csp = False
        self.referrer = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        require(
            tag not in {"form", "input", "textarea", "iframe", "object", "embed"},
            f"Unexpected content-entry or embedding element: {tag}",
        )
        require(not any(key.startswith("on") for key in values), "Inline event handler")
        if tag == "meta" and values.get("http-equiv") == "Content-Security-Policy":
            require(values.get("content") == CSP, "Unexpected demo CSP")
            self.csp = True
        if tag == "meta" and values.get("name") == "referrer":
            self.referrer = values.get("content") == "no-referrer"
        if tag == "script":
            require(values.get("type") == "module", "Scripts must be external modules")
            self.assets.append(values.get("src") or "")
        if tag == "link":
            require(values.get("rel") == "stylesheet", "Unexpected linked resource")
            self.assets.append(values.get("href") or "")
        if tag == "a":
            href = values.get("href") or ""
            require(
                href.startswith(
                    (
                        "#",
                        "https://github.com/cgfixit/yara-gate/",
                        "https://docs.github.com/en/pages/",
                    )
                ),
                "Unexpected link",
            )
            if not href.startswith("#"):
                require("noreferrer" in (values.get("rel") or ""), "Referrer on outbound link")
        require(
            not any(key in values for key in ("srcset", "action", "ping")),
            "Unexpected resource or submission attribute",
        )
        if "src" in values:
            require(tag == "script", "Unexpected resource")


def is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_recordings(data: dict[str, Any]) -> None:
    require(set(data) == {"schema", "source_revision", "captured_at", "cases"}, "Recording fields")
    require(data["schema"] == 2, "Recording schema")
    require(re.fullmatch(r"[0-9a-f]{40}", data["source_revision"]) is not None, "Source revision")
    require(
        re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00", data["captured_at"]) is not None,
        "Capture time must be UTC",
    )
    require(len(data["cases"]) == SCENARIOS, f"Expected {SCENARIOS} reviewed scenarios")
    ids = set()
    pairs = {}
    # Every completed recording must come from one ruleset, so the page never mixes revisions.
    rulesets = set()
    for case in data["cases"]:
        require(set(case) == CASE_KEYS, "Scenario fields")
        require(case["id"] not in ids, "Duplicate scenario")
        ids.add(case["id"])
        require(case["kind"] in KINDS, "Scenario kind")
        require(case["channel"] in CHANNELS, "Scenario channel")
        pairs[case["id"]] = (case["kind"], case["pair"])
        require(set(case["results"]) == POLICIES, "Policy recordings missing")
        verdicts = {policy: result["verdict"] for policy, result in case["results"].items()}
        # What each kind claims on the page must be what was recorded.
        if case["kind"] == "control":
            require(
                set(verdicts.values()) == {"clean"}
                and not any(result["findings"] for result in case["results"].values()),
                "A benign control must be clean with no findings under every policy",
            )
        elif case["kind"] == "detection":
            require(verdicts["agent-ingest"] == "block", "A detection must be held by agent-ingest")
        else:
            require(set(verdicts.values()) == {"incomplete"}, "A failure must stay incomplete")
        require(
            len({result["sha256"] for result in case["results"].values()}) == 1,
            "One scenario must record the same input under every policy",
        )
        for policy, result in case["results"].items():
            require(set(result) == RESULT_KEYS, "Response contains unreviewed fields")
            require(result["policy"] == policy, "Policy identity")
            require(
                all(
                    is_count(result[key])
                    for key in (
                        "compiled_rules",
                        "skipped_rule_files",
                        "units_scanned",
                        "bytes_scanned",
                    )
                )
                and isinstance(result["views_scanned"], dict)
                and all(
                    isinstance(view, str) and is_count(count)
                    for view, count in result["views_scanned"].items()
                )
                and isinstance(result["findings"], list),
                "Coverage counters",
            )
            if result["verdict"] != "incomplete":
                rulesets.add(
                    (
                        result["ruleset_sha256"],
                        result["compiled_rules"],
                        result["engine_version"],
                        result["tool_version"],
                    )
                )
            expected = {"clean": 0, "advisory": 0, "block": 1, "incomplete": 2}
            require(result["verdict"] in expected, "Unknown verdict")
            require(result["exit_code"] == expected[result["verdict"]], "Exit/verdict mismatch")
            require(
                (result["incomplete_reason"] is not None) == (result["verdict"] == "incomplete"),
                "Completeness mismatch",
            )
            require(
                re.fullmatch(r"[0-9a-f]{64}", result["sha256"]) is not None, "Input fingerprint"
            )
            require(policy != "agent-ingest" or result["verdict"] != "advisory", "Ingest hold")
            severities = set()
            for finding in result["findings"]:
                require(set(finding) == FINDING_KEYS, "Finding contains unreviewed fields")
                require(finding["severity"] in {"note", "advisory", "block"}, "Finding severity")
                severities.add(finding["severity"])
                require(
                    isinstance(finding["rule_id"], str)
                    and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", finding["rule_id"])
                    is not None,
                    "Rule identifier",
                )
                require(
                    all(
                        finding[key] is None or is_count(finding[key])
                        for key in ("offset", "length")
                    ),
                    "Finding position",
                )
                require(
                    all(
                        re.fullmatch(r"(?:zip|tar|gzip|mime):[0-9]+", x)
                        for x in finding["member_path"]
                    ),
                    "Member names must not be published",
                )
            complete = result["verdict"] != "incomplete"
            require(
                result["advisory"] == (complete and "advisory" in severities)
                and result["note"] == (complete and "note" in severities),
                "Severity flags must match the recorded findings",
            )
            if policy == "agent-document" and result["verdict"] == "advisory":
                require(
                    result["note"]
                    and not result["advisory"]
                    and result["findings"]
                    and all(f["severity"] == "note" for f in result["findings"])
                    and result["policy_reason"] == "agent-document records note findings",
                    "Document recording must be exactly notes-only",
                )
    require(len(rulesets) == 1, "Completed recordings must share one ruleset and runtime")
    for case_id, (kind, pair) in pairs.items():
        # The page shows every attack beside its benign twin, so every detection and every
        # control is paired; only the failure stands alone.
        require((pair is None) == (kind not in PAIRED), "Every detection and control is paired")
        if pair is None:
            continue
        # A pair joins one detection and its benign twin, and each names the other.
        require(
            pair in pairs and pairs[pair][1] == case_id and {kind, pairs[pair][0]} == PAIRED,
            "A pair must join a detection and a control that name each other",
        )


def build(output: Path) -> None:
    files = {}
    for name in ("index.html", "style.css", "app.mjs", "recordings.json"):
        path = SOURCE / name
        require(
            path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
            f"Source must be a regular single-link file: {name}",
        )
        files[name] = path.read_text(encoding="utf-8")
    page = PageCheck()
    page.feed(files["index.html"])
    require(page.csp and page.referrer, "Missing browser privacy policy")
    require(sorted(page.assets) == ["./app.mjs", "./style.css"], "Unexpected page assets")
    require(
        "@import" not in files["style.css"] and "url(" not in files["style.css"],
        "Unexpected CSS resource",
    )
    # This lint catches accidental transport/storage additions; CSP is the browser boundary.
    forbidden = (
        r"\b(fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|localStorage|sessionStorage|"
        r"innerHTML|outerHTML|eval|serviceWorker)\b"
    )
    require(re.search(forbidden, files["app.mjs"]) is None, "Unexpected script capability")
    require(
        files["app.mjs"].count("import ") == 1
        and "import recording from './recordings.mjs';" in files["app.mjs"],
        "Module imports",
    )
    data = json.loads(files["recordings.json"])
    validate_recordings(data)
    # Never copy the checkout, docs, screenshots, rule bodies, or arbitrary extra source files.
    output.mkdir(parents=True, exist_ok=False)
    for name in ("index.html", "style.css", "app.mjs"):
        (output / name).write_text(files[name], encoding="utf-8")
    (output / "recordings.mjs").write_text(
        "export default " + json.dumps(data, ensure_ascii=True) + ";\n", encoding="utf-8"
    )
    count = len(data["cases"])
    print(
        f"Built four public files in {output}; {count} scenarios / "
        f"{count * len(POLICIES)} policy recordings validated"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New, nonexistent output directory"
    )
    build(parser.parse_args().output)
