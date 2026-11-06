"""The Pages deploy gate and the recorder's baseline guard must fail closed."""

import copy
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gate = _load("pages_deploy_gate")


def _run(run_id: int, path: str, conclusion: str | None = "success", status: str = "completed"):
    return {
        "id": run_id,
        "path": path,
        "event": "push",
        "status": status,
        "conclusion": conclusion,
        "check_suite_id": run_id * 10,
        "run_number": 1,
        "run_attempt": 1,
    }


def _check(name: str, conclusion: str | None = "success", run_id: int = 1) -> dict:
    status = "completed" if conclusion else "in_progress"
    url = f"https://github.com/o/r/actions/runs/{run_id}/job/1"
    return {
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "check_suite": {"id": run_id * 10},
        "details_url": url,
    }


RUNS = [
    _run(1, gate.CI),
    _run(2, "dynamic/github-code-scanning/codeql"),
    _run(9, gate.SELF, None, "in_progress"),
]


def test_gate_waits_on_everything_but_itself() -> None:
    own = _check("Deploy gate (main only)", None, run_id=9)
    assert gate.evaluate(RUNS, [_check("check", run_id=1), own], 9)[0] == "green"
    assert gate.evaluate(RUNS, [_check("Analyze (python)", None, run_id=2), own], 9)[0] == "pending"


@pytest.mark.parametrize("conclusion", ["failure", "cancelled", "timed_out", "action_required"])
def test_gate_refuses_any_non_green_check(conclusion: str) -> None:
    state, details = gate.evaluate(RUNS, [_check("CodeQL", conclusion, run_id=2)], 9)
    assert state == "red" and details == [f"CodeQL: {conclusion}"]


def test_gate_requires_ci_to_have_passed_on_the_push() -> None:
    assert gate.evaluate(RUNS[1:], [], 9)[0] == "pending"
    assert gate.evaluate([_run(1, gate.CI, "failure")], [], 9)[0] == "red"


def test_gate_skips_a_commit_main_has_moved_past() -> None:
    def fetch(path: str) -> dict:
        assert path.endswith("/commits/main"), path
        return {"sha": "b" * 40}

    assert gate.decide(fetch, "o/r", SHA, run_id=9, timeout=0, interval=0) is False


def test_baseline_guard_allows_provenance_and_refuses_outcomes() -> None:
    recorder = _load("record_pages_demo")
    baseline = json.loads((ROOT / "web-demo" / "recordings.json").read_text(encoding="utf-8"))
    fresh = copy.deepcopy(baseline)
    fresh["source_revision"] = "c" * 40
    for case in fresh["cases"]:
        for result in case["results"].values():
            result["compiled_rules"] += 1
            result["engine_version"] = "9.9.9"
    assert recorder.outcome_changes(fresh, baseline) == []
    note = next(case for case in fresh["cases"] if case["id"] == "note")
    note["results"]["agent-document"]["verdict"] = "block"
    assert recorder.outcome_changes(fresh, baseline) == [
        "/cases[note]/results/agent-document/verdict"
    ]
