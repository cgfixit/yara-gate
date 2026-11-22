"""Decide whether a main commit may be published to GitHub Pages.

The demo-results-page workflow runs this with a read-only token before it builds anything. It allows
only the newest commit on main, and only once every other check on that commit has finished
green: the ci workflow, CodeQL, and any other check suite. The ci run and a CodeQL analysis
of the commit must both be there and have passed; a commit that either never ran on is not
green. It fails closed: a red, cancelled, or timed-out check, a missing one, an API error, or
a check still running at the deadline stops the deploy.
A commit that main has already moved past is skipped, since the newer commit deploys itself.

Usage (in the workflow): GH_TOKEN=... python3 scripts/pages_deploy_gate.py --sha <sha>
    --repo <owner/name> --run-id <this run's id>
The run id keeps the gate from waiting on its own still-running jobs.
Writes ``deploy=true`` or ``deploy=false`` and the validated ``sha`` to $GITHUB_OUTPUT when that
variable is set.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.request
from collections.abc import Callable
from typing import Any

API = "https://api.github.com"
SELF = ".github/workflows/demo-results-page.yml"
CI = ".github/workflows/ci.yml"
# CodeQL runs through GitHub's default setup, which has no workflow file in the repository.
# Its runs carry this path, on a push, a schedule, and a pull request alike.
CODEQL = "dynamic/github-code-scanning/codeql"
GREEN = frozenset({"success", "skipped", "neutral"})
PAGE = 100
MAX_PAGES = 10

Fetch = Callable[[str], Any]


def evaluate(
    runs: list[dict[str, Any]], checks: list[dict[str, Any]], own_run_id: int | None = None
) -> tuple[str, list[str]]:
    """Classify every check on the commit outside this workflow: green, pending, or red.

    ``runs`` are the commit's workflow runs and ``checks`` its check runs, as the REST API
    returns them. The ci workflow must have run on the push and passed, and a CodeQL analysis
    of the commit on main must have finished with success. Without the second rule a commit
    CodeQL never ran on had nothing red and nothing pending, and was green.
    """
    own_suites = {run.get("check_suite_id") for run in runs if run.get("path") == SELF}
    own_runs = {run.get("id") for run in runs if run.get("path") == SELF} | {own_run_id} - {None}

    def ours(check: dict[str, Any]) -> bool:
        if (check.get("check_suite") or {}).get("id") in own_suites:
            return True
        url = check.get("details_url") or ""
        return any(f"/actions/runs/{run_id}/" in url for run_id in own_runs)

    ci = [run for run in runs if run.get("path") == CI and run.get("event") == "push"]
    if not ci:
        return "pending", ["ci has not reported on this commit's push yet"]
    latest_ci = max(ci, key=lambda run: (run.get("run_number", 0), run.get("run_attempt", 0)))
    if latest_ci.get("status") != "completed":
        return "pending", [f"ci: {latest_ci.get('status')}"]
    if latest_ci.get("conclusion") != "success":
        return "red", [f"ci: {latest_ci.get('conclusion')}"]
    others = [check for check in checks if not ours(check)]
    red = [
        f"{check.get('name')}: {check.get('conclusion')}"
        for check in others
        if check.get("status") == "completed" and check.get("conclusion") not in GREEN
    ]
    if red:
        return "red", red
    pending = [
        f"{check.get('name')}: {check.get('status')}"
        for check in others
        if check.get("status") != "completed"
    ]
    if pending:
        return "pending", pending
    # Last, so a failed analysis is reported by its own check above, as red. What is left is
    # an analysis that never started, or one cancelled before it made a check.
    analysed = any(
        run.get("path") == CODEQL
        and run.get("head_branch") == "main"
        and run.get("status") == "completed"
        and run.get("conclusion") == "success"
        for run in runs
    )
    if not analysed:
        return "pending", ["CodeQL has not passed on this commit"]
    return "green", [str(check.get("name")) for check in others]


def _github(token: str) -> Fetch:
    def fetch(path: str) -> Any:
        request = urllib.request.Request(  # noqa: S310 - fixed https API origin
            API + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "User-Agent": "yara-gate-pages-gate",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
            return json.load(response)

    return fetch


def _all(fetch: Fetch, path: str, key: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        batch = fetch(f"{path}{'&' if '?' in path else '?'}per_page={PAGE}&page={page}")[key]
        items.extend(batch)
        if len(batch) < PAGE:
            return items
    raise SystemExit(f"refusing: more than {PAGE * MAX_PAGES} {key} to evaluate")


def decide(
    fetch: Fetch,
    repo: str,
    sha: str,
    *,
    run_id: int | None,
    timeout: float,
    interval: float,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> bool:
    """True to deploy ``sha``, False to skip a superseded commit; SystemExit stops the deploy."""
    deadline = clock() + timeout
    while True:
        head = fetch(f"/repos/{repo}/commits/main")["sha"]
        if head != sha:
            print(f"skip: main is now {head[:12]}, newer than {sha[:12]}; that commit deploys")
            return False
        runs = _all(fetch, f"/repos/{repo}/actions/runs?head_sha={sha}", "workflow_runs")
        checks = _all(fetch, f"/repos/{repo}/commits/{sha}/check-runs", "check_runs")
        state, details = evaluate(runs, checks, run_id)
        if state == "green":
            print(f"deploy {sha[:12]}: every other check passed ({len(details)})")
            return True
        if state == "red":
            raise SystemExit(f"refusing: a check on {sha[:12]} did not pass: {'; '.join(details)}")
        if clock() >= deadline:
            raise SystemExit(
                f"refusing: checks still running at the deadline: {'; '.join(details)}"
            )
        print(f"waiting: {'; '.join(details[:5])}")
        sleep(interval)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--sha", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--run-id", type=int, required=True, help="this workflow run's id")
    parser.add_argument("--timeout", type=float, default=1200.0, help="seconds to wait for checks")
    parser.add_argument("--interval", type=float, default=15.0)
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.sha) is None:
        raise SystemExit("refusing: --sha must be a full commit id")
    if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo) is None:
        raise SystemExit("refusing: --repo must be owner/name")
    token = os.environ.get("GH_TOKEN", "")
    if not token:
        raise SystemExit("refusing: GH_TOKEN is required")
    try:
        deploy = decide(
            _github(token),
            args.repo,
            args.sha,
            run_id=args.run_id,
            timeout=args.timeout,
            interval=args.interval,
        )
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"refusing: could not read the checks: {type(exc).__name__}") from None
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            # The validated full commit id is what the build checks out and deploys.
            handle.write(f"deploy={'true' if deploy else 'false'}\nsha={args.sha}\n")


if __name__ == "__main__":
    main()
