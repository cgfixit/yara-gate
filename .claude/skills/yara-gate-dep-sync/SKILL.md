---
name: yara-gate-dep-sync
description: Check and sync yara-gate's dependencies - the Python packages in pyproject.toml and uv.lock, the YARA-X engine, the pinned GitHub Actions and build tools, open Dependabot pull requests, and the vendor rule-pack pins. Use when asked to update, bump, refresh, audit, or sync dependencies, to review or reconcile a Dependabot pull request, to upgrade YARA-X, to look for outdated or vulnerable packages, or to explain why the lock and pyproject disagree, even when the word "dependency" is never used. It starts read-only and reports before it changes a lock.
argument-hint: "[package, tier, or Dependabot PR number]"
---

# Sync yara-gate dependencies

In a scanner, a dependency is part of the verdict. A YARA-X release can change what a rule
matches. A parser release changes what a reader sees. `detector_sha256` covers the versions of
the packages in `_DETECTOR_PACKAGES` (`src/yara_gate/scanner.py`), so a bump to one of them makes
every consumer's cached admission stale. A lock change is therefore reviewed like a detection
change, with evidence, and is never taken because a newer number exists.

`AGENTS.md` holds the contracts; this file restates none. The ones a dependency change reaches:
Python 3.12 and the locked environment, no global YARA engine in place of the locked YARA-X,
vendor downloads only with explicit scope, and no hosted check disabled to make a change pass.

## 1. Read the state

```sh
uv sync --frozen --group dev
uv run python .claude/skills/yara-gate-dep-sync/scripts/dep_state.py
uv lock --check
uv tree --frozen --outdated --depth 1 --group dev
```

`dep_state.py` reads only this checkout: the Python version in each file that names it, every
direct dependency with its bound, locked version, and upload date, the pinned Actions, the
actionlint build pin, the vendor pack pins, the packaged paths, and each living document that
names the engine version. It exits 1 when two files that must agree do not. `uv tree --outdated`
asks the index which releases are newer.

Then list the open pull requests and find Dependabot's (`dependabot/uv/...`,
`dependabot/github_actions/...`). Where one already carries a bump, that pull request is the
vehicle: review it and verify it rather than opening a second one for the same package.

`uv audit --frozen` is experimental and queries `api.osv.dev`. Run it. If the host is blocked,
report that the audit did not run. A check that could not run is never recorded as clean.

## 2. Sort by what the package can change

| Tier | Packages | What a bump can change | Evidence before it merges |
| --- | --- | --- | --- |
| Engine | `yara-x` | Matches, regex acceptance, the compiled-rule cache, the match cap | Section 4 |
| Scan-path parsers | `oletools`, `olefile`, `pyyaml` | What a reader sees in Office, OLE, and YAML input | `probe_rule_coverage.py --verify`, `probe_detection_gaps.py --verify`, `measure_precision.py --fail-over`, `scripts/record_pages_demo.py --baseline web-demo/recordings.json` |
| Runtime | `typer`, `platformdirs`, `pydantic`, `watchdog` | The CLI surface, the user data and cache paths, the demo's request model, the watcher | `yara-gate --help` and each command's `--help` compared with the base, `check_scan_only.py`, `check_intake.py`; the watcher tests run in the macOS job only, so a `watchdog` bump is not verified until that job is green |
| Dev tools | `ruff`, `mypy`, `pytest`, `zizmor` | New lint or type findings | Run each. Fix a new finding; do not pin the tool back or add a `noqa` to hide it |
| Actions and build tools | The `uses:` pins, actionlint | What runs with the repository's token | Section 5 |
| Vendor rule packs | `rules/rules.lock` | What blocks | Report the pins and stop. `rules update` runs only when the maintainer asks, in a disposable tree first |

## 3. Report before changing anything

Give one table: package, bound, locked, newest, the newest release's upload date, tier, and what
you recommend. Take the upload date from the package index (`https://pypi.org/pypi/<name>/json`) rather than from memory.

`.github/dependabot.yml` waits seven days after a release before it proposes one, because a
freshly uploaded release is where a compromised upload lands. Hold a manual bump to the same
wait unless an advisory or the maintainer says otherwise, and say which it was in the record.

Ask the maintainer before a major version, an engine bump, a change to a bound in
`pyproject.toml`, a release inside the wait, a Python version change, or a vendor pin. One
question, at most three options, the recommended one first and labeled, each with why and what
it costs.

## 4. Change the lock

- One tier per pull request, so a behaviour change can be traced to one package:
  `uv lock --upgrade-package <name>`. A bare `uv lock --upgrade` moves everything at once and is
  for the maintainer to request.
- Leave the bounds in `pyproject.toml` alone unless the code now needs the newer release.
- Never edit `uv.lock` by hand. Afterwards run `uv sync --frozen --group dev`, `uv lock --check`,
  and `dep_state.py` again.

For the engine, compare the base and the new release on the same inputs and keep both columns:

| Check | What must hold |
| --- | --- |
| `docs/verification/lint_rules.py` | The same compiled count, no new warning |
| `check_rule_pairs.py`, `check_added_rules.py` | The same pass counts |
| `measure_precision.py --fail-over` | Identical per-rule counts |
| `docs/research/probe_match_cap.py` | No blind spot. `MATCH_LIMIT` in `rules.py` assumes the engine records 1,000,000 matches a string; read the release for a change to that constant |
| `docs/verification/check_worst_case_timing.py` | Under the ceiling |
| `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | Outcomes match the reviewed recordings |

A vendor-pack comparison across engines needs the packs, which needs the maintainer's say and a
disposable rules root. Without it, state that vendor rules were not compared. The
[November 6 engine record](../../../docs/verification/2026-11-06-yara-x-1.23.0.md) is the model
for the whole comparison.

## 5. Actions and build tools

Every `uses:` is pinned to a commit with the version in a trailing comment; change both
together and read the action's release notes for the versions in between. The actionlint commit
appears twice in `ci.yml`, in the cache key and in `go install`, and the Go version comes from
actionlint's `go.mod` at that commit. Then run actionlint v1.7.12 and
`uv run zizmor --offline --pedantic .github`. The deploy workflow's name, path, and the gate
script refer to each other; `AGENTS.md` lists them.

## 6. Documents and the record

`dep_state.py` lists each living document that names the engine version. A line that reports a
measurement belongs to its date: measure again or leave it dated, never just swap the number.
Search `README.md`, `user-guide.md`, `docs/`, and `rules/README.md` for the old version.

Add `docs/verification/YYYY-MM-DD-dependency-refresh.md`: the base SHA, a before and after
table, the commands with what they printed, whether `uv audit` ran, and what the record does
not claim (a vulnerability audit that did not run, a performance change that was not measured).

## 7. Deliver

Title `[deps] - summary`. Open a draft, follow CI on the pushed head, and read the Windows job
too: it runs with other wheels and without `O_NOFOLLOW`. Merging is the maintainer's call.
