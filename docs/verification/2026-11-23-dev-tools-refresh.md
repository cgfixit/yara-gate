# Dev tool refresh: Ruff 0.17.6 and zizmor 1.33.1 (2026-11-23)

Source: `main` at `bdd0fa4`, branch `claude/deps-dev-tools`. Linux x86_64, Python 3.12. One
command, written with uv 0.13.9 (the version that wrote the lock, `revision = 5`):
`uvx uv@0.13.9 lock --upgrade-package ruff --upgrade-package zizmor`. Both are in the `dev`
group, so nothing a consumer installs moves, and `detector_sha256` does not change.

| Package | Bound | Before | After | Uploaded |
| --- | --- | --- | --- | --- |
| ruff | `>=0.6` | 0.17.5 | 0.17.6 | 2026-11-19 |
| zizmor | `>=1.32` | 1.32.0 | 1.33.1 | 2026-11-22 |

Both are inside the seven-day Dependabot wait; the maintainer chose to bump every tier now.
zizmor 1.33.1 was less than a day old when locked.

## What changed upstream

**Sourced, read** (each project's changelog at its default branch, fetched 2026-11-23):

- **Ruff 0.17.6:** bug fixes to `B033`, `RUF068`, `F823`, `PLR1733`, `PLR1736`, and the
  `RUF072` fix, one preview fix, two rule changes (`SIM208` fixes, `F841` ignores
  `__traceback_hide__`), and performance work. No formatter style change is listed.
- **zizmor 1.33.0 and 1.33.1:** a new `dangerous-checkout` audit for `actions/checkout`,
  lockfile awareness in `impostor-commit` and `ref-confusion`, `dependabot-cooldown` support
  for `semver-*-days`, and parser fixes (anchors beside comments, bare `inputs:`, a `services:`
  expression).

## Checks

CI runs both tools from the lock (`ci.yml`: `uv run zizmor --offline --pedantic .github`,
`uv run ruff check .`, `uv run ruff format --check .`), so the lock is the only pin.

| Check | Before | After |
| --- | --- | --- |
| `uv run ruff check .` | All checks passed | All checks passed |
| `uv run ruff format --check .` | 309 files already formatted | 309 files already formatted |
| `uv run zizmor --offline --pedantic .github` | No findings (1 ignored) | No findings (1 ignored) |
| `uv lock --check`, `dep_state.py` | | pass, no problems |

The one ignored finding is the reviewed `dangerous-triggers` suppression on the deploy
workflow's `workflow_run` trigger (`demo-results-page.yml`), the same on both versions. The new
`dangerous-checkout` audit reports nothing on the four `actions/checkout` steps.

## Not established

- `uv audit` did not run: `api.osv.dev` was unreachable from the session.
- zizmor ran `--offline`, as CI does; the online audits (such as `impostor-commit` against the
  GitHub API) were not run.
