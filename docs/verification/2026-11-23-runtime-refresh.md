# Runtime dependency refresh (2026-11-23)

Source: `main` at `bdd0fa4`, branch `claude/deps-runtime-refresh`. Linux x86_64, Python 3.12,
YARA-X 1.23.0, 89 compiled local rules. One command, written with uv 0.13.9 (the version that
wrote the lock, `revision = 5`):

```sh
uvx uv@0.13.9 lock --upgrade-package platformdirs --upgrade-package pydantic \
    --upgrade-package typer --upgrade-package watchdog
```

| Package | Bound | Before | After | Uploaded |
| --- | --- | --- | --- | --- |
| platformdirs | `>=4.12.4` | 4.14.5 | 4.14.8 | 2026-11-20 |
| pydantic | `>=2.7` | 2.14.3 | 2.14.4 | 2026-11-19 |
| pydantic-core (transitive) | | 2.50.4 | 2.50.5 | with pydantic |
| typer | `>=0.12` | 0.29.1 | 0.29.2 | 2026-11-18 |
| watchdog | `>=4.0` | 7.1.0 | 7.1.1 | 2026-11-20 |

Every release is inside the seven-day Dependabot wait; the maintainer chose to bump every tier
now. None is in `_DETECTOR_PACKAGES`, so `detector_sha256` does not change. `pyproject.toml` is
unchanged.

## What changed upstream

**Sourced, read** (each project's changelog at its default branch, fetched 2026-11-23):

- **typer 0.29.2:** drops Python 3.10 and narrows upstream's test matrix. No code change listed.
- **pydantic 2.14.4:** jiter 0.19.0 (a memory fix), a JSON Schema deprecation fix, two
  performance changes. The demo's request model reads two fields.
- **platformdirs 4.14.8:** stricter checks when it *creates* directories (sticky and shared
  parents, runtime directories, root-owned site paths). The gate only reads
  `user_data_dir("yara-gate")` and `user_cache_dir("yara-gate")` (`rules.py`) and creates them
  itself, so the creation checks are not reached.
- **watchdog 7.1.1:** an `Observer.start()`/`schedule()` race fix, the observer lock released
  during dispatch, and on Linux, inotify changes: a recursive watch that hits the watch limit
  raises again, the inotify instance is allocated on the first schedule, and events read before
  a queue overflow are delivered. The watcher schedules one non-recursive watch on `inbox/`
  (`quarantine.py`).

## Checks

| Check | Before (`bdd0fa4`) | After |
| --- | --- | --- |
| `yara-gate --help` and each command's `--help`, `rules <sub> --help` | captured | identical |
| `user_data_dir`, `user_cache_dir`, `user_config_dir` for `yara-gate` | `/root/.local/share/yara-gate`, `/root/.cache/yara-gate`, `/root/.config/yara-gate` | identical |
| `check_scan_only.py` | | 7 cases passed |
| `check_intake.py` | | passed |
| `probe_rule_coverage.py --verify` | | passed |
| `yara-gate selftest` | | `SELFTEST PASS` |
| `mypy --strict src scripts` | | no issues in 34 files |
| `tests/test_demo.py` (the request model) | 7 runs, 14 passed each | 7 runs: 6 with 14 passed, 1 with `test_demo_times_out_a_body_that_stops_short` failed |
| Watcher smoke run, disposable home (below) | same placement | same placement |
| `uv lock --check`, `dep_state.py` | | pass, no problems |

The one demo failure is a race in the test, not in the dependency: `DemoHandler._send` flushes
the headers with `end_headers()` and writes the body in a second send, and the test reads one
`recv(4096)` and expects the body in it. The node passed three more times alone. It is fixed in
its own pull request.

Watcher smoke run, Linux (inotify), on both watchdog versions: `yara-gate watch --home <scratch>
--rules <copy of rules/local>`, then a benign note, an override phrase, and a directory dropped
in `inbox/`. On both, the note went to `clean/` (clean), the phrase to `clean/` (advisory under
the default policy, `agent_prompt_injection_phrases`), the directory to
`quarantine/_rejected/<time>-dir1` (incomplete, `not a regular file`), and a second watcher on
the same home exited 2 with `incomplete: watch already running`.

## Not established

- `uv audit` did not run: `api.osv.dev` was unreachable from the session. No vulnerability claim.
- The watcher tests in the suite run in the macOS job only (FSEvents); the smoke run above is
  Linux inotify. The macOS job on the pull request is the evidence for FSEvents.
- Windows was not run locally; the hosted job is the evidence.
