# Rule and watcher integrity — November 8, 2026

Phase 3 of the follow-up to [#183](https://github.com/cgfixit/yara-gate/issues/183), stacked
on Phase 2 ([consumer enforcement](2026-11-07-consumer-enforcement.md)). Base: the Phase 2 head
`c30bd23`, which contains `main` at `1497368`. Each defect was reproduced on that base before
the change. Python 3.12, YARA-X 1.23.0, 85 bundled rules, disposable rules roots, gate homes,
and `HOME`. No vendor pack was downloaded: vendor installs used synthetic archives through the
existing `transport` hook.

## Scope

| #183 item | Status before this change | This change |
| --- | --- | --- |
| 8. Watcher single instance | A PID file: check, then write | An OS lock (`flock`, or `msvcrt` on Windows) on `.watch.lock`, held for the watcher's life |
| 8. launchd | `KeepAlive` false; log directory not created | `KeepAlive: {SuccessfulExit: false}`; `install-agent` creates the log directory |
| 9. Candidate status | Any `status = "candidate"` line excluded the whole file | Only hunt's `hunt_<12 hex>.yar` files are candidates; lint flags the status elsewhere |
| 10. Vendor extraction | ZIP members flattened with silent overwrite; no expansion limit | A same-name collision, more than 20,000 rule files, or more than 300 MiB expanded raises `RuleDownloadError` and keeps the previous tree |
| 8. Oversize, dotfiles, directories | Already on `main` (AGENTS.md intake contract) | Unchanged |
| 11. Scan-event log | Open | Not in this change: a new record schema needs its own review |
| 12. actionlint tag | `go install …@v1.7.12` with the default `GOSUMDB` | Unchanged: the module is checked against sum.golang.org, as the workflow comment says, so a moved tag fails the install |

The flat vendor layout is kept on purpose. Preserving directories would change rule keys, the
vendor inventory, and the pack mapping that `rules/vendor-overrides.json` uses.

## Reproductions

| Case | Base `c30bd23` | This change |
| --- | --- | --- |
| `local/team_rules.yar`: two rules, the second with `status = "candidate"` | 85 rules compiled; the first rule's marker scans clean | 87 compiled; the marker blocks (`team_marker_one`) |
| Vendor ZIP with `a/dup.yar` and `b/dup.yar` | Installed one file, `vendor_b` silently replaced `vendor_a` | `RuleDownloadError: vendor archive has two members at dup.yar` |
| Vendor ZIP of 1,200 deflated 1 MiB rule files (about 1.2 MB downloaded) | Installed 1,200 files, 1.2 GiB on disk | `RuleDownloadError: vendor archive expands past the download cap`; staging removed |
| Two `yara-gate watch` started together on one home, 12 trials | Both alive in 2 of 12 | Exactly one alive in 12 of 12; the other exits 2 with `watch already running` |
| `.watch.pid` naming a live unrelated process (PID 1) | Refused: `watch already running`, exit 2 | Starts and runs; the stale file is removed |
| Watcher killed with `kill -9`, then restarted | (PID-file path) | The new watcher starts: the OS released the lock |

The disposable default home was never created in any run.

## Checks

- Focused tests: the watcher lock is refused while held and free once released; a stale PID
  file is ignored; a non-hunt candidate status loads its rules while a hunt candidate is still
  skipped; a vendor collision and a file-count flood keep the previous tree and leave no staging;
  the launchd plist keys and log directory. `tests/test_rules.py`, `tests/test_quarantine.py`,
  and `tests/test_demo.py`: 99 passed.
- `check_intake.py`: passed. Its Windows-only liveness probe for the removed PID check is
  replaced by a cross-process lock check (a child takes the lock, this process is refused, and
  takes it once the child is killed), which also exercises the `msvcrt` path on the Windows job.
- `lint_rules.py` (85 rules, 2 vendor overrides), `check_rules_lock.py`,
  `probe_rule_coverage.py --verify`, and `yara-gate selftest`: passed.
- Ruff check and format, `mypy --strict src`, and `check_text_controls.py`: passed.

## Boundaries

- launchd behavior was checked by the plist's keys, not by loading an agent; no macOS session
  was available. `plutil -lint` runs in the existing test where `plutil` exists.
- launchd also restarts a watcher that exits 2 because another watcher holds the home, at most
  every 10 seconds, until that watcher stops.
- The expansion and file caps apply per pack. The 300 MiB figure reuses the download cap; the
  reviewed packs are far below both, but their current sizes were not re-measured here.
- Startup reconciliation of quarantine slots a crashed watcher leaves behind (the rest of
  #183 item 8) was not examined or changed here.
