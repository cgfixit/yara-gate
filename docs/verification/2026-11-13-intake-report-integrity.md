# Intake, report and queue recovery — November 13, 2026

Base `origin/main` was `e0a70ab48d454be7619ad60a3e39e5515b177b5f`. The
runnable source was `7770c76b7d8b`, with the Pages copy change included in
the local build. Verification ran on macOS 27.2.1 arm64 with Python 3.12.13,
the frozen lock, YARA-X 1.23.0, and 87 bundled rules with zero skips. Homes,
rule copies, input, and SMS credentials were disposable. No vendor packs
were downloaded.

## Differences from main

| Path | Observed on the base | Candidate |
| --- | --- | --- |
| Two CLI scans of identical bytes under different names and policies | The second scan overwrote the only digest-named JSON and SARIF pair. | The latest pair remains available. Unique, versioned JSON event files preserve both scan contexts. |
| Restart after intake copied and removed an inbox file | The restarted watcher ignored the orphaned quarantine slot. | The watcher retries the recorded copy under its original policy and rules root. A recorded incomplete scan stays in quarantine. |
| A local rule with an include outside the loader's enumerated sources | Editing the included file left the ruleset fingerprint and cached verdict unchanged. | Validation and compilation both disable includes. The cache salt changes, so a prior compiled set cannot hide the error. |
| SMS queue write interrupted before completion | The prior JSONL append and SQLite commit used different stores, leaving a duplicate window. | SQLite commits the deduplication row and pending JSONL bytes together. A restart finishes the pending append using the original file identity, offset, and existing prefix. |
| Actionlint install | Selected v1.7.12 by tag and verified the module checksum. | Selects the same release by commit. The Go module proxy resolved the full commit to v1.7.12. |

## Executed checks

- Sent SIGKILL to a disposable intake process just before scanning. Restarted the real
  `yara-gate watch` with the default policy. The pending `agent-ingest` submission moved to
  `blocked/` with that policy in its event. A new ordinary file moved to `clean/`.
  SIGTERM shut the watcher down with exit 0.
- Ran `docs/research/probe_rule_coverage.py --verify` (617 library observations and 55
  CLI observations), `check_intake.py`, `check_scan_only.py` (7 cases),
  `lint_rules.py`, and the affected `yara-gate selftest` entry point.
- Ran 72 focused report, quarantine, release and SMS checks, plus five selected rule
  compilation, promotion and cache checks. Covered concurrent report writers and
  queue recovery before, during, and after an append.
- Exercised the SMS HTTP handler on loopback with synthetic signatures. A bad signature
  got HTTP 403. Concurrent duplicate deliveries produced one allowed row. An MMS
  replay produced one held row. After a partial append returned HTTP 503, a restart and
  retry produced one complete JSONL row.
- Compared `measure_precision.py --fail-over` output against the base. The 328-file
  synthetic corpus had identical per-rule counts, including four known collisions
  and zero incomplete inputs. The existing detection-gap probe reported 500 passing
  cases and its four expected open cases.
- Rebuilt and installed the wheel in a disposable environment. Its bundled-only stdin
  scan returned clean and wrote a version-1 report event. Candidate wheel SHA-256
  `c7e64e4f494c2ca1b8beed0341ab1adbcc0a5f19093e784e05df01400d728fd2`.
- Used Codex Computer Use with the live loopback workbench. All 81 cases per policy
  matched expectations under each of the three policies. All 40 benign twins were
  clean under each policy with zero findings. The rebuilt Pages replay matched 246
  recorded results. The browser displayed the fail-closed compilation result and
  the documented LZW limitation outside the scoreboard.
- Ruff lint and format, strict mypy, actionlint 1.7.12, zizmor offline with pedantic
  mode, Markdown links, tracked text controls, and diff whitespace checks passed.

## Scope and limits

A report event describes a scan. An event can precede a failed move. Review actions
remain in the release audit log. Recovery uses current rules at the recorded root
and holds a copy if the rules overlay mode has changed. A slot created before the
pending record exists stays held for operator review. Scan events have no automatic
retention. SMS queue files may be rotated while the bridge is stopped and the
pending table is empty. Old queue lines are kept as they were written.

The tests cover process interruption on this Mac. They do not establish power-loss
durability, live Twilio delivery, production precision, vendor-pack compatibility,
or Linux and Windows runtime behavior. Issue [#223](https://github.com/cgfixit/yara-gate/issues/223)
tracks coverage metadata for skipped PDF page streams.

## Follow-up review

On `74c3e42`, if interruption left the original in the inbox, a direct retry
under `agent-ingest` could return the earlier pending `default` verdict. The
follow-up lets explicit intake of the unchanged original supersede its pending
record before any old-policy relocation. The focused test confirmed one scan event,
an `agent-ingest` block, and no copy in `clean/`. Recovery of a pending file
whose inbox original was already consumed still uses its recorded settings.
