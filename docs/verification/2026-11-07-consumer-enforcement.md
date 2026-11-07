# Consumer enforcement — November 7, 2026

Phase 2 of the follow-up to [#183](https://github.com/cgfixit/yara-gate/issues/183) and the
[November 7 detection review](../reviews/2026-11-07-detection-review.md), stacked on Phase 1
([scope and budgets](2026-11-07-detection-scope-and-budgets.md)). Findings were reproduced with
`origin/main`'s examples (`7d505f9`) before the change. Python 3.12, YARA-X 1.23.0, 85 bundled
rules, disposable rule copies, gate homes, queues, and `HOME`. No sample was executed or fetched;
no request left loopback.

## Changes

| Change | Before | After |
| --- | --- | --- |
| Report field `detector_sha256` | A reader or heuristic change can alter a verdict under the same `tool_version` (0.2.0) and `ruleset_sha256` | SHA-256 over the package's Python sources and the `olefile`, `oletools`, and `yara-x` versions; in every scanned record and the JSON report |
| Sync example: cached admission | Skip key is size and mtime only | Also the detector identity: policy, `ruleset_sha256`, `engine_version`, `tool_version`, `detector_sha256`, read from one in-memory probe scan per run |
| Sync example: revocation | A rescan that holds leaves the earlier `allowed/` copy readable | Each run ends by moving every `allowed/` copy no entry admits under the current identity to `withdrawn/<sha256>/`, with `withdrawn.json` |
| Sync example: timeout | `subprocess.run` without a timeout | Killed `--timeout` + 30 s after start; partial output ignored; held; retried next run (no ledger key) |
| SMS bridge: replays | Every signed delivery is appended | One unique `MessageSid` row in owner-only `processed.sqlite3`, written in the same transaction as the queue line; duplicates dropped before scanning; no ID is held |
| Integration example | `subprocess.run` without a timeout | `--timeout 30` and `timeout=60` |

## The review's upgrade sequence

Same source folder and rules copy (identical `ruleset_sha256`). The "old" scanner is main's code;
the "new" one is this branch, whose MCP walk sees a shell entry at list item 51. The input is an
inert MCP config with that entry plus a plain note, under `agent-document`.

| Step | Main's sync script | This change |
| --- | --- | --- |
| 1. Old scanner, home A | both allowed, exit 0 | both allowed, exit 0 |
| 2. New scanner, same home A | nothing rescanned; stale `allowed/mcp.json` stays, exit 0 | both rescanned; `mcp.json` held and withdrawn, exit 1 |
| 3. New scanner, fresh home B | `mcp.json` held, exit 1 | `mcp.json` held, exit 1 |
| 4. New scanner, home A, source mtime changed | held, **and** the old copy still in `allowed/` | held; nothing for it in `allowed/` |

Source bytes were unchanged and the disposable default home was never created.

Further runs on the new script: a scanner that never exits (`--timeout 1`) was killed after 31 s
(the run took 32 s), its partial `{"partial":` output was ignored, the file was held with a null
ledger key, and no child process remained; the next run with a working scanner rescanned and
allowed it. An idle rerun scanned nothing and exited 0. Switching to `--policy agent-ingest`
rescanned. A missing scanner failed the probe: nothing was scanned or moved, exit 2.

## SMS bridge

Through the real HTTP handler on loopback with valid Twilio signatures (a fake token):

| Delivery | Outcome |
| --- | --- |
| A message, then the same signed request again | allowed, then duplicate (one queue line) |
| Two identical deliveries at once | one allowed, one duplicate |
| A held message, then its replay | held, then duplicate |
| No `MessageSid` | held |
| `allowed.jsonl` unwritable (a directory) | no response, no row; after repair the retry is allowed |
| After a restart: the first message, the retried one, a new one | duplicate, duplicate, allowed |

Final queues: `allowed.jsonl` holds SM1, SM3, SM4, SM5 once each; `held.jsonl` the injected
message and the unnamed one. `processed.sqlite3` and both queues are 0600; the directory 0700.

## Checks

- Focused tests: the report digest, one `MessageSid` processed once across a restart, and a held
  unnamed message; the related scanner, heuristics, demo, report, pre-read-hook, and SMS files
  passed (257 tests, 4 macOS-only skipped).
- Ruff check and format (including Markdown Python blocks), `mypy --strict src`, and
  `check_text_controls.py`: passed.
- The Pages recordings curate result keys, so the new field changes no public outcome.

## Boundaries

- `detector_sha256` covers this package's sources and three parser versions, not the Python
  runtime or other installed packages. A record built without a scan (an intake rejection) has
  none, as it has no `tool_version`.
- The SMS bridge opens its SQLite file by path after checking it through the queue descriptor,
  because `sqlite3` cannot open relative to a descriptor. The directory is owner-only.
- A crash between a queue append and its commit can repeat one line; the consumer must skip a
  `message_sid` it has consumed. Exactly-once delivery is not provided.
- `allowed/` now holds only the current admission of each path. A consumer that relied on old
  versions staying there should read `withdrawn/` as history, never as a read set.
- These are reference examples; a live CyClaw or harness adapter was not exercised.
