# Ingress replay: an observe-only record of what the gate would decide

Date: 2026-11-20. Base: `main` at `bc5811b`. Engine: YARA-X 1.23.0, Python 3.12.3, Linux
container with 4 CPUs. Rules: a disposable copy of the shipped `rules/local` (89 rules), no
vendor packs. Issue: [#236](https://github.com/cgfixit/yara-gate/issues/236), phases 0, 1,
and 5 of the plan recorded there on 2026-11-16.

## What changed

- `yara-gate replay CAPTURE` and `yara_gate.replay`: scan a capture of the exact text a
  consumer handed its model, and print one envelope per item with the gate's record, the
  decision its read rule gives, and the consumer's own decision. The contract is in the
  [integration guide](../integrations.md#replaying-captured-model-input).
- The [shadow evaluation protocol](../research/shadow-evaluation-protocol.md): the frozen
  conditions, pilot size, budgets, and which metric the replay records.
- The live workbench's response and its **Coverage & provenance** panel gained
  `detector_sha256`. The public recorded demo is unchanged: its builder keeps its own field
  allowlist, and `web-demo/recordings.json` was not touched.

No rule, reader, heuristic, severity, verdict, exit code, or report field changed. `scan`,
`watch`, `scan_bytes`, and `scan_file` are untouched.

## What was run

Direct runtime, on this change, with `XDG_CACHE_HOME` pointed at a disposable directory.

### Every catalog pair, under every policy

A capture built from `showcase.CASES` (the 44 attacks and 44 benign twins that are not
failure cases, as base64 bytes under their own names, once per policy): 264 items.

| Check | Result |
| --- | --- |
| Gate verdict against the catalog's reviewed expectation | 264 of 264 equal |
| Status | 264 complete, 0 truncated, 0 failed |
| Benign twins proposed as a hold | 0 of 132 |
| Attacks proposed as a hold | `agent-ingest` 44 of 44, `agent-document` 20 of 44, `default` 4 of 44 |
| Notes-only `agent-document` records proposed as an admit | 24, each `advisory` with every finding a note |
| Wall time per item, median and maximum | 0.219 s, 0.307 s |
| Scan time per item, median and maximum | 0.092 s, 0.171 s |
| Exit | 0 |

Two more runs with `--no-timings`, one from the file and one from stdin, printed the same
bytes (one SHA-256 for both outputs).

### Real documents, against the library

Every tracked Markdown file and every file under `tests/fixtures/benign` (166 files, 1.6 MB,
the largest 143 KB), replayed under `agent-ingest` and `agent-document`: 332 items. Each
envelope's `gate` record was compared, field by field except the two timings, with
`compact_report(scan_bytes(...))` of the same bytes in the parent process.

| Check | Result |
| --- | --- |
| Records that differ from the in-process scan | 0 of 332 |
| Status | 332 complete |
| Rule and detector identities seen | 1 |

These documents quote attacks, so 73 of the 332 are proposed holds. That is the documents'
content, not a false-positive measurement.

### What is not a record

Each case below was run through `shadow_scan` or `replay_capture`. The hung child is a real
process; the tampered answers replace the child's output.

| Case | Status | Reason | Proposed |
| --- | --- | --- | --- |
| A child that sleeps past the kill time (`timeout_s=1`, killed at 2 s) | failed | `hard deadline` | hold |
| A clean record handed back for different bytes | failed | `record is for other bytes` | hold |
| A clean record for the same bytes under another policy | failed | `record is for another policy` | hold |
| No output; text that is not JSON; two records; an exit code that disagrees with the verdict; `clean` with an incomplete reason; an unknown verdict | failed | `malformed output` | hold |
| A child killed by a signal | failed | `worker exit -9` | hold |
| An interpreter that cannot start | failed | `worker did not start` | hold |
| A rules tree with one broken local rule | truncated | `local rule compile failed` | hold |
| A rules directory that does not exist | truncated | `no rules compiled` | hold |
| 25 MiB of quoted phrases with `--timeout 1` | truncated | `timeout` | hold |
| A capture `text_sha256` that names other bytes | failed, not scanned | `receipt mismatch` | hold |
| A capture line that is not JSON, repeats a key, has an unknown key, gives both or neither text, names an unknown policy, a control character in `source_id`, a lone surrogate, or `schema_version` 2 | failed | `malformed capture: …` | hold |
| A capture line over the limit, followed by a good line | failed, then complete | `malformed capture: line too long` | hold, then admit |

A capture with any failed item exits 2. No case produced exit 1.

### The live workbench, in a browser

`yara-gate demo --rules <disposable copy> --port 8791`, driven with Playwright and Chromium.

- A pasted override phrase scanned as `block`; **Coverage & provenance** showed a 64-digit
  **Detector SHA-256** row, equal to `detector_sha256` in **Demo response JSON**.
- **Run every pair** under `agent-ingest`: "90 of 90 results as expected, 0 finding(s) on
  benign twins".
- No console errors.

### Other checks

- `docs/research/probe_rule_coverage.py --verify`: exit 0, no failures.
- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts`: clean.
- `check_doc_links.py`, `check_text_controls.py`: pass.
- `pytest -m "not slow"`, the whole suite on Linux: 1299 passed, 5 skipped. The 38 replay
  tests are in `tests/test_replay.py`.

### Independent review

A second reader, given the diff and not this record, tried to break the stated guarantees.
No capture line it tried (a 60,000-case fuzz of keys and value types included) produced a
wrong admit, a miscount, or a crash. It found these, all fixed in this change:

| Finding | Fix |
| --- | --- |
| `--timeout 2147454` or larger raised `OverflowError` and exited 1 | `--timeout` is bounded to 1 through 86,400; `shadow_scan` reports a deadline the clock cannot hold as `failed` |
| A child record whose `severity` was a list raised `TypeError` | A non-string severity is `malformed output` |
| A scan that raised (`scan failed`) was reported as `record is for another policy`, or kept a record without identity under `default` | It is `failed` with `scan failed` and no record, under every policy |
| `shadow_scan(5)` scanned five NUL bytes | Anything but bytes raises `TypeError` |
| A lone surrogate in `name` reached the child's argv | It is a malformed capture line |
| A `clean` record with a finding, or a non-integer exit code, was accepted | Both are `malformed output` |
| A closed stdout was reported as an unreadable capture | It exits 2 without that message |
| Tests passed with the default hard deadline, the notes-only rule, and the error text each broken | Each now has a test that fails on that mutation |

It also noted that a run whose rules do not load exits 0 with every item `truncated`. That
is the documented exit rule; the integration guide and the protocol now say to read `status`
before using a run. Not changed: with an ASCII-only filesystem encoding, a non-ASCII `name`
is `failed` with `worker did not start`.

## Cost

The replay starts one process per item. With the compiled rules cached, that is about
0.2 s of wall time for a small text item, of which about 0.09 s is the scan. The first item
after a rule change also compiles the rules (1.3 s here). A consumer that calls `scan_bytes`
in its own process pays the scan time, not the process start, so judge the protocol's
latency budget on `scan_seconds` for a library integration and on `wall_seconds` for a CLI
one.

## Limits

- This is the adapter and the protocol. No consumer capture was replayed: the catalog and
  this repository's documents stand in for one. The pilot's 100 benign and 100 attack tasks
  are captured in CG-agent-harness, which this change did not touch or inspect. That work
  is tracked in [#294](https://github.com/cgfixit/yara-gate/issues/294).
- The replay measures detector matches, false holds, unfinished scans, and latency. It
  cannot measure whether an attack would have succeeded, or whether a task still completed.
- The classifier slot is a pass-through. No classifier adapter exists; it is tracked in
  [#295](https://github.com/cgfixit/yara-gate/issues/295).
- `source_id`, `extractor`, and the classifier record are the caller's and are copied to
  the output. Hashes can identify known content. Review a replay before publishing it.
- Hosted CI on macOS and Windows had not run when this was written.
