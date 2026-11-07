# Intake bounds and scanned-byte handoff

Verified November 6, 2026 (America/New_York), on macOS 27.2 arm64 with locked
Python 3.12.12, YARA-X 1.23.0, watchdog 6.0.0, Ruff 0.17.3 and mypy 2.4.1.
Base: `682cf08fbb37d8778f87b2470902f8de6e4b02a9` (`origin/main`). Work took place in
an isolated `cx/bounded-intake-watch` worktree; the existing demo draft was preserved.
The candidate was exercised before committing; source hashes below identify its
exact runtime bytes. All inputs were inert, all gate homes/rules were disposable,
and no vendor packs were downloaded.

## Reproduced findings and scope

- Baseline `drain_inbox` left `.note.txt` and a directory in the inbox, with zero
  reports. The explicit CLI folder scan recurses and includes dotfiles, but the
  watcher never calls that path. The sync-folder example separately filters
  metadata; it does not compensate for the watcher's omission.
- A 100 MiB + 1 byte sparse input caused 209,715,202 bytes of intake `os.read`
  activity (hash plus copy), a full-size quarantine copy, then scanner rejection.
  Scanner rejection also performed an unbounded full-file hash. This is a
  resource-exhaustion exposure, not clearance into `clean/`.
- The old pre-read hook returned 0 with no rewritten path; replacing the source
  immediately afterwards changed the bytes a subsequent reader received. The
  documented race was an integration limitation, but the hard-control wording
  overstated the guarantee.

The watcher now scans top-level dotfiles and rejects dropped directories intact
with an incomplete report, using the existing non-regular-entry contract. Explicit
recursive CLI scans remain available. Temporary uploads must finish outside the
inbox before an atomic rename. Both intake passes have the existing 100 MiB bound,
including growth after the stat check, and failed copies remove their partial file.
Oversized entries are renamed into `_rejected/` without hashing their contents;
the rejection token is not a content digest. Oversized scanner inputs have the
unknown digest (64 zeroes), including stdin. Unexpected scan failures do not reread
the file to compute a hash.

The hook captures one bounded buffer, scans it through the real stdin CLI while
preserving the original filename, verifies policy and digest, and either emits
that buffer (`--bytes`) or rewrites the Read request to a fresh private, read-only
snapshot. It preserves read parameters and makes no automatic permission grant.
The integration must authorize the original path and protect snapshot storage;
mode 0400 does not isolate an adversary with the same account. A runtime that
ignores `updatedInput` cannot use the hook as a gate. The byte-output mode avoids
a second pathname read entirely. These are explicit handoff contracts, not
claims of an installed consumer integration.

## Direct execution and focused regressions

- `uv sync --frozen --group dev`: succeeded with the pinned environment.
- `docs/research/probe_rule_coverage.py --verify`: 531 library observations,
  55 CLI operations, nine benign fixtures, three failure-path checks; passed.
  85 bundled rules compiled, zero skips. Includes identical-byte policy
  resubmissions, exit codes, reports, and physical disposition.
- `docs/verification/check_intake.py`: passed locally, including new dotfile,
  directory-hold and oversized-entry identity checks. The existing Windows job
  runs this script on the no-`O_NOFOLLOW` path; local results are not Windows proof.
- Focused pytest coverage: 51 cases across `tests/test_quarantine.py`,
  `tests/test_pre_read_hook.py`, and
  `tests/test_scanner.py::test_over_size_is_incomplete_without_reading` passed
  (45 initial cases, five further hook/staging failure cases, one report-failure
  case). No full local pytest or selftest run.
- Growing-file checks used the production 104,857,600-byte limit and real reads:
  both hash and copy stopped after exactly limit + 1 bytes. The earlier destination
  survived a failed copy and no `.partial-*` remained. Exactly 100 MiB was accepted
  with a matching full digest. No test lowered the production limit.
- A 1 GiB sparse inbox file was rejected in 1.2 ms with zero content bytes read,
  and the held file retained its original filesystem identity. An in-place scan
  also returned incomplete without hashing it. This establishes bounded work,
  not a throughput guarantee on arbitrary storage.
- Hook checks cover a real scanner run with source replacement during scanning,
  replacement after success, unique successive snapshots, the exact byte-output
  handoff, notes-only/document and strict/message policies, blocked content,
  unsafe/missing inputs, malformed requests/records, and scanner startup failure.
  Sync staging rejects oversized inputs and removes partial copies on growth.
- Ruff lint/format on changed Python and applicable Markdown, strict mypy on
  `src`, ShellCheck on the shell entry point, the text-control checker, and
  `git diff --check` passed. No workflows changed.

A live `watch --policy agent-ingest` process consumed a preexisting clean dotfile,
blocked a newly atomically renamed dotfile, held a directory with its child intact,
and held a 1 GiB entry. SIGINT exited 0 and removed `.watch.pid`. The first run in
the sandbox logged a native FSEvents startup error while periodic draining still
worked. Repeating the same probe outside the sandbox in a new disposable home
passed all outcomes with no emitter error. Both owned processes exited.

## Performance check

Five batches of 40 distinct 1 MiB files through `intake` on the same local disk:
base median 31.305 ms; candidate median 30.846 ms (ranges 30.455–33.741 ms and
30.597–33.140 ms). This small measurement showed no detectable ordinary-intake
regression; it does not establish a general speedup.

The old versus new shell hook on the same small clean document and scanner binary,
after one warmup: median 105.6 ms versus 100.1 ms across five calls each. The new
run includes writing a private snapshot. Timing noise and storage differences
limit these numbers; the new byte and storage bounds are the substantive change.

## Browser verification

Codex Computer Use exercised the live loopback scanner at `127.0.0.1:60444`, with
copied bundled rules. Plain note: clean/exit 0. Override phrase: block/exit 1 under
agent-ingest, notes-only advisory/exit 0 under agent-document. Secret request:
block/exit 1 with its original advisory finding. The UI showed 85 compiled rules;
no warning/error console entries were observed. The original full-page JPEG is
[saved here](../../screenshots/yara-gate-intake-boundary-check.jpg).
This is live scanner/policy evidence; the browser does not exercise filesystem
intake or the agent hook, which have separate process evidence above.

## Source identity and remaining limits

| Candidate file | SHA-256 |
| --- | --- |
| `src/yara_gate/quarantine.py` | `5d63d6e917217bbc15f057fdff093c2a19848fd2ec62772be9e769cf31550ea9` |
| `src/yara_gate/scanner.py` | `86f29f90dd050bcba424a0033db34d4ffc182b0aa97e8c5059f5189ed72abb05` |
| `docs/examples/yara_gate_pre_read_hook.py` | `66b2394c252b3355505cbe56d4197dfa9d70b41b87ce6da0b359ceb169cd8377` |
| Browser JPEG | `9b1087ca81b67fbd59b20851a48ef89423b2ce018d1888262ab903a0f40e80b2` |

No actual Claude Code/CyClaw/Harness read-tool deployment, Windows desktop, real
cloud placeholder, hostile same-account process, or production false-positive
study was exercised. Snapshots need consumer-owned storage and lifecycle cleanup;
`--bytes` consumers must wait for success before using captured output. Hosted CI
and review status are reported separately on the draft PR. No merge or deployment
is part of this verification.
