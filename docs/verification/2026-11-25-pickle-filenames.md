# Pickle inspection under every filename

Date: November 25, 2026 (ET). Base: `origin/main` at `c8519c5`. Candidate: this
branch's `src/yara_gate/heuristics.py`, SHA-256
`9d7d8e7a629eb6383161511767af07e2ecd8ea04bd1bc9a32f36c4a89a8dc304`. macOS 27.2.1 arm64, Python 3.12.12, locked YARA-X 1.24.0,
89 bundled local rules, zero skipped rule files, no vendor packs. Installed detector:
`49acd163df3db680eb2a14e967a6e2ec2d3fd061e621f20ceaf7a997a9c7221d`. All inputs were
inert; no pickle was loaded, no sample command was executed, and no sample URL
was fetched.

## Current issue review and selection

The eight open issues were reviewed against the refreshed source and their latest
comments. The only open PR was [#356](https://github.com/cgfixit/yara-gate/pull/356),
which covers Windows sync-folder staging and changes no pickle code.

| Issue | Current assessment |
| --- | --- |
| [#322](https://github.com/cgfixit/yara-gate/issues/322) | Highest actionable correctness concern: the legacy pickle walk still depends on a recognized filename. Other original findings have fixes; Windows staging coverage is in #356. Windows script-rule suppression remains deferred pending representative benign evidence. |
| [#342](https://github.com/cgfixit/yara-gate/issues/342) | Most proposed cleanup is already on main: dead helpers/parameters were removed, SARIF now derives properties from the compact JSON report, and Office probes share their phrase oracle. A real report comparison confirmed matching identity properties. Remaining suggestions are maintenance choices, not a higher-priority bug. |
| [#236](https://github.com/cgfixit/yara-gate/issues/236), [#294](https://github.com/cgfixit/yara-gate/issues/294) | Still need exact model-facing Harness captures, the frozen task set, baseline runs and the outcome decision. Current replay completeness checks do not supply that evidence. |
| [#295](https://github.com/cgfixit/yara-gate/issues/295) | The classifier follows the measured gate-only baseline; no classifier is in the current scan path. |
| [#225](https://github.com/cgfixit/yara-gate/issues/225), [#228](https://github.com/cgfixit/yara-gate/issues/228), [#229](https://github.com/cgfixit/yara-gate/issues/229) | Parked follow-ons: no explain bundle, authenticated receipt, or cross-source ledger is implemented. Existing reports, held-item discovery and the SMS window are narrower mechanisms. Preserve the recorded prerequisite sequence. |

## Reproduction and change

On the base, the same inert protocol 0 call blocks as `model.pkl` but is clean as
`model.bin`, `model.joblib`, `model`, or `notes.txt` under all three policies.
`heuristic_findings` calls `pickle_reduce_findings`; its `_pickle_candidate` gate
refused those names unless the bytes began with the protocol 2–5 header.

The candidate removes that gate and its unused path argument. The existing
bounded opcode walker starts at byte zero for every name and every member. It
still stops at malformed input, walks consecutive pickle streams, never executes
a callable, and retains its dangerous-global list and its opcode, stack, memo and
deadline limits. The owner explicitly selected inspection under every filename
with existing fail-closed limits on November 25.

Regression cases cover `.bin`, `.joblib`, `.txt`, no suffix, a consecutive stream
under `.bin`, uncalled globals and prose quotations. The detection-gap tracker
removes the resolved `OPEN` marker and adds filename and quotation controls.
README, user guide, rule guide and backlog describe the broadened scope and its
compatibility boundary. No dependency, YARA rule, severity or report schema changes.
The detector digest changes, so cached admissions keyed on it require revalidation.

## Direct execution and packaged acceptance

Built with `uv build --wheel --out-dir dist`, installed the wheel and locked
runtime requirements in a disposable virtual environment, and verified imports
came from its `site-packages`. Wheel SHA-256:
`3ab291e6f034d004dba7027ec7e4d3d25e005a5afdbf5ae9462cfe84ffbfef62`.
The installed Python sources matched the candidate.

- A direct installed-library run checked six dangerous spellings/layouts under
  five filenames and all three policies: **90 block/exit 1 results**, each with
  `heuristic_pickle_reduce` and no incomplete reason.
- Twenty-four benign values serialized under protocols 0–5, all three policies,
  plus six uncalled-global, quotation, path-file, empty and ordinary-text controls:
  **438 clean results**, zero findings. `pickle.dumps` only serialized benign data.
- A zip containing the inert stream as `payload.bin` blocked with `zip:0` and
  `raw` provenance, without exposing the member's name in the finding.
- The installed CLI scanned a disposable inbox: dangerous `.bin` → block/1 in
  `blocked`, ordinary note → clean/0 in `clean`, stack-limit text → incomplete/2
  in `quarantine`. The stored bytes matched the submitted SHA-256, reports omitted
  matched content, and the disposable rules were unchanged.
- Installed `yara-gate conform`: **94 fixtures, 282 checks, zero changed verdicts
  or findings**. No manifest update was needed.

The first intake assertion looked for files directly in the destination rather
than in its digest subdirectory. The actual CLI result was correct; the probe was
corrected to inspect the documented layout and rerun successfully.

## Benign scope and cost

The installed-file walk read **133,877 regular files, 4,594,155,656 bytes**, each
at most 16 MiB, under the pyenv Python 3.12.13 library, uv Python 3.12.12 library,
and Homebrew Cellar. The candidate pickle heuristic returned **zero findings and
zero limit errors**. No individual walk exceeded 10 ms on that run. This checks
the newly reached heuristic only, not every scanner path or production traffic.

A separate 1,000-file text sample selected by the existing
`sweep_rule_changes.collect` helper was scanned through both the base and candidate
scanner using the same locked environment and rules. Compare content digest,
verdict, incomplete reason, rule IDs, offsets, lengths, views and member provenance;
ignore timing and the intentionally changed detector digest. **Zero differences.**

The boundary deliberately changes: 1,000,001 consecutive `N`, `]`, or `)` bytes
under `notes.txt` were uninspected by the base, but now reach the existing stack
cap. All nine installed scans (three byte patterns × three policies) were
incomplete/2 with `pickle exceeds walk limit`. Mean scan time over the three
policies was 0.285–0.296 s per pattern. An isolated walk of 4 MiB of push/pop pairs
completed in 1.22 s; ordinary prose exited at its first invalid opcode. These are
single-machine observations, not a performance guarantee or a claimed speedup.

A bare dangerous stream shown as a text example now blocks. A quotation following
ordinary prose stays clean because the walker does not search arbitrary offsets.
Other callable modules and loader-specific behavior remain outside this heuristic;
this change closes filename gating, not every unsafe-pickle shape.

## Computer Use

Started the freshly installed wheel's `yara-gate demo --port 0 --rules` against a
disposable local rules tree. Computer Use used the in-app browser on loopback:

- The bare protocol 0 text, submitted as `paste.txt`, painted block/1 under
  `agent-ingest`, with `heuristic_pickle_reduce` in original bytes at offset 21.
- The same text after ordinary prose painted clean/0 with zero findings.
- Run every pair: **92/92 expected outcomes**, 45/45 attacks held, 45/45 benign
  twins clean, zero findings on twins, 2/2 incomplete cases held.
- Empty submission displayed an error and cleared the previous verdict.

This repository delivers a CLI/library and browser demos, not a macOS `.app`.
The browser run is live scanner evidence; the static Pages replay is separate.
Its painted JSON named the same detector digest as the installed CLI. After
commit `e621312`, the Pages recorder matched all 279 reviewed outcomes. The
supported four-file build validated the existing curated recordings; Computer
Use selected Inspection limit and showed recorded incomplete/2 under all three
policies. That page still labels the original curated recording revision; it is
not presented as a live scan of this candidate.

## Reproducible checks and limits

- `python docs/research/probe_rule_coverage.py --verify`: base and candidate both
  passed, 617 library, 55 CLI and 9 benign observations, plus three failure paths.
- `python docs/research/probe_detection_gaps.py --verify`: passed, including the
  filename gap now required to hold and all three policy verdicts.
- `python docs/verification/check_added_rules.py`: passed, 271 cases plus four
  vendor-override cases.
- `pytest -q tests/test_heuristics.py -k pickle`: 22 passed. This focused test run
  covers the changed routing, limits and deadline callback; broad pytest stays in CI.
- Ruff lint/format and strict mypy on `src scripts`: passed.

The sandbox initially refused the loopback listener; the unchanged installed
command ran with authorized access. The Pages recorder correctly refused the
uncommitted scanner tree, then passed after the implementation commit. No gate
was disabled. Native Windows, vendor packs, live consumers, broader regression
coverage and production false-positive rates are not established by these runs.
Keep #322 open for the deferred Windows script-rule item after this fix merges.

## Overlap and artifact refresh

Trial merges on November 25 were clean against `main` `c8519c5` and against
#356 head `b8d588b`. Both branches edit different sections of README.md. On the
combined tree, Ruff, actionlint 1.7.12 and locked zizmor offline/pedantic passed,
and the wheel built successfully. This does not replace each PR's hosted checks.

The original operator checkout has widespread unstaged deletions. Its source,
index and local main were preserved; its origin refs were refreshed. Work and
verification use the isolated clone and installed wheel described above.
