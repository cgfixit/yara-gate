# A macOS timing failure that no change caused — November 14, 2026

Main `c8c6f16` (the merge of [#224](https://github.com/cgfixit/yara-gate/pull/224)) failed
`check (macos-15)` at the worst-case timing tripwire:
`mail-nested-charset.eml: 10.316s exceeds 10s`. Ubuntu and Windows passed on the same commit,
and the macOS job passed on the commit before it, `e4aad66` (#222). Because `ci` did not
succeed, the `demo-results-page` runs for `c8c6f16` ended `skipped`
([`pages_deploy_gate.py`](../../scripts/pages_deploy_gate.py) deploys only a green commit), so
the public demo is one merge behind until a green `ci` run exists for a newer `main`.

No change was made to the code, the rules, or the 10 s limit. This record is the diagnosis the
[tripwire's own rule](worst-case-timing.md) asks for before anyone touches the ceiling:
*diagnose the same input on base and candidate*.

## What was read, what was measured

Hosted CI, read from the job logs: `check (macos-15)` job `132316377347` (failing, run
`43551073399`), `check (macos-15)` job `132313365109` (green, run `43551056886`), and
`check (ubuntu-24.04)` job `132316377070` (green on `c8c6f16`). Direct runtime, on this
container (Linux x86_64, Python 3.12, YARA-X 1.23.0, bundled rules, one warm-up scan, then
`scan_case` from `check_worst_case_timing.py`): the numbers marked "here".

## Findings

**1. #224 did not touch this path.** Its diff against `e4aad66` is `quarantine.py`,
`report.py`, `rules.py`, `selftest.py`, tests, and docs. Nothing under `content.py`.
Three scans of `mail-nested-charset.eml` each, in one session:

| Revision | Seconds (here) |
| --- | --- |
| `e4aad66` (#222, macOS green) | 5.83, 5.44, 5.46 |
| `c8c6f16` (#224, macOS red) | 5.36, 5.34, 5.53 |

The two cannot be told apart.

**2. The macOS runner was slow, and this input has the thinnest margin there.**

| Run | `mail-nested-charset.eml` | Whole timing step |
| --- | --- | --- |
| macOS, green (`e4aad66`) | 6.94 s | 220 s |
| macOS, red (`c8c6f16`) | 10.32 s | 276 s when it failed (the step stopped there) |
| Ubuntu, green (`c8c6f16`) | 4.54 s | 192 s (180 s on `e4aad66`) |

The same code took 49% longer on the red run, and the step as a whole about 25% longer. Across
the 45 inputs with a Ubuntu time over 1 s on both runs, macOS runs a median 1.28 times and at
most 2.69 times Ubuntu's time. At 6.94 s on a good day the input was already at 69% of the
ceiling, so a 1.44 times swing crosses it. `mail-quoted-parameter.eml` (6.97 s) and
`pdf-page-fonts.pdf` (6.27 s) sit just as close on the green macOS run.

**3. The cost is not in the mail reader.** The input is a 4 MiB legacy-charset body, opened
once per message level and read as `text-folded`. Under `cProfile` almost all of it is in
`folded_text`. Without the profiler, per 4 MiB of decoded Cyrillic text (here):

| Stage | Seconds |
| --- | --- |
| `folded_text` in total | 1.89 |
| of which `_NON_ASCII_WORD.sub(_fold_confusables)` | 0.89 |
| of which the two `str.translate` passes | 0.53 |
| the format-control strip in `text_views` (a Python loop over every character) | 0.66 |

Two bodies are read, which accounts for the 5.4 s. The cost is spread over about eight stages
and no one of them dominates.

**4. The same step then failed a second way, on this record's own pull request.** The first
hosted run for [#230](https://github.com/cgfixit/yara-gate/pull/230) (this file only; run
`43553475202`, `check (macos-15)` job `132320949236`) printed `PASS: 78 adversarial inputs`,
and the step was then marked failed: `The action 'Worst-case timing tripwire (4 MiB inputs)'
has timed out after 5 minutes`, 0.09 s after the PASS line. No scan crossed 10 s; the slowest
was `mail-nested-charset.eml` at 9.94 s. The step has `timeout-minutes: 5`
([`ci.yml`](../../.github/workflows/ci.yml)) and took about 311 s, against 220 s on the green
macOS run. A documentation-only diff cannot change a scan, and the slowdown is the whole
step's: over the 55 inputs that took over 1 s on both runs, the median ratio to the green
macOS run is 1.37 (range 1.04 to 1.80), and the scan seconds summed 240 against 174. At about
1.4 times the green run's speed the step reaches its five minutes while every scan is still
under its ceiling. The step budget has the same thin margin the per-scan ceiling has.

## Tried and not kept

Memoizing `_script` (called 3.7 million times, pure per character) with
`functools.lru_cache(maxsize=16384)` left every view and every code point's script identical
(one digest over six views, five folded samples, and all 1,114,112 code points, before and
after) and cut the input from about 5.4 s to about 4.9 s. It was dropped: the gain is about
10%, which does not change the macOS margin, and when every letter in a file is distinct the
cache thrashes and `_script` runs about twice as slow (0.053 s against 0.026 s per 143,000
characters), which is a regression on an input an attacker can build. Replacing the
format-control loop with a `translate` is the largest single stage, but about 0.4 s per body,
and needs a second hand-kept Unicode table (`FOLD_DELETE` also deletes C0 and C1 controls,
which that view must keep). Neither is a fix for a failure no change caused.

## Boundaries

- **The next red run on macOS is likely until the margin grows.** `check (macos-15)` has now
  failed at this step three times in four days: [2026-11-10](2026-11-10-pdf-font-reading-cost.md)
  (`pdf-page-fonts.pdf`, 10.093 s), `c8c6f16` (`mail-nested-charset.eml`, 10.316 s), and this
  record's own pull request (the five-minute step limit, finding 4). The last is a
  documentation-only change. All three point at the runner and the margin, not at a
  regression in any revision. A cost reduction in `folded_text` as a whole is the honest fix
  and is a change to the text-folding view, which the
  [detection backlog](../research/detection-backlog.md) and the reader probes govern; it was
  out of scope here. Raising `timeout-minutes` or the ceiling would only move the margin, and
  the tripwire's own rule is not to do that without a diagnosis of the same input on base and
  candidate; that diagnosis is above, and the choice stays with the maintainer.
- A re-run of a failed macOS job is a hosted-CI fact and is not recorded here.
- This container is slower than the hosted Ubuntu runner (5.4 s here, 4.5 s there on this
  input); ratios, not absolute seconds, carry over.

## Later on November 14: the format-control stage, without a second table

`text_views` removes format controls and variation selectors for the
`format-controls-removed` view with a Python check on every character. It now looks up each
*distinct* character once (`set(text)`, then `unicodedata.category`, the same test as before)
and removes the matches in one `str.translate` pass. That answers the objection above: no
hand-kept Unicode table is added, and C0 and C1 controls are untouched because the test is
unchanged.

- **Same output.** The old and new forms gave the same string on 20,000 random strings drawn
  from ASCII, Cyrillic, CJK, an astral emoji, a lone surrogate, U+00AD, U+061C, U+200B to
  U+200D, U+202E, U+2060, U+2066, U+FEFF, U+FE00, U+FE0E, U+FE0F, U+1D173, U+E0001, and U+E0041.
- **Cost.** `mail-nested-charset.eml`, the input that failed on `c8c6f16`, three runs each in
  one session here (the container was also running a benign sweep, so the seconds are higher
  than above; the ratio is what carries over): 4.14, 3.83, 3.95 s against 4.94, 4.97, 4.82 s
  on `main` `e365218`, about 19% less. At that ratio the red macOS run's 10.32 s would have
  been about 8.3 s.

This widens the margin; it does not remove it. The rest of `folded_text` is still where most
of the time goes, and the step's five-minute limit is unchanged.

## Later on November 14: the step budget is thin on both runners

On `main` `78a0f06` (run `43599768381`) the timing step passed on macOS in 249 s and took
289 s on Ubuntu, 11 s under its five-minute limit. The thin margin is therefore not only
macOS's. This section measures it across the last twelve `ci` runs; it changes no code and no
limit.

### What was read

Hosted CI only: for each run below, both `check` jobs' step start and end from the Actions
job record (whole seconds), and every per-case `seconds` and log timestamp from the job log.
Every run was attempt 1; no log was missing or cut short. On a pull request the header's
`revision` is GitHub's merge commit, not the head named here. Ubuntu reports Python 3.12.3,
macOS 3.12.10, and YARA-X is 1.23.0 on both. Direct runtime on this container (Linux x86_64,
4 CPUs, Python 3.12) is marked "here".

| Revision | Run | Inputs | Runner | Step | Scans summed | Outside the scans | Slowest three (s) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `main` `e0a70ab` | `43534903756` | 76 | Ubuntu | 218 s | 151.0 s | 67.0 s | page-fonts 5.71, nested-charset 5.36, font-definitions 5.32 |
| `main` `e0a70ab` | `43534903756` | 76 | macOS | 246 s | 194.6 s | 51.4 s | nested-charset 8.24, quoted-parameter 7.80, font-definitions 7.27 |
| #224 `d7c9913` | `43541851542` | 76 | Ubuntu | 225 s | 150.9 s | 74.1 s | page-fonts 5.76, nested-charset 5.41, font-definitions 5.27 |
| #224 `d7c9913` | `43541851542` | 76 | macOS | 214 s | 168.7 s | 45.3 s | page-fonts 8.83, quoted-parameter 6.34, font-definitions 6.07 |
| #233 `edc8e9f` | `43543389018` | 78 | Ubuntu | 220 s | 152.7 s | 67.3 s | page-fonts 5.68, nested-charset 5.47, font-definitions 5.23 |
| #233 `edc8e9f` | `43543389018` | 78 | macOS | 277 s | 215.2 s | 61.8 s | page-fonts 7.80, font-definitions 7.46, nested-charset 6.87 |
| `main` `e4aad66` | `43551056886` | 78 | Ubuntu | 180 s | 125.4 s | 54.6 s | page-fonts 4.68, nested-charset 4.44, font-definitions 4.36 |
| `main` `e4aad66` | `43551056886` | 78 | macOS | 220 s | 174.4 s | 45.6 s | quoted-parameter 6.97, nested-charset 6.94, page-fonts 6.27 |
| `main` `c8c6f16` | `43551073399` | 78 | Ubuntu | 192 s | 133.6 s | 58.4 s | page-fonts 5.08, font-definitions 4.73, readings-winansi 4.61 |
| `main` `c8c6f16` | `43551073399` | 74 of 78 | macOS | 276 s (ceiling) | 212.3 s | 63.7 s | nested-charset 10.32, page-fonts 6.72, font-definitions 6.69 |
| #230 `6565244` | `43553475202` | 78 | Ubuntu | 251 s | 177.2 s | 73.8 s | page-fonts 6.56, font-definitions 6.20, nested-charset 6.07 |
| #230 `6565244` | `43553475202` | 78 | macOS | 311 s (limit) | 240.1 s | 70.9 s | nested-charset 9.94, quoted-parameter 9.23, page-fonts 8.52 |
| #230 `4da4a82` | `43554896576` | 78 | Ubuntu | 207 s | 142.8 s | 64.2 s | page-fonts 5.44, font-definitions 5.09, readings-winansi 4.85 |
| #230 `4da4a82` | `43554896576` | 78 | macOS | 288 s | 225.4 s | 62.6 s | page-fonts 8.62, nested-charset 8.46, font-definitions 8.23 |
| `main` `e365218` | `43569627810` | 78 | Ubuntu | 166 s | 109.5 s | 56.5 s | page-fonts 4.63, repeated-keys 4.07, font-definitions 4.03 |
| `main` `e365218` | `43569627810` | 78 | macOS | 238 s | 188.3 s | 49.7 s | page-fonts 6.73, hidden-stretch 6.59, nested-charset 6.45 |
| #232 `f0b031f` | `43597522237` | 78 | Ubuntu | 225 s | 151.7 s | 73.3 s | page-fonts 5.72, font-definitions 5.23, readings-winansi 4.93 |
| #232 `f0b031f` | `43597522237` | 78 | macOS | 197 s | 152.9 s | 44.1 s | quoted-parameter 6.29, page-fonts 5.52, font-definitions 5.18 |
| #233 `5355cdc` | `43599057537` | 81 | Ubuntu | 307 s (limit) | 218.7 s | 88.3 s | page-fonts 7.79, readings-winansi 7.43, font-definitions 7.41 |
| #233 `5355cdc` | `43599057537` | 81 | macOS | 309 s (limit) | 238.5 s | 70.5 s | font-definitions 9.72, page-fonts 9.51, nested-charset 8.97 |
| `main` `78a0f06` | `43599768381` | 78 | Ubuntu | 289 s | 203.4 s | 85.6 s | page-fonts 7.63, font-definitions 7.28, readings-winansi 6.68 |
| `main` `78a0f06` | `43599768381` | 78 | macOS | 249 s | 196.6 s | 52.4 s | page-fonts 8.72, quoted-parameter 7.81, font-definitions 7.14 |
| #233 `6a2e0ac` | `43601473600` | 81 | Ubuntu | 282 s | 198.6 s | 83.4 s | page-fonts 7.28, readings-winansi 7.04, font-definitions 6.78 |
| #233 `6a2e0ac` | `43601473600` | 81 | macOS | 292 s | 225.9 s | 66.1 s | quoted-parameter 8.38, readings-winansi 8.35, font-definitions 8.08 |

"Limit" marks the three runs that printed `PASS` and were then stopped by `timeout-minutes: 5`
(0.02 to 0.09 s after the `PASS` line); "ceiling" marks `mail-nested-charset.eml` at 10.316 s
(the run stopped after 74 inputs, so its sum is partial). #233 adds three inputs, hence 81.

### Headroom

| | Ubuntu | macOS |
| --- | --- | --- |
| Step headroom to 300 s: least, median, most | -7, 77.5, 134 s | -11, 37.5, 103 s |
| Runs with under 30 s of step headroom | 3 of 12 | 6 of 12 |
| Per-scan headroom to 10 s: least, median, most | 2.21, 4.28, 5.37 s | -0.32, 1.50, 3.71 s |
| Runs whose slowest scan was within 2 s of 10 s | 0 of 12 | 8 of 12 |
| Scans summed, 78-input runs: least to most | 109.5 to 203.4 s (1.86 times) | 152.9 to 240.1 s (1.57 times) |

The two constraints bind on different runners. Ubuntu's slowest scan never came within 2.2 s
of the ceiling, but its step has reached 289 s and, on 81 inputs, 307 s. On macOS both are
thin. The spread is the runner's, not the code's: Ubuntu's largest sum (203.4 s) is on
`78a0f06`, which contains #232's cost reduction, and its smallest (109.5 s) on `e365218`, the
revision before it.

**The slowest inputs are now the PDF font readers.** Across the 24 jobs, `pdf-page-fonts.pdf`
is among the slowest three in 22 and `pdf-font-definitions.pdf` in 21;
`mail-nested-charset.eml` is in 13, and in none of the six jobs whose revision contains #232
(`f0b031f`, `78a0f06`, and #233's `6a2e0ac`).
`pdf-font-readings-winansi.pdf` and `mail-quoted-parameter.eml` are in 7 each. On `78a0f06`
the PDF inputs are 87 s of macOS's 197 s of scans and 95 s of Ubuntu's 203 s; the OOXML
inputs are next at about 36 s.

### A quarter of the step is spent outside any scan

The step's time less the scans' summed `seconds` is 44 to 88 s, 20 to 31% of the step. Read
from the log timestamps, almost all of it falls between one worker's result line and the
next's: the per-worker cost of starting Python, building fixtures, and warming the rules,
which the 20 s watchdog counts and the per-case `seconds` does not. Its median is 0.54 to
1.07 s a worker, and it grows with the case's position (Ubuntu on `78a0f06`, by quarter of
the run: 0.92, 1.01, 1.12, 1.26 s; macOS 0.50, 0.59, 0.80, 0.74 s).

The reason is in `main()`. Every worker builds `--case`'s `choices` from `cases()`, which
constructs all 78 fixtures of 4 MiB, and then `scan_case` iterates `cases()` again up to its
own input. Here a worker took a median 0.67 to 0.74 s outside its scan (five runs each of
`html-comments.html`, `zip-end-records.zip`, and `xml-prolog-comments.xml`); the imports took
0.08 s and the rule warmup 0.04 s once the compiled cache existed. With the `choices` list
removed, as a throwaway edit that was not kept, the same workers took 0.18 to 0.26 s. That is
about 0.48 s a worker and 37 s a run here. Scaled to the hosted overhead above, about 30 to
60 s a run; that is a projection, not a hosted measurement.

### Options

Each is a proposal for the maintainer; none is applied.

1. **Stop building every fixture in every worker** (`check_worst_case_timing.py` only). Drop
   `choices` from `--case`, report an unknown name as a worker failure with its name, and,
   further, build only the named input (a name-to-builder table in place of iterating
   `cases()`). No limit, no scanner code, and no measured `seconds` change; each input still
   runs in its own process under the 20 s watchdog. It recovers step headroom on both runners
   and does nothing for the per-scan ceiling. The parent's own three full builds (its `choices`, the
   loop, and the `PASS` count) are about 1.5 s here and can stay.
2. **Lower the cost of the slowest readers.** The PDF font readers (`pdf-page-fonts.pdf`,
   `pdf-font-definitions.pdf`, `pdf-font-readings-winansi.pdf`) are now the inputs nearest the
   ceiling, then `mail-quoted-parameter.eml` and `folded_text`. This is the only option that
   widens macOS's per-scan margin, which is the one that has failed on a scan. It is a change
   to what `pdftext.py` reads and needs `probe_pdf_font_reader_agreement.py` with its fuzz pass
   before and after, so it is the largest of the four.
3. **Split the step**, for example PDF inputs in one step and the rest in another, each with
   its own five minutes, through a selection argument to the script. It halves each step's
   exposure, but the job's total time is unchanged and the combined budget doubles: in effect
   a limit increase that leaves aggregate growth less visible. Running workers in parallel
   inside one step would cut wall time, but the runner's few cores would then be shared
   between timed scans, inflating the per-scan `seconds` that are already within 2 s of the
   ceiling there.
4. **Change a limit.** The step's `timeout-minutes: 5` is not what bounds a pathological input
   (each worker's 20 s watchdog and the 10 s ceiling do), so a larger step limit would not
   pass a slow reader; what it gives up is a signal when the whole set slowly grows. That
   signal could instead be an explicit budget on the summed scan `seconds`, which excludes
   the worker overhead and so measures the readers. The 10 s ceiling is the one the tripwire's
   rule governs. The same input on base and candidate is diagnosed above and in this record's
   earlier sections: identical code ran 1.86 times apart on Ubuntu and 1.57 times on macOS.
   A per-scan change is still the maintainer's call; scaling the ceiling by a reference scan
   timed in the same job is a further option, at the cost of the calibration's own noise.

Option 1 alone would have put every run above under 300 s except, at the low end of the
projection, #233's `5355cdc` on Ubuntu (307 s less 30 to 60 s). Options 1 and 2 together
address both constraints without moving a limit.
