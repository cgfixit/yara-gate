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

- **The next red run on macOS is likely until the margin grows.** Two `check (macos-15)`
  failures at this step in four days ([2026-11-10](2026-11-10-pdf-font-reading-cost.md) was
  `pdf-page-fonts.pdf`, 10.093 s) point at the runner and the margin, not at a regression in
  either revision. A cost reduction in `folded_text` as a whole is the honest fix and is a
  change to the text-folding view, which the
  [detection backlog](../research/detection-backlog.md) and the reader probes govern; it was
  out of scope here.
- Whether a rerun passes is a hosted-CI fact. None had run when this was written.
- This container is slower than the hosted Ubuntu runner (5.4 s here, 4.5 s there on this
  input); ratios, not absolute seconds, carry over.
