# Text scan fast paths — October 13, 2026

Baseline: `2e8c85ad2fa22e456345efa6071e778326bf29cc`. Runtime: Python 3.12.12,
YARA-X 1.21.0, macOS ARM64. The candidate adds two early exits: skip the joiner
loop when neither joiner occurs, and skip formatting-control normalization
when the HTML-unescaped text is ASCII. The latter check happens after HTML
unescaping, since ASCII entities can introduce non-ASCII controls.

## Direct execution

`docs/research/benchmark_text_scan.py` copies all local rules into a temporary
tree and scans three inert documents three times each through `scan_file`.
Compilation is warmed before timing. Reads, hashing, rules lookup, raw scans,
heuristics, and derived views remain in the timed path.

| Workload | Bytes | Baseline median | Candidate median | Ratio |
| --- | ---: | ---: | ---: | ---: |
| ASCII prose | 4,194,304 | 0.5138 s | 0.1293 s | 3.97x |
| Same text, UTF-16 | 8,388,610 | 0.5420 s | 0.1479 s | 3.67x |
| HTML entities | 4,349,648 | 0.6286 s | 0.2380 s | 2.64x |

[Raw measurements](text-scan-performance.json) include input hashes, all timings,
complete path-independent scan results, and candidate source hashes. All nine
scans per revision returned clean, with identical results across revisions.
These are local synthetic workloads, not a vendor-pack or production benchmark.
Unicode text containing joiners still takes the existing validation path.

## Regression evidence

- The unchanged `docs/research/probe_rule_coverage.py --verify` passed on the
  baseline and candidate: 70 library cases, 16 CLI operations, 16 local rules,
  no skips. Library and CLI observation records were identical.
- Five focused scanner cases passed for an ASCII entity introducing a hidden
  character, a variation selector entity, UTF-16 plus HTML decoding, a Latin
  joiner, and legitimate emoji/Persian joiners. These guard the risk of checking
  ASCII before decoding or bypassing required Unicode checks.
- Ruff lint/format and `mypy --strict src` passed. No workflow was changed.
  Broad pytest/selftest and platform coverage are assigned to hosted CI.

Reproduce in either checkout after `uv sync --frozen --group dev`:

```sh
uv run python docs/research/benchmark_text_scan.py
uv run python docs/research/probe_rule_coverage.py --verify
uv run pytest -q tests/test_text_fast_paths.py
```

For the baseline, run the candidate's benchmark script with the baseline
checkout's `src` on `PYTHONPATH`. The script reports its imported source root.
Use an owned `XDG_CACHE_HOME` to keep compilation caches disposable. No target
content is executed, no vendor pack is downloaded, and no operator gate home
is used.

## 2026-10-30: large base64 bodies (#112)

#112 reported a 21 MB `.eml` with a 15 MB base64 attachment, and the same bytes as
a bare `.txt`, ending `incomplete: timeout` at the default 30 s, and attributed the
time to `content.text_views`. Profiling on this host (Linux, Python 3.12.3, YARA-X
1.22.1) put most of it in YARA instead:

- `agent_base64_blob` was a 400-character class pattern, `[A-Za-z0-9+/]{400}`.
  It has no literal atom, so YARA-X verified it at every offset. On 1 MB of base64,
  `{400}` took 5.35 s, `{100}` 1.58 s, `{20}` 0.71 s, and a boundary-anchored form
  4.9 to 5.6 s. The literal-anchored media and executable patterns took 0.00 to 0.03 s.
  One YARA pass over 2.1 MB of base64 took 5.5 s on `main`, and the scanner runs a
  pass per derived view.
- `folded_text` ran a per-character Python filter whenever any character was below
  U+0020, which is every multi-line file, and folded leet digits inside base64 runs,
  which also produced a full-size `text-folded` view for YARA to scan again.

Changes: the scanner finds base64 runs with a linear `re` walk
(`heuristics.base64_run_signals`) and passes `yara_gate_b64_blob` and
`yara_gate_b64_exe` to YARA as globals. The two rules keep their ids, `source`,
and `verdict_on_match`. ASCII text drops control characters in `folded_text` with one
`str.translate`. The scanner ignores the two base64 rules on the `text-folded` view,
where folding turns `0` into `o` inside base64 and breaks the media exemptions; the
raw view carries the base64 verdict for the same bytes. (An earlier version of this
change left long runs unfolded instead. The Codex security review on #117 showed that
`/` lets a run absorb the first word of a phrase, so 195 `A`s plus
`//1gn0r3 previous instructions` scanned clean; that protection was removed.) A differential run of 200,000 random short texts
(controls, NBSP, U+3000, combining marks, confusables) gave identical output to
`main`'s `folded_text`.

`docs/research/benchmark_text_scan.py`, median of three `scan_file` runs, same host,
`main` `e3cee59` (its `src` first on `sys.path`) against this change:

| Case | Bytes | `main` s | this change s | Verdict (both) |
| --- | ---: | ---: | ---: | --- |
| `ascii.txt` | 4,194,304 | 1.579 | 0.622 | clean |
| `utf16.txt` | 8,388,610 | 1.638 | 0.895 | clean |
| `entities.html` | 4,349,648 | 1.751 | 0.776 | clean |
| `base64-run.txt` | 4,194,304 | 12.622 | 0.602 | advisory |
| `base64-wrapped.txt` | 4,304,680 | 5.878 | 0.837 | clean |

#112's fixture, `scan_bytes` with the default 30 s timeout:

| Input | `main` | this change |
| --- | --- | --- |
| 21.2 MB `.eml`, one 15 MB base64 attachment | 30.05 s, incomplete `timeout` | 5.87 s, block (`agent_bidi_*`, `agent_invisible_unicode` on the decoded random attachment: #109) |
| the same base64 body as a bare `.txt` | 30.01 s, incomplete `timeout` | 3.96 s, clean |
| 22.0 MB single base64 run | (not run; 4 MiB took 12.6 s) | 3.59 s, advisory `agent_base64_blob` |

The external-content probe (34 rows) and `probe_rule_coverage.py --verify
--benign-stdlib` returned the same verdicts before and after.
