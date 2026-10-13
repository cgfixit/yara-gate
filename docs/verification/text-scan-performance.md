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
