# Scan overhead outside the scan — October 23, 2026

Starting point: clean `main` at `647dce435a2b6995de7be4620143bd31874e4af6`. Python 3.12.3,
YARA-X 1.22.0, Linux in a shared 4-CPU container running as root. Inert synthetic text,
copied local rules, synthetic one-rule vendor files, disposable gate homes and cache
directories. No target was executed and nothing was downloaded. Not measured: macOS, native
Windows, or the real vendor packs.

## What was slow

A caller that shells out once per file (the CyClaw/Harness pattern in
[the integration guide](../integrations.md)) pays process startup on every file, and a
directory scan or `watch` pays rules-directory bookkeeping on every file. On the baseline:

- A one-file `scan` took 0.29–0.32 s, while `--version` alone took 0.24–0.32 s. Building
  pydantic's schemas for `Finding`/`ScanResult` and the rules lock accounted for roughly half
  of the import time; the scan itself was about 20 ms.
- Per-file cost grew with the number of vendor rule files: each scanned input re-listed the
  rules tree several times, built a `Path` per rule file to compute its key, and queried
  package metadata for the engine version. cProfile put most of it in `ruleset_digest`.

## What changed

- `models.py` and the rules lock use dataclasses. `ScanResult` and `Finding` keep
  `model_dump(exclude=...)` and `model_dump_json()` with the shape they had; reports, SARIF and
  `rules.lock` bytes are unchanged. `pydantic` stays a dependency for the demo's request
  models, which load only when `demo` runs. Pydantic-only methods such as `model_validate` on
  `ScanResult`/`Finding`, `model_copy`, and `model_fields` no longer exist.
- `compile_ruleset` lists the rules once and hands the list to `ruleset_digest`; rule keys
  come from string slicing with `relative_to` as the fallback; the installed-vendor inventory
  check does the same; the engine version is looked up once.

## Evidence

Direct runtime, all on the changed tree, compared against the baseline:

- A golden harness captured 16 sections from the unmodified tree and again after the change:
  model dumps, SARIF/compact reports, `rules.lock` bytes for four locks and the checked-in one,
  12 lock-validation outcomes, ruleset digests for checkout/overlay/inventory trees with
  awkward names (`a.x/c.yar` vs `a/b.yar`, case, non-ASCII), rule order, compile results, a
  missing-inventory scan, and 28 scan reports (14 inputs, both policies: ZIP, gzip, tar,
  UTF-16, HTML entities, a double extension). All sections were identical.
- `docs/research/probe_rule_coverage.py --verify --benign-stdlib` passed with zero failures
  before and after.
- The live demo, started with copied rules, returned clean/0, advisory/0 and block/1 for the
  same text under the two policies, and rejected a cross-origin request, a wrong content type
  and a sample+text body.
- 114 tests in the models, rules, report, CLI, demo, scanner, quarantine, hunt and text-path
  modules gave the same result on both trees (112 passed, 1 skipped, 1 failed). The failure, `test_missing_bundled_rules_exit_2`, `chmod`s a
  rule unreadable and so fails for a root user on `main` too. With the 23 added tests the same
  modules give 135 passed. This is not the full suite; the Ubuntu/macOS hosted CI result for the
  published head is separate.
- Profiling found a bug in the first version of this change: a loop variable overwrote the
  digest cache key, so every scan reread every rule file. The cache now hits (0 reads on a
  repeat call) and an edit, deletion or addition is still noticed. New tests cover that, key
  equivalence, lock validation and a no-pydantic import guard; each was confirmed to fail when
  its bug or mutation was reintroduced.

```sh
uv sync --frozen --group dev
uv run python docs/research/benchmark_scan_overhead.py
```

Three alternating before/after rounds of that script (median of 9 fresh processes; 30
in-process scans per tree):

| Metric | Baseline | Changed |
| --- | ---: | ---: |
| `scan` of one file, fresh process | 0.29–0.32 s | 0.19–0.22 s |
| `--version`, fresh process | 0.24–0.32 s | 0.18–0.20 s |
| per file, 0 vendor files | 3.4–5.6 ms | 1.4–1.5 ms |
| per file, 300 synthetic vendor files | 45–50 ms | 6–10 ms |
| per file, 800 synthetic vendor files | 116–158 ms | 15–29 ms |

Run-to-run noise on this shared VM is large; read the ratios (about 1.5× per process, 3–6× per
file), not the absolute times. The vendor files are one-rule synthetic files with a recorded
inventory, not the real packs, so the per-file curve shows the shape rather than a production
figure.

## Remaining cost

Startup is still about 0.17 s above a bare interpreter: Typer, package-metadata lookup for the
engine version, and `urllib` imported for the download code. Per-file cost at hundreds of
vendor files is now dominated by re-walking and sorting the rules tree on every input; skipping
that walk safely needs a directory-change check that tolerates coarse filesystem timestamps, so
it was not attempted here.
