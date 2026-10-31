# Leet folding in linear time — October 31, 2026

Baseline: `main` `03e2404`. Head: `5d6d3c8`. Python 3.12.3, YARA-X 1.22.1, Linux x86_64 (root
container). Shipped local rules only: 80 compiled, 0 skipped. No vendor pack was installed, no
target was executed, nothing was fetched, and every CLI scan used a fresh disposable home.

## Defect

`folded_text` in `content.py` builds the `text-folded` view. Its last step is
`_LEET_TOKEN.sub(_fold_leet, folded)`, with
`[^\W_]*[0134578@$][^\W_@$]*(?:[0134578@$][^\W_@$]*)*`. On a run of letters with none of
`0134578@$`, the engine can start at every position of the run. From each start, `[^\W_]*`
reads to the end of the run and then backs off one character at a time looking for a stand-in.
The cost is quadratic in the run length, and it is spent inside a single `re.sub` call, which
the scan deadline cannot interrupt.

| Letters-only token | `_LEET_TOKEN.sub` on `main` |
| --- | --- |
| 5,000 | 0.17 s |
| 10,000 | 0.63 s |
| 20,000 | 2.90 s |
| 40,000 | 11.85 s |

Observed through the CLI on `main`:

- A 120 KB `.txt` (ten words, then 120,000 `q`): `incomplete: timeout`, exit 2, after
  **100.8 s** against the 30 s default. The deadline is checked only after the call returns.
- A DOCX built with python-docx 1.2.0 holding an 800x600 grainy mid-tone BMP
  (`word/media/image1.bmp`, 1.44 MB of pixels in `h`-`r`): killed at the 120 s wall cap. By the
  table, it would take about four hours. This came up while surveying DOCX image members for
  the PDF image-as-text work. The same member also gives the raster false positive that
  `claude/raster-image-kinds` addresses separately.
- `yara-gate-final-rejection.jpg` saved as TIFF in a DOCX finishes in 2 s. Real photographs and
  screenshots contain digit bytes, which end the token. The trigger is a long run with no
  stand-in: synthetic grain, flat letter-range art, or any text an attacker writes.

Every shape that went quadratic in a sweep of `text_views` traces to this one pattern. That
includes letters, uppercase, base64 without digits, Cyrillic, and mixed-script tokens. It also
includes `a a a ...`, `a_a_...`, and ZWSP-split letters, because `_SPACED` and the control filter
rejoin those into one run. Digits, spaces, dots, entities, JSON escapes, tabs, and hyphenated
words were linear. Heuristic checks (`joiner_findings`, `tag_findings`, `base64_run_signals`)
were linear for every shape.

## Change

```python
_LEET_TOKEN = re.compile(r"(?<![^\W_])(?<![@$])(?:[^\W_]|[@$])*?[0134578@$](?:[^\W_]|[@$])*")
```

The match may start only where the previous character is not a letter, digit, `@`, or `$`, which
is the first character of a run. It finds the first stand-in lazily and then takes the rest of
the run. A start inside a run fails on the lookbehind in constant time, so each run is read a
bounded number of times. The old pattern also matched only whole runs: its leftmost match
starts at a run's first character, since `@` and `$` are themselves stand-ins, and extends to
the run's end. So the matches are the same.

## Verification

- **Same matches.** 200,000 random strings of 0 to 24 characters drawn from letters, `0`-`9`,
  `@`, `$`, `_`, `-`, `.`, whitespace, Cyrillic, `é`, Arabic-Indic digits, ZWSP, and punctuation:
  `finditer` spans are identical for old and new on every string.
- **Same views.** All `text_views` output (every derived view, `text-folded` included) is
  byte-identical, old pattern against new, on 484 files. These are the 310-file precision
  corpus plus the repository's Markdown, Python, YARA, text, HTML, and JSON files; 200 of them
  produce a `text-folded` view.
- **Time.** A letters-only token of 40,000 takes 0.007 s, of 1.4 million 0.66 s, and of 2.8
  million 1.05 s. The `text_views` sweep is at or below 0.02 s for every shape at 40,000
  characters, against 2.8-13.9 s before.
- **CLI.** The 120 KB `.txt` now takes 0.053 s and is `advisory` (`agent_base64_blob`: 120,000
  letters are a base64 run). The grainy BMP DOCX finishes, and its findings are that raster false
  positive.
- **DOCX rescan.** 45 DOCX files without BMP or TIFF members, under default, agent-ingest, and
  agent-document. They are the 12 repository screenshots and two synthetic images as PNG, JPEG,
  and GIF, LibreOffice 24.2 exports of `README.md` and `docs/rules.md`, and a README build with a
  screenshot. All 135 scans are identical on `main` and head. The three text documents keep
  their documentary phrase findings.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src tests && uv run ruff format --check src/yara_gate tests
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_text_fast_paths.py
```

- Probe at `5d6d3c8`: passed, 0 failures; 531 library, 55 CLI, and 109 benign observations; 3
  failure paths.
- Rule pairs: passed (105 rules).
- Precision: 310 files, 0 incomplete, exit 0; the per-rule table is identical to `main`'s.
- Ruff, format, strict mypy, and the text control check: clean.
- `test_a_long_letters_only_token_folds_in_linear_time` (200,000 letters, then a leet phrase,
  under 10 s) passes on head in a fraction of a second. On `main` it was killed at 60 s. All 11
  tests in `tests/test_text_fast_paths.py` pass. The broad pytest and selftest suites are left to
  hosted CI.

## Remaining

- Python's `re` cannot be preempted. A future pattern with the same shape would stall the same
  way, and the deadline is checked only between calls. A per-view time test over long
  single-class runs would catch the next one. The sweep script used here is not in the
  repository.

## Memory follow-up: single-class repeats only

The lazy pattern above, `(?<![^\W_])(?<![@$])(?:[^\W_]|[@$])*?[0134578@$](?:[^\W_]|[@$])*`, fixed the
quadratic rescan but repeats a group that holds an alternation. Python's `re` runs a repeat of
one character class (`[^\W_]*`) without saving state, and saves backtracking state for every
iteration of a repeated group. Measured on the pattern alone, one process per size (hex token,
`finditer`, peak RSS above the text itself):

| Token | `main` | lazy pattern |
| --- | --- | --- |
| 8.4 M characters | 0.12 s, +0 MB | 4.8 s, +954 MB |
| 33.6 M characters | 0.54 s, +0 MB | 15.1 s, +3.8 GB |
| 67.1 M characters | 0.82 s, +0 MB | 28.6 s, +7.7 GB |

That is about 114 bytes per character. A file near the 100 MB limit that is one alphanumeric
token would need over 10 GB, so the scanner process can be killed or fail with `MemoryError`
instead of ending `incomplete`. End to end, a 23 MB hex file took 16.5 s against 1.5 s on
`main`, so about 40 MB of hex would reach the 30 s timeout that `main` does not.

The pattern is now `main`'s own, with only the start anchor added:

```python
_LEET_TOKEN = re.compile(r"(?<![^\W_])[^\W_]*[0134578@$][^\W_@$]*(?:[0134578@$][^\W_@$]*)*")
```

Every repeat is a single character class, and the match can start only at the first character
of a run, so a letters-only run is backtracked once, not once per position.

Evidence, direct runtime on this head:

- Spans from `finditer` equal `main`'s pattern on 200,000 fuzzed strings of up to 14 characters
  (letters, digits, `@`, `$`, `_`, `-`, space, `.`, `,`, Cyrillic, an Arabic-Indic digit, a
  ZWSP, `é`). The lazy pattern also matched all 200,000.
- Pattern alone, 67 M characters: hex 1.09 s, +0 MB (lazy pattern 46.7 s, +7.7 GB); letters run
  ending in one stand-in 0.56 s, +0 MB (lazy 42.6 s, +7.6 GB). 8 M letters-only: 0.29 s, +0 MB
  (lazy 6.2 s, +899 MB; `main` did not finish in 150 s).
- End to end through `scan_bytes`, default policy: a 23.1 MB hex token 1.94 s; an 8.4 MB
  letters-only token 0.56 s; 200,000 letters followed by `1gn0r3 previous instructions` 0.02 s
  with `agent_prompt_injection_phrases` on the `text-folded` view.
- `test_leet_token_matches_the_unanchored_pattern_and_uses_constant_memory` compares spans with
  the earlier pattern on 15 shapes and bounds `tracemalloc` growth on a 1 M-character hex
  token to 10 MB. On the lazy pattern it fails (122 MB of growth); on this head it passes.
- Full suite 369 passed, 1 skipped. Ruff check and format, `mypy --strict src`, `lint_rules`,
  `check_rules_lock`, `check_rule_pairs`, `check_added_rules`, `measure_precision --fail-over`,
  `check_text_controls`, `check_scan_only`, the probe with `--verify --benign-stdlib`, and
  selftest pass.

The same limit as above applies: `re` cannot be preempted, and a memory test only catches the
shapes it builds.
