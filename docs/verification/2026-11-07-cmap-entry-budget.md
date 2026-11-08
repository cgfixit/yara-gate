# Per-file ToUnicode CMap budget

Date: 2026-11-07 to 2026-11-08 (UTC). Base `43aba2eb7615e6352dc1cf2238596fd31c92410d` (`main`). Linux
container x86_64, Python 3.12.3, YARA-X 1.23.0, 85 compiled bundled local rules,
zero skipped rule files, disposable rules roots, no vendor packs or downloads.
Every timing is one `scan_bytes` run after a rule warmup, not a benchmark.

## Defect

`pdftext.py` parsed each font's ToUnicode CMap on its own. `MAX_CMAP_ENTRIES`
(131,072) capped the distinct codes in one map, but nothing capped the work across
fonts or the writes inside one map, and `budget.check()` ran only between sections.
Three costs followed.

1. **Entries across fonts.** One 20-byte `<0000> <FFFF> <0000>` bfrange writes
   65,536 entries, about 60 ms and 8.6 MB. 200 fonts with their own maps cost
   13 s and roughly 1.8 GB of maps. Fonts that shared one ToUnicode object each
   parsed it again, because the cache was keyed by font object.
2. **Overwrites inside one map.** A repeated range overwrites the same 65,536
   codes, so `len(mapping)` never reaches the per-map cap. A 664-byte file with
   600 repeats ran past the 30 s deadline before the next check.
3. **Lexing.** The section regex `begin(kind)(.*?)end\1` rescans to the end of the
   map from every unclosed `begin`. That is quadratic, inside one `finditer` call
   with no deadline check. Each section's tokens were also materialized as one
   list before any check. The 2026-11-07
   [detection review](../reviews/2026-11-07-detection-review.md) noted the second
   point as an unmeasured source observation.

## Change

- `MAX_CMAP_TOTAL = 4 * MAX_CMAP_ENTRIES` (524,288) counts every entry a file's
  maps write, overwrites included. Each section is charged before it writes:
  bfchar per pair, a bfrange by its code count, an array bfrange by its targets.
  Past the budget, `ContentLimit("pdf cmap entries exceed 524288")` makes the scan
  incomplete.
- `MAX_CMAP_TOKENS = 3 * MAX_CMAP_TOTAL` (1,572,864) counts CMap tokens per file.
  Each section is charged before lexing, by `bytes.count` of `<`, `[`, and `]`,
  which bounds the `_CMAP_TOKEN` matches. A well-formed entry takes two tokens
  (bfchar) or at most three (a one-code bfrange), so any map within the entry
  budget is within the token budget. Past it the reason is
  `pdf cmap tokens exceed 1572864`.
- `_cmap_sections` replaces the lazy section regex. It searches `begin(kind)`,
  then `find`s `end<kind>`. A kind with no `end` left is never searched for again,
  and each `begin` runs `budget.check()`. On 200,000 random marker sequences its
  output matched the old regex exactly.
- `_Cmaps` caches parsed maps by ToUnicode object number, so fonts sharing a map
  parse it once and share the dict. Fonts only read maps. The per-map
  `MAX_CMAP_ENTRIES` cap, the `_CMAP_TOKEN` lexer, and the existing deadline
  checks are unchanged.

## Before and after

Small synthetic fixtures, each with one page drawing `Hi` in `/F0`, Type0
`/Identity-H` fonts, and FlateDecode maps `<0000> <FFFF> <0000>`:

| Input | Bytes | Base 43aba2e | This change |
| --- | ---: | --- | --- |
| 200 fonts, 200 maps | 59,295 | 12.97 s, clean | 0.63 s, `pdf cmap entries exceed 524288` |
| 1 font, range repeated 600 times | 664 | 35.85 s, `timeout` | 0.53 s, `pdf cmap entries exceed 524288` |
| 200 fonts, 1 shared map | 22,480 | 13.55 s, clean | 0.09 s, clean |
| 8 fonts, 8 maps (at the budget) | 2,651 | not run | 0.55 s, clean |
| 9 fonts, 9 maps | 2,943 | not run | 0.54 s, `pdf cmap entries exceed 524288` |

Lexing floods. Each is one font whose FlateDecode map inflates to the stated size.
Max RSS is the process peak:

| Map content | Bytes | Base 43aba2e | This change |
| --- | ---: | --- | --- |
| 0.25 MiB of unclosed `beginbfchar ` | 905 | 27.79 s, advisory, 45 MB | 0.03 s, advisory, 45 MB |
| 4 MiB of unclosed `beginbfchar ` | 8,529 | killed at 300 s, still running | 0.34 s, advisory, 57 MB |
| 90 MiB bfchar `<0048> <0048>` | 183,610 | 19.99 s, advisory, 1,142 MB | 4.57 s, `pdf cmap tokens exceed 1572864`, 317 MB |
| 90 MiB bfrange `<00> <00> <00>` | 183,602 | 28.99 s, advisory, 461 MB | 4.82 s, `pdf cmap tokens exceed 1572864`, 317 MB |
| 90 MiB codespacerange `<00> <FF>` | 183,603 | 19.29 s, advisory, 533 MB | 4.80 s, `pdf cmap tokens exceed 1572864`, 317 MB |
| 90 MiB bfrange of `[` | 92,130 | 31.49 s, `timeout`, 1,037 MB | 4.97 s, `pdf cmap tokens exceed 1572864`, 317 MB |

In the 90 MiB rows, CMap work is about 0.3 s of the candidate's time (cProfile on
the `[` row: `_cmap` 0.30 s of 4.9 s). The rest is the existing raw and
`pdf-flate` views, YARA, and base64 signals over the inflated stream. This change
does not alter them. Every base row that finished reported a complete verdict,
except the `[` flood, which overshot the 30 s deadline. A complete verdict after
20 s of CMap work is the outcome this change replaces with a named, early reason.

## Worst-case timing tripwire

[`check_worst_case_timing.py`](check_worst_case_timing.py) has three new 4 MiB cases:

| Case | Base 43aba2e | This change |
| --- | --- | --- |
| `pdf-cmap-fonts.pdf`: 200 fonts, own FlateDecode maps, padded | 13.56 s, clean: over the 10 s ceiling | 0.86 s, `pdf cmap entries exceed 524288` |
| `pdf-cmap-sections.pdf`: one unfiltered map of unclosed `beginbfchar ` | killed at 120 s (watchdog 20 s) | 1.21 s, advisory |
| `pdf-cmap-tokens.pdf`: one unfiltered bfrange section of `[` | 2.28 s, advisory: missing reason | 0.41 s, `pdf cmap tokens exceed 1572864` |

The token case is a reason check. A 4 MiB unfiltered flood is not slow on base.
Its cost comes from inflation, as in the 90 MiB rows, and a 4 MiB inflating case
would mostly time the existing views. The full tripwire, 27 cases, passed locally.
Every case finished within 6.6 s.

## Real PDFs with many subset fonts

PDFs made in this container from local HTML (benign Latin, Greek, Cyrillic, and
3,000 to 4,000 CJK, kana, and Hangul glyphs over every installed font family and
style). Entries written comes from instrumenting `_Cmaps`:

| Generator | Bytes | ToUnicode maps | Entries written | Budget used | Verdict, base and change |
| --- | ---: | ---: | ---: | ---: | --- |
| LibreOffice, 29 families x 4 styles + CJK | 3,177,958 | 101 | 18,772 | 3.6% | advisory, both |
| LibreOffice, 29 families x 4 styles | 1,885,328 | 73 | 11,796 | 2.2% | advisory, both |
| Chromium, 26 families x 2 weights | 1,304,765 | 84 | 5,285 | 1.0% | clean, both |
| Chromium, 3,000 CJK glyphs | 519,858 | 1 | 3,000 | 0.6% | clean, both |
| Skill theme showcase (existing file) | 124,310 | 6 | 768 | 0.1% | clean, both |
| LibreOffice `xpdfimport_err.pdf` (existing file) | 21,204 | 1 | 23 | 0.0% | advisory, both |

The advisory results come from rules unrelated to CMaps (`agent_base64_blob` on
embedded font data and `heuristic_pdf_OpenAction_goto`), and were the same on
base. Chromium pages that use every installed family, or the Unifont bitmap
fonts, ended `pdf streams exceed 2000` on base and on this change before any font
was read, so they say nothing about CMaps. These are a handful of generators and
documents, not a production false-positive rate. A file whose maps really pass
524,288 entries, such as more than eight fonts each mapping all 65,536
two-byte codes, now ends incomplete and stays quarantined.

## Checks

- `uv run python docs/verification/measure_precision.py --fail-over`: passed. 324
  files, 0 incomplete.
- `uv run python docs/verification/check_added_rules.py`: 180 added-rule cases
  and 4 vendor-override cases passed.
- `uv run python docs/research/probe_detection_gaps.py --verify`: 204 rows, all `ok`.
- `uv run python docs/research/probe_rule_coverage.py --verify`: passed.
- `uv run python docs/verification/check_worst_case_timing.py`: 27 cases passed.
- `uv run pytest -q tests/test_pdftext.py`: 13 passed. New tests cover: nine
  separate maps, nine repeats in one map, and 200 maps past the entry budget; a
  shared map and eight maps read within it; the token budget; and unclosed
  sections in linear time. The old regex on that last input was still running
  when a 60 s timeout killed it.
- Ruff check and format, `mypy --strict src`, and
  `check_text_controls.py`: clean.

Full pytest, selftest, and macOS and Windows runs are left to hosted CI.

## Interaction with the overflow branch

`claude/sweet-tesla-ubj0gd` (`23e47a8`, recorded in its own
`2026-11-07-cmap-range-overflow.md`, not on `main` at this base) gives an
overflowing bfrange a second, carried reading. Its `_font` builds that reading as
`{**cmap, **carried}`, a second dict per font. Whichever change merges second
should charge the copy to `MAX_CMAP_TOTAL`, and should cache the carried reading
by map object, so fonts that share an overflowing map do not each copy it. The
range charge here already covers the loop that fills both readings.
