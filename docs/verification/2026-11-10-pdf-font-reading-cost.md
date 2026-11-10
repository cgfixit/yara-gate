# Cost of reading redefined PDF fonts — November 10, 2026

Main `838b11d` (the merge of [#206](https://github.com/cgfixit/yara-gate/pull/206)) failed
`check (macos-15)` at the worst-case timing tripwire:
`pdf-page-fonts.pdf: 10.093s exceeds 10s`. Ubuntu and Windows passed on the same commit, and
the macOS job passed on the commit before it, `8e3a8aa` (#209). No rule or verdict changed.

## Reproduction

`pdf-page-fonts.pdf` on this container (Python 3.12.3, YARA-X 1.23.0, three scans each, after
one warm-up scan):

| Revision | Seconds |
| --- | --- |
| `1b60986` (#205) | 5.92, 5.98, 5.82 |
| `8e3a8aa` (#209) | 5.85, 5.44, 5.46 |
| `838b11d` (#206) | 6.47, 6.75, 6.14 |

#206 adds about 10%. The macOS runner is about 1.6 times slower than this container on this
input, so a 6.2 s scan here crosses 10 s there. `cProfile` on the two revisions puts the
increase in `_fonts`: 2.2 s to 3.0 s, from 163,951 calls to `_FontReader.readings` and 16,397
calls to `_font`, which orders each font's definitions (`_likeliest`, the generation split) even
when the font has one.

## Change

- `_FontReader.readings` keeps its answer per set of references. The input has 163,951 names
  and 16,397 distinct reference sets.
- `_Definitions.__call__` returns at once for a font with exactly one definition, the usual
  case, which has nothing to order. The result is the one the general path gives: the same
  body, and the leading count is 1 when its generation is one a reference names.

## Results

- `pdf-page-fonts.pdf`: 5.74, 5.95, 6.36 and 5.84, 6.09, 5.94 s, against 6.09, 6.13, 6.16 s on
  `838b11d` and 5.94, 5.84, 6.18 s on `8e3a8aa` in the same session.
- `check_worst_case_timing.py`: PASS on 36 inputs; `pdf-page-fonts.pdf` 6.24 s,
  `pdf-font-definitions.pdf` 5.82 s.
- Behaviour is unchanged: 3,000 generated redefinition files (the set recorded in
  [2026-11-10-pdf-font-definitions.md](2026-11-10-pdf-font-definitions.md)) read the same on
  `838b11d` and here, the nine defect fixtures from that record give the same verdicts and rule
  ids, and 153 real PDFs have the same verdict and rule ids as main under the default policy.
- `pytest tests`: 785 passed, 5 skipped. Ruff, `mypy --strict src scripts` clean.

## Boundaries

- **The margin on macOS is still thin.** At the 1.6 ratio, 6.0 s here is about 9.7 s there. The
  rest of the cost is in the annotation reader (`_dictionaries`, 6.8 s under the profiler) and
  page map, which this change does not touch. A hosted run is the only evidence for the macOS
  number; none had run when this was written.
- This is a cost reduction, not a change to the 10 s limit.
