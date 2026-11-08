# Overflowing ToUnicode bfrange destinations — November 7, 2026

Base: main `43aba2e` (Reject every startxref a reader might use, #189). Linux
6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85 bundled local rules, zero
skips, no vendor download. Ruleset SHA-256
`4517a40579c9522edb8ad94babfee8cb338a4aded9fdb62d94f90133b3e35985`. Every scan used
a disposable copy of `rules/local` and `rules/rules.lock`.

## Defect

`_cmap_ranges` in `src/yara_gate/pdftext.py` turned each code of a
`<lo> <hi> <dst>` bfrange into `(base + offset).to_bytes(width, "big")`. When the
sum no longer fits `dst`'s width (`<0000> <00FF> <FFFF>`), Python raises
`OverflowError`. It escaped the PDF text reader, and the scan ended `incomplete`
with `content scan failed` (exit 2, quarantined). That fails closed, but any
such CMap held a benign PDF in quarantine, and the attack text behind it was
never read. The common off-by-one identity range `<0000> <FFFF> <0001>`
overflows at its last code and was incomplete too.

## What readers do

Read from each project's default branch on 2026-11-07 around 23:18 UTC (raw
source, SHA-256 of the fetched file in brackets). This is a source reading of
the CMap parsers. The readers themselves were not run.

| Reader | Source | One-unit `dst` past U+FFFF |
| --- | --- | --- |
| PDFium (Chrome, pypdfium2) | `core/fpdfapi/font/cpdf_tounicodemap.cpp` [`bb7c511e…`] | `value++` as `uint32_t`, then `Lookup` returns `value & 0xffff`: **wraps** |
| PDFBox (Tika) | `fontbox/.../cmap/CMapParser.java` [`6c1908d7…`], `pdmodel/font/CMapManager.java` [`bb43dc0a…`] | ToUnicode uses `new CMapParser()` (`strictMode = false`), so `increment` carries through every byte and the top byte wraps: **wraps** |
| pdfminer.six (pdfplumber) | `pdfminer/cmapdb.py` [`d15c31ca…`] | `struct.pack(">L", base + i)[-vlen:]` over the last ≤4 bytes: **wraps** |
| pdf.js (Firefox) | `src/core/cmap.js` [`ab3e85d9…`], `src/core/evaluator.js` [`83462eb6…`] | `mapBfRange` carries one byte, and that byte may exceed 0xFF. `readToUnicode` computes `(hi << 8) \| lo`, so the result is the **untruncated** sum (U+10000 and up) |
| MuPDF (PyMuPDF) | `source/pdf/pdf-cmap-parse.c` [`f6023ee5…`] | a 2-byte `dst` uses `pdf_map_range_to_range`; a longer `dst` does `dststr[i-1]++` on an `int`: **untruncated** last unit |
| pypdf | `pypdf/_cmap.py` [`e8eed582…`] | `unhexlify(b"%04X" % c)` on `0x10000` is odd-length and raises (not traced past `parse_bfrange`) |

Without an overflow, every reader in the table carries the increment into the
higher byte of a one-unit destination. ISO 32000-1 9.10.3 says only the last byte
increments, but none of these readers does that. PDFBox's strict mode stops at
the first last-byte overflow, but ToUnicode parsing does not use it. PDFium also
clamps `hi` to `lo`'s upper bytes, so it reads only the last-byte span of a
range.

Readers split into two camps, and each camp can show text the other does not.
With `<0000> <00FF> <FF80>`, code `0x80 + c` is `c` in PDFium, PDFBox, and
pdfminer.six, which is plain ASCII. In pdf.js and MuPDF the same code is
U+10000 + c, a Linear B syllable. With `<0000> <FFFF> <FFFF>`, pdf.js and MuPDF
put letters on Mathematical Bold (U+1D400 and up). An LLM reads those as letters,
and NFKC folds them to ASCII. The wrapping readers show Hangul there instead.

## Decision

Read the text both ways. The font's map takes the wrapped value: `(base + offset)`
masked to `dst`'s width, which is what PDFium, PDFBox, and pdfminer.six show.
Each overflowing code also gets a carried reading in a second map: `dst`'s
leading units unchanged, then `chr(last unit + offset)`, which lies between
U+10000 and U+1FFFE and is never a surrogate. For a two-byte `dst`, this is
pdf.js's and MuPDF's value. When any range overflows, `_font` returns a second
`Font` with the carried codes overlaid. `_fonts` lists every font's first reading
before any second reading, so a second reading never displaces another font
within `MAX_FONT_VARIANTS`. A later bfchar or bfrange entry for the same code
replaces both readings.

The cap is unchanged. The carried map holds only codes the primary map already
has, so the overlay is at most `MAX_CMAP_ENTRIES` entries. The linear CMap
lexer, the per-section `budget.check()`, and the non-overflowing path are also
unchanged. One `budget.check()` was added before the overlay copy.

Rejected options, measured on the same fixtures by patching `_cmap_ranges` in a
scratch script:

- **Stop the range at the overflow**: both attack fixtures become `clean` under
  every policy. That is a silent miss, which is worse than base's fail-closed
  `incomplete`.
- **Skip the entry**: not run separately. It drops a superset of what stopping
  drops (the pre-overflow codes as well), so it misses at least the same cases.
- **Wrap only** (one reading): misses the pdf.js/MuPDF Mathematical Bold case.
- **Carried only**: misses the PDFium/PDFBox/pdfminer ASCII case.
- **Spec-literal last-byte wrap** (`FFFF` + 1 → `FF00`): no reader examined does
  this, so it would give a third reading that matches no reader.

## Before and after

`check_added_rules._overflow_cmap_cases()` builds these fixtures, plus one where
the phrase is mapped by bfchar and an unrelated range overflows. The policy
columns are the overall verdict. The finding column shows the default policy's
findings.

| Reading | Fixture | default | agent-ingest | reason | findings |
| --- | --- | --- | --- | --- | --- |
| base `43aba2e` | all five | incomplete | incomplete | content scan failed | - |
| this change | `cmap-wrapped.pdf` | advisory | block | | agent_override_imperative |
| this change | `cmap-carried.pdf` | advisory | block | | agent_override_imperative |
| this change | `cmap-carried-plain.pdf` | clean | clean | | - |
| this change | `cmap-overflow-plain.pdf` (`<0041>` via `<0000> <00FF> <FFFF>`) | clean | clean | | - |
| this change | `cmap-bfchar-phrase+overflow.pdf` | advisory | block | | agent_override_imperative |
| stop at overflow | wrapped / carried | clean | clean | | - |
| wrap only | carried | clean | clean | | - |
| carried only | wrapped | clean | clean | | - |

CLI, with a disposable home, inbox, and rules root (`yara-gate scan <inbox file>
--home … --rules … --policy …`):

| Fixture | base exit / filed | change, default | change, agent-ingest |
| --- | --- | --- | --- |
| `cmap-carried.pdf` | 2 / quarantine (both policies) | 0 / clean | 1 / blocked |
| `cmap-wrapped.pdf` | 2 / quarantine (both policies) | 0 / clean | 1 / blocked |
| `cmap-overflow-plain.pdf` | 2 / quarantine (both policies) | 0 / clean | 0 / clean |

## Commands and results (this container)

- `uv run pytest -q tests/test_pdftext.py tests/test_pdf_text_folding.py tests/test_pdfannotations.py tests/test_pdfxref.py`:
  104 passed. Six of these are new `tests/test_pdftext.py` cases. They cover both
  readings, carries that do not overflow, the leading units of a wide destination,
  later entries replacing a carried code, the `MAX_CMAP_ENTRIES` cap, and
  `_font`'s second reading.
- `docs/verification/check_added_rules.py`: passed, 184 cases plus 4
  vendor-override cases (180 before). With the base `pdftext.py`, the four new
  cases fail as `incomplete content scan failed`.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 204 `ok`, no FAIL,
  STALE, or open cases. CLI agent-ingest intake filed every case as blocked.
- `docs/research/probe_rule_coverage.py --verify`: exit 0, with 531 library,
  55 CLI, and 9 benign observations and no failures.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 324 benign files,
  zero incomplete, no rule over the 2% bar.
- `docs/verification/check_worst_case_timing.py`: PASS, 24 adversarial 4 MiB
  inputs. None of them is a CMap case.
- `ruff check .`, `ruff format --check .`, `mypy --strict src` (20 files), and
  `check_text_controls.py` (276 files): clean.

Cost, from scratch timings (best of five, `_cmap` alone): a 65,536-code range
that does not overflow takes 54 ms (57 ms on base). The same range overflowing
on every code but the first takes 67 ms. End to end, a 57 KB PDF with 200 Type0
fonts on one page, each with its own `<0000> <FFFF> <dst>` CMap, scans `clean`
in 11.4 s on base with `dst = 0000`. With this change it scans `clean` in 12.7 s
(`0000`) and 17.0 s (`FFFF`; base: 0.08 s, `incomplete`). At 900 fonts the
`/Font` dictionary passes the 4 KB object window, and at 1,000 fonts the 2,000
stream cap makes the scan `incomplete`.

## Residual risks and boundaries

- **Pre-existing CMap amplification.** About 57 ms per 65,536-entry font, with no
  per-file entry budget, lets a ~57 KB file use about 11 s of the 30 s default
  deadline. The deadline still bounds it (the check runs between sections), and
  an overflowing map adds about 28 ms per font. A per-file CMap entry budget is
  a separate change.
- `MAX_FONT_VARIANTS` (4) still truncates a resource name's readings without
  reporting it. Second readings are ordered last, so this change never drops a
  font that base read, but a name already at four fonts gets no carried reading.
  (Follow-up: that truncation is now reported as `heuristic_pdf_text_unmapped`; see
  [2026-11-07-pdf-font-readings.md](2026-11-07-pdf-font-readings.md).)
- These cases follow the table above, not every reader:
  - pdf.js treats a carried value in U+1D800–U+1DFFF as a surrogate and shows a
    different code point there.
  - PDFium reads a wrapped low unit of 0xFFFF as a multi-character index.
  - PDFium's multi-unit increment uses `wchar_t`, so it differs between Windows
    and other platforms.
  - PDFium's `hi` clamp makes this scanner read more codes of a cross-byte range
    than PDFium does.
- For a destination wider than one unit, ranges that do not overflow keep this
  scanner's whole-value carry. pdf.js and MuPDF increment only the last unit
  there. That behavior is unchanged and out of scope.
- These are synthetic fixtures. They are not a production false-positive rate or
  a general prompt-injection guarantee. Hosted CI (Ubuntu, macOS, Windows) has
  not run on this change yet.
