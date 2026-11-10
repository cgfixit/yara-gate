# Linearized and MuPDF files, and where `startxref` is found — November 10, 2026

Base: main `2b6eda8` (Merge #204). Linux x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85
bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local` and `rules/rules.lock`.

## Defects

Both are in `pdfxref.py`, which resolves cross-reference offsets so that an annotation
hidden inside a length-proven stream cannot scan clean
([2026-11-07-pdf-annotations.md](2026-11-07-pdf-annotations.md)).

**Ordinary files were held.** A scan was `incomplete` with `pdf xref malformed` for:

| File | main |
| --- | --- |
| Chromium 153 export, re-saved plain by qpdf 11.9.1 (pikepdf 9.4.2) | clean |
| the same export saved with `linearize=True` | incomplete, `pdf xref malformed` |
| LibreOffice 24.2 export, re-saved plain | its usual `heuristic_pdf_OpenAction_goto` note |
| the same export saved with `linearize=True` | incomplete, `pdf xref malformed` |
| 6 two-page files written by MuPDF 1.28.6 (`doc.tobytes()`) | 5 incomplete, `pdf xref malformed` |

Three causes:

1. A linearized file's first-page trailer ends with `startxref` / `0`. The pointer readers
   use is the last one in the file. It names the first-page section, whose `/Prev` names the
   main one. Every `startxref` was followed, so offset 0, the `%PDF` header, was read as a
   section.
2. `_trailer` lexed 64 KiB past the `trailer` keyword. After a first-page trailer come
   objects and their stream bytes, and an open parenthesis there that does not close within
   the window fails the lexer.
3. `_classic` expected a subsection header or `trailer` right after the last entry. MuPDF
   writes a blank line there.

**The check could be walked around.** `_startxref_candidates` took the keyword only at the
start of a line, outside comments and strings, and it tracked strings from the top of the
file through stream bodies. One `(` byte in any stream left it inside a string to the end
of the file. On 79 of 132 real files it found no `startxref`, so the cross-reference check
did not run on them. Linearized files and small MuPDF files, where the first `startxref`
comes before any such byte, were the ones that reached the three causes above.

Readers do not lex around the keyword. With the hiding fixture of `tests/test_pdfxref.py`
(a link annotation inside a stream, reachable only through the table), these readers
return the hidden text: pypdf 5.1.0, pdfminer.six 20260107, PDFium 153.0.7999.0 (pypdfium2
5.13.0), and pdf.js 6.5.438.

| Where `startxref` is written | Readers that return the hidden text | main | this change |
| --- | --- | --- | --- |
| at a line start (control) | all four | incomplete | incomplete |
| a stream before the table holds one `(` | all four | **clean** | incomplete |
| inside a literal string at the end of the file | all four | **clean** | incomplete |
| inside a comment, `% startxref N` | PDFium, pdf.js | **clean** | incomplete |
| in the middle of a line | PDFium, pdf.js | **clean** | incomplete |
| inside an unclosed hex string | pypdf | **clean** | incomplete (`pdf xref malformed`) |
| at a line start, a vertical tab before the number | pypdf, pdfminer.six | **clean** | incomplete |
| at a line start, the number written `+N` | pypdf, PDFium, pdf.js | incomplete (`pdf xref malformed`) | the same |
| `%startxref`, with the number on the next comment line | none | clean | clean |

"Incomplete" is `pdf annotation xref offset inside stream` unless noted.

## Change

- **Candidates.** Every occurrence of the bytes `startxref` that a number follows is a
  candidate, wherever it is written. The bytes between the keyword and the number may be any
  that a reader skips as whitespace, a vertical tab among them.
- **Skipped.** An occurrence with no number after it, and one whose offset is 0. No reader
  gets a section from either.
- **Malformed.** A sign or a dot in front of the number. pypdf, PDFium, and pdf.js read
  `+12` as 12.
- **Trailer.** The lexer stops at the `startxref` that follows the dictionary.
- **Blank lines** between a classic table's subsections and before `trailer` are stepped
  over.
- **One parse per section.** A section many candidates or `/Prev` chains reach is parsed
  once per scan.

A pointer that leads nowhere other than offset 0 is still `pdf xref malformed`, as before.

## Results on real files

132 files: 121 generated in this container (single exports, merges of 2 to 20 sources, and
n-up sheets) and 11 third-party files (matplotlib's bundled icons). Writers: Chromium,
LibreOffice, pypdf, qpdf (plain, object streams, QDF, linearized), reportlab, fpdf2,
matplotlib, MuPDF, cairo, and PDFium.

| Files | main | this change |
| --- | --- | --- |
| 4 linearized single exports | incomplete, `pdf xref malformed` | the verdict of their plain saves: 2 clean, 2 with the open-action note |
| 2 linearized 5-source merges | incomplete, `pdf xref malformed` | advisory, `heuristic_pdf_text_unmapped`, as their plain saves |
| 5 MuPDF files | incomplete, `pdf xref malformed` | clean |
| 121 others | | identical verdicts and reasons |

Every one of the 132 now has its `startxref` found. On main the scanner found it in 53. No
file became incomplete. The ten that still are reach the 20,000-block limit of the text
reader first, which is unchanged here.

## Commands and results (this container)

- Full `uv run pytest -q tests`: 647 passed, 5 skipped.
- `tests/test_pdfxref.py`: 28 tests. Eleven of the new cases fail on main's `pdfxref.py`:
  the five placements of the keyword, the skipped mentions, the followed comment, the
  linearized file, the linearized file that hides an object, the blank line, and the
  section parsed once. The test that a `startxref` in a comment is not a candidate is
  replaced; PDFium and pdf.js take one.
- `docs/verification/check_worst_case_timing.py`: PASS, 29 inputs of exactly 4 MiB. The
  slowest was `pdf-page-objects.pdf` at 5.15 s.
- `check_added_rules.py`, `measure_precision.py --fail-over`,
  `probe_rule_coverage.py --verify`, and `probe_detection_gaps.py --verify` (222 `ok`):
  exit 0.
- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts` (24 files),
  `check_doc_links.py`, and `check_text_controls.py`: clean.
- `docs/verification/sweep_rule_changes.py` was not run: the change is to the scanner, not
  the rules. The run over the 132 real files above stands in for it.

Cost on 4 MiB inputs built for this reader, main → this change:

| Input | main | this change |
| --- | --- | --- |
| 30 `startxref`, each naming one table of 100,000 free entries | 7.02 s | 0.87 s |
| 30 `startxref`, each chained by `/Prev` to that table | 6.60 s | 2.04 s |
| 400,000 `startxref` with no number | 0.45 s | 0.22 s |
| 33 `startxref` with numbers | 0.11 s, incomplete | 0.11 s, incomplete |

The old scanner walked the file a byte at a time; the new one is one regular-expression
pass.

## Residual risks and boundaries

- **The check runs on more files.** Every file with a `startxref` now has its tables read. A
  writer whose table this reader does not decode (a filter other than Flate, an unsupported
  predictor) scans incomplete where the old scanner happened not to find the keyword. None
  of the ten writers tried does that.
- **Prose that looks like a pointer is held.** `startxref 99999` in an uncompressed comment
  or string is followed, leads nowhere, and makes the scan incomplete. The word with no
  number after it is not.
- **Four readers.** The table above is what four readers return. Another reader may find the
  keyword some other way.
- **Not a rendering check.** Which annotations a reader shows is still not resolved; every
  definition is inspected, as before.
- **Synthetic sample.** The hiding fixtures are synthetic and the real files locally
  generated. They are not a production false-positive rate.
