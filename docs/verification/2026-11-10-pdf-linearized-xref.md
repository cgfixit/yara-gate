# Linearized PDFs and where `startxref` is found — November 10, 2026

Base: `main` at `2b6eda8`. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85
bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local` and `rules/rules.lock`, and CLI runs a disposable gate home. The scanner
executed, unpacked, and fetched nothing. Three pull requests were open
([#205](https://github.com/cgfixit/yara-gate/pull/205),
[#206](https://github.com/cgfixit/yara-gate/pull/206),
[#207](https://github.com/cgfixit/yara-gate/pull/207)); see [the last section](#open-pull-requests).

## Reproduced on main

Every linearized file was `incomplete`, `pdf xref malformed`. The same export saved without
linearization was not.

| File (qpdf 11.9.1 through pikepdf 9.4.2) | main `2b6eda8` | This change |
| --- | --- | --- |
| Chromium 153 `page.pdf()`, saved plain | clean | clean |
| The same, `linearize=True` | incomplete, `pdf xref malformed` | clean |
| LibreOffice 24.2 Writer export, saved plain | advisory (`heuristic_pdf_OpenAction_goto`, a note) | advisory, same note |
| The same, `linearize=True` | incomplete, `pdf xref malformed` | advisory, same note |

Under `agent-ingest` the LibreOffice file blocks, as its note always has. Through the CLI
with an inbox: on main both linearized files exit 2 and stay in `quarantine/`. With this
change the Chromium file exits 0 into `clean/`, and the same LibreOffice bytes submitted
under default, `agent-ingest`, and default again exit 0, 1, 0 and land in `clean/`,
`blocked/`, `clean/`.

Five faults in `pdfxref.py`, each read in the code and then observed:

1. **The dummy pointer.** A linearized file's first-page trailer ends `startxref`, `0`,
   `%%EOF`. Every `startxref` was followed, so offset 0, the `%PDF` header, was parsed as a
   section.
2. **The trailer lexer.** It lexed 64 KiB after `trailer`. After a first-page trailer come
   the first page's objects and their stream bytes, which do not lex. An incremental update
   that appends a binary stream after the old trailer fails the same way.
3. **Whitespace before `trailer`.** MuPDF 1.28.6 writes a blank line between the last entry
   and the keyword. The table reader took it for a broken subsection header, so any MuPDF
   file whose pointer was found was `pdf xref malformed`.
4. **The pointer search.** `_startxref_candidates` lexed the file from the top and tracked
   literal strings through stream bodies. One `(` byte in a stream left it inside a string
   to the end of the file. Of 194 real files here it found a pointer in 60, and 47 of those
   then failed on fault 1 or 3. The cross-reference check finished on 13 files.
5. **The offset lookup.** Each offset was compared with every stream span. A table of
   99,000 entries beside 1,000 streams took 4.2 s of a 4 MiB scan, with no deadline check
   inside the loop.

Fault 4 is also a way past the check. The table below has four files that scan clean on
main while readers show an annotation from inside a stream.

## What changed

- **Every occurrence of the bytes `startxref` is a pointer**, at most 32. A comment, a
  string, a letter before the keyword, or stream bytes before it make no difference, as
  they make none to a reader that searches backward for the bytes. A pointer with no number
  after it is still malformed.
- **A zero pointer is passed over only in a file that ends with a pointer every reader
  takes instead**: `startxref`, a non-zero offset, and `%%EOF`, each on its own line, then
  only whitespace. Anywhere else a zero pointer is malformed, as on main.
- **A linearized file's first-page section is checked by position.** When the first object
  in the first 1024 bytes is a dictionary with `/Linearized`, the section after its
  `endobj` is a candidate whether or not a pointer names it. A linearization dictionary
  with a comment or a string in it, or one that does not lex, is malformed: readers
  disagree where such an object ends.
- **A trailer dictionary is lexed up to the `startxref` after it.**
- **Whitespace may follow a table's last entry** before `trailer` or the next subsection.
- **The offset lookup bisects the spans** and checks the deadline every 4,096 offsets.

No rule id, severity, or incomplete reason was added.

One test changed its expectation. `test_startxref_inside_a_comment_is_not_a_candidate`
asserted that `% startxref 99999` and `(startxref 99999)` after a good file are ignored.
Readers do not ignore them, so the file is now `pdf xref malformed`, and
`test_startxref_is_found_wherever_its_bytes_are` covers the four spellings.

## What readers do with each shape

In every fixture, annotation object 5 lies inside object 4's stream, preceded by `QQ` so
the header check does not see it. The fixtures differ in how a reader could reach it.
"Phrase" means the reader returned the annotation's text.
[`probe_pdf_readers.py`](../research/probe_pdf_readers.py) builds the files and asks
whichever readers are installed; `--verify` fails when a reader shows the text and the scan
is not incomplete. It passes on this change and fails six fixtures on main.

Readers: pdf.js 6.5.438 (pdfjs-dist, Node 22), PDFium 153.0.7999.0 (pypdfium2,
`FPDF_LoadDocument`), MuPDF 1.28.6 (PyMuPDF), qpdf 11.9.1 (pikepdf 9.4.2), pypdf 6.17.0
(`strict=False`).

| Fixture | main | This change | pdf.js | PDFium | MuPDF | qpdf | pypdf |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Control: one table, one pointer | incomplete | incomplete | phrase | phrase | phrase | phrase | phrase |
| The same, one `(` byte earlier in the stream | **clean** | incomplete | phrase | phrase | phrase | phrase | phrase |
| Pointer written `% startxref` | **clean** | incomplete | phrase | phrase | phrase | phrase | refuses |
| Pointer written `Xstartxref` | **clean** | incomplete | phrase | nothing | phrase | phrase | refuses |
| Pointer inside `( ... )` | **clean** | incomplete | phrase | phrase | phrase | phrase | refuses |
| A real pointer to a benign table, then `% startxref` to the hiding one | **clean** | incomplete | phrase | phrase | phrase | phrase | nothing |
| A real pointer, then one with no `%%EOF` | incomplete | incomplete | phrase | nothing | phrase | phrase | nothing |
| `startxref %c`, offset on the next line | incomplete (malformed) | incomplete (malformed) | nothing | phrase | nothing | phrase | phrase |
| Linearization dictionary, hiding table after it, `startxref 0`, last pointer to a benign table | incomplete (malformed) | incomplete | phrase | nothing | nothing | nothing | nothing |
| The same without `startxref 0` | **clean** | incomplete | phrase | nothing | nothing | nothing | nothing |
| The same, `(endobj)` inside the linearization dictionary | incomplete (malformed) | incomplete (malformed) | nothing | nothing | nothing | nothing | nothing |
| `startxref 0` is the only pointer | incomplete (malformed) | incomplete (malformed) | nothing | nothing | nothing | nothing | phrase |
| Hiding table, `startxref 0`, benign table, canonical last pointer | incomplete (malformed) | clean | nothing | nothing | nothing | nothing | nothing |
| Hiding table, `startxref 0` with `%%EOF`, benign table, last pointer with no `%%EOF` | incomplete (malformed) | incomplete (malformed) | nothing | nothing | nothing | nothing | phrase |
| Benign table whose `xref` follows a letter; object 5 unlisted | clean | clean | nothing | nothing | nothing | nothing | nothing |

What the table decided:

- **Bytes, not tokens.** Rows 2 to 6 are clean on main and read by three to five readers.
- **The first-page section needs no pointer.** pdf.js reads the table after a linearization
  dictionary whose `/L` equals the file length (rows 9 and 10). Row 10 is clean on main.
  PDFium is believed to have the same path for progressive loading (`FPDFAvail`). That
  is an assessment from memory of its source, not run: pypdfium2 opens files with
  `FPDF_LoadDocument`.
- **Zero is not simply skipped.** A first version of this change passed over every zero
  pointer. Row 12 then scanned clean while pypdf showed the phrase: given 0, pypdf rebuilds
  the table from every `N G obj` it finds (`_find_pdf_objects`, read in 6.17.0), with no
  boundary before the number, so it finds `QQ5 0 obj` in the stream. The rule now needs the
  canonical ending. In row 13, the one zero-pointer shape that scans clean, no reader shows
  the phrase.

## Real files, before and after

194 files, 1,252 to 189,990 bytes. 37 were written by a tool and kept as written. Each of
those was also saved four ways by qpdf: plain, with object streams, linearized, and
linearized with object streams (148 files). Nine more are updates, merges, and MuPDF saves.
The content is inert text, tables, and one generated image.

Writers: Chromium 153.0.8010.12 (Skia/PDF), LibreOffice 24.2.7.2 (Writer, Calc, Draw, and
the web filter), cairo through poppler 24.02.0 `pdftocairo`, Ghostscript 10.02.1 `pdfwrite`
(with and without `-dFastWebView`, and at PDF 1.3), ReportLab 5.0.1, fpdf2 2.9.0, matplotlib
3.11.2, WeasyPrint 70.0, typst 0.15.2 (the Python package), img2pdf 0.6.3, PDFKit 0.20.2, pdf-lib 1.17.1 (classic
and object-stream output), jsPDF 4.2.1, and the two PDFs installed on the machine (a
ReportLab sample and a StarOffice 9 file shipped with LibreOffice).

| Files | Count | Incomplete on main | Incomplete now | Check finished on main | Check finished now |
| --- | --- | --- | --- | --- | --- |
| As written by the 13 writers, and the two installed files | 37 | 7 | 0 | 4 | 37 |
| qpdf plain | 37 | 0 | 0 | 1 | 37 |
| qpdf with object streams | 37 | 0 | 0 | 3 | 37 |
| qpdf linearized | 37 | 37 | 0 | 0 | 37 |
| qpdf linearized with object streams | 37 | 0 | 0 | 3 | 37 |
| pypdf 6.17.0 merge, three incremental updates, one attached PDF | 5 | 2 | 1 | 1 | 4 |
| MuPDF 1.28.6: new file, the same with object streams, an incremental save, a rewrite | 4 | 1 | 0 | 1 | 4 |
| Total | 194 | 47 | 1 | 13 | 193 |

**46 files change verdict, all from `incomplete` (`pdf xref malformed`) to the verdict of
their plain save. No file became incomplete, and no file's findings changed.**

| Files that changed | Count | Why they were incomplete on main | Now |
| --- | --- | --- | --- |
| qpdf linearized saves of all 37 sources | 37 | `startxref 0` (fault 1) | 24 clean, 13 advisory with the `/OpenAction` note their plain saves have |
| Ghostscript `-dFastWebView` output, as written | 6 | The same; Ghostscript linearizes these itself | 4 clean, 2 advisory |
| img2pdf output, as written | 1 | The same; img2pdf writes linearized files | clean |
| pypdf incremental update of a linearized file | 1 | The same | clean |
| MuPDF new file | 1 | Blank line before `trailer` (fault 3) | clean |

The qpdf saves that are linearized with object streams carry one pointer and no zero, which
is why they were not incomplete on main.

One file is incomplete before and after, for a reason this change does not touch: pypdf's
attached PDF sits uncompressed in a stream, so the outer span holds the inner file's
`endstream` keywords (`pdf annotation stream length unaligned`). Its inner `startxref` is
now a candidate as well and does not parse in the outer file.

All 83 linearized files (45 with a zero pointer, 38 with a first-page cross-reference
stream) have their first-page section named by a pointer too, so checking it by position
read no section twice and changed no real file. In the 193 files where the check now
finishes it resolves 7,537 offsets; none is inside a stream span and each begins an object
header. One pass over the 194 files took 10.6 s on main and 10.0 s now.

## Timing

`check_worst_case_timing.py`: PASS, 31 inputs of exactly 4 MiB. Two are new. No existing
PDF input holds a `startxref`, so this path was not timed before.

| Input | main | This change | Outcome |
| --- | --- | --- | --- |
| `pdf-xref-offsets.pdf`: one table of 99,000 entries, 1,000 empty landed streams | 4.21 s | 2.22 s | clean |
| `pdf-startxref-flood.pdf`: 4 MiB of pointers | 1.32 s | 1.29 s | `pdf xref malformed` at the 33rd |
| `pdf-page-objects.pdf` (the slowest input) | 4.83 s | 4.52 s | clean |
| `pdf-hidden-stretch.pdf` | 4.55 s | 4.20 s | clean |
| `pdf-white-areas.pdf` | 4.24 s | 3.62 s | clean |
| `pdf-font-readings.pdf` | 4.16 s | 3.58 s | advisory |
| `pdf-contents-arrays.pdf` | 3.71 s | 3.02 s | clean |

One run each. The other 24 inputs moved by at most 0.35 s, and every input has the same
verdict and reason on both revisions. The existing PDF inputs are faster because the old
pointer search walked all 4 MiB a byte at a time in Python.

## Commands and results

- `uv run pytest -q tests/test_pdfxref.py`: 22 passed. Eight are new. Six of them fail on
  main; the other two pin what must stay incomplete (the zero-pointer shapes and a
  linearization dictionary that hides its end).
- `tests/test_pdfxref.py`, `test_pdfannotations.py`, `test_pdftext.py`,
  `test_worst_case_timing.py`, and `test_scanner.py` together: 199 passed.
- Full `uv run pytest -q tests`: 641 passed, 5 skipped. Selftest and the macOS and Windows
  jobs are left to hosted CI.
- `docs/research/probe_pdf_readers.py --verify --pdfjs DIR` with the five readers: exit 0
  here, exit 1 on main with six fixtures.
- `docs/research/probe_rule_coverage.py --verify`: exit 0.
- `docs/research/probe_detection_gaps.py --verify`: exit 0.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete.
- `docs/verification/check_added_rules.py`: passed, 215 cases plus 4 vendor-override cases.
- `scripts/record_pages_demo.py --baseline web-demo/recordings.json`: 58 scenarios under 3
  policies, outcomes match; `web-demo/` is unchanged.
- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts` (24 files),
  `check_doc_links.py`, and `check_text_controls.py`: clean.
- `docs/verification/sweep_rule_changes.py` was not run. It compares two rule trees under
  one scanner, and this change is to the scanner. The real-file table above is the
  equivalent; this machine has two PDFs outside the generated sample.

To measure other files, run this on main and on the change and compare the lines:

```sh
uv run python docs/research/probe_pdf_readers.py --scan DIRECTORY
```

## Limits

- No file from Acrobat, Word, Quartz, pdfTeX, or iText was at hand. Their tables may hold
  a shape this reader calls malformed, as MuPDF's did, and the check now reaches every
  file with a pointer. That is the first thing to measure on a larger sample. A new
  `pdf xref malformed` on an ordinary file is a reader limit to fix, not a finding.
- A linearized file with anything but whitespace after its last `%%EOF`, or with its last
  pointer laid out another way, keeps `pdf xref malformed`.
- A file that merely mentions `startxref` in uncompressed bytes, with no parsable offset
  after the word, is `pdf xref malformed`. None of the 194 files does.
- `/Prev 0` in a trailer is still malformed.
- The readers were run through their Python and Node bindings, not their viewers. The
  fixtures show which pointer a reader takes, not what a person sees on screen.
- pypdf's rebuild accepts an object header with no boundary before its number, which
  `pdf object header inside stream` does not flag. Every shape found here that sends pypdf
  to its rebuild is incomplete for its pointer.

The second, fourth, and last of these are in the
[detection backlog](../research/detection-backlog.md).

## Open pull requests

Each head was merged into this change in a scratch worktree and the checks run on the
result. Nothing merged was pushed. #205 moved from `f83c738` to `94e00a8` while this change
was written; the figures are for `94e00a8`.

| Pull request | Files that conflict | Merged result |
| --- | --- | --- |
| [#205](https://github.com/cgfixit/yara-gate/pull/205) at `94e00a8` | `src/yara_gate/pdfxref.py` | Resolved as below: Ruff and `mypy --strict` clean, 289 PDF and scanner tests pass, timing PASS with 33 inputs, the gap probe exits 0, and the first 15 sources with their qpdf saves (75 files) have the verdicts in this record |
| [#206](https://github.com/cgfixit/yara-gate/pull/206) at `3707639` | `docs/verification/worst-case-timing.md`: the input count and one sentence | Both sentences kept, count 32: Ruff and mypy clean, 214 tests pass, timing PASS with 32 inputs, links resolve |
| [#207](https://github.com/cgfixit/yara-gate/pull/207) at `3f44e7d` | None | Ruff and mypy clean, 196 tests pass, timing PASS with 35 inputs, links resolve |

#205 found faults 1 to 3 as well and fixed them for its own caller: with `anywhere=True`
its `xref_tables` follows every occurrence of the bytes and skips a zero pointer, and with
`bounded` its `_classic` and `_trailer` accept the blank line and stop at `startxref`. The
default path, which the annotation reader uses, is unchanged there. Resolving the two:

- Keep its `XrefTables`, `_Listed`, and `xref_tables`, and this change's
  `_linearized_section` and `_section_starts`. Inside `xref_tables`, replace the candidate
  selection and the skip of offset 0 with a loop over `_section_starts(data, budget)`, and
  pass each start to `_section` with `listed`.
- `anywhere` and `bounded` then change nothing: this change's `_classic` and `_trailer` do
  both for every caller. They can be removed with the arguments that pass them.
- After the merge its page map sees a zero pointer the way the annotation reader does. In a
  file that does not end in a canonical pointer, `xref_tables` raises, and the map falls
  back to the file-wide font union, which is its conservative answer.
- Both changes add tests to `tests/test_pdfxref.py`, and Git merges them without a
  conflict. #205 names a helper `_linearized`; the helper here is `_first_page_file` so the
  later definition does not replace the earlier one.
- Its backlog row "`_startxref_candidates` misses `startxref` after binary stream bytes"
  is closed by this change.
- It adds `docs/research/probe_pdf_reader_agreement.py`, which runs readers on page text.
  `probe_pdf_readers.py` here asks them for annotation text on cross-reference shapes. The
  reader shims overlap and could be shared once both are on main.

`worst-case-timing.md` states the input count by hand, and all four changes set it.
Whichever merges later has to write the number the script prints.
