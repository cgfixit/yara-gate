# PDF font resource dictionaries, read as readers read them — November 10, 2026

Base: main `2b6eda8`. Ubuntu 24.04.5 container (Linux 6.18, x86_64), Python 3.12.3,
YARA-X 1.23.0, 85 bundled local rules, zero skips, no vendor download. Every scan used a
disposable copy of `rules/local`; every CLI scan used a disposable home.

Evidence labels: **runtime** is this tree run here. **Readers** are six PDF text
extractors run here on the same fixture bytes, in a throwaway environment that is not a
project dependency: pypdf 5.1.0, pdfminer.six 20260107, pypdfium2 5.13.0 (PDFium
153.0.7999.0), PyMuPDF 2.1 (MuPDF 1.28.6), poppler `pdftotext` 24.02.0, and pdfjs-dist
6.5.438 under Node 22. No reader source was read; what a reader does is what it did on
these files. Nothing here is a production false-positive rate.

## Defect

`pdftext._fonts` builds one file-wide map from a font resource name to the fonts it names.
On the base it found the names with three regular expressions: `/Font`, spec whitespace,
`<<`, at most 8,192 bytes, and the first `>>`; `/Font N G R`; and `/Name N G R` inside what
those matched. A reader does not parse that way. It lexes tokens, and each reader's lexer
accepts more than the specification's grammar. Text shown in a font the regular
expressions did not see was decoded through whatever else the name meant, or as WinAnsi
bytes, and the scan was clean.

The fixture is `yara_gate.samples.font_resources_pdf`: one page with a classic
cross-reference table that shows the test phrase of `tests/test_pdftext.py` as glyph ids
numbered from 3 in order of first use, so no view but the font's `ToUnicode` map holds the
phrase. Object 6 is the font that reads it. Object 7 is another font whose map reads each id
seven characters along, and an unused object makes `/F1` mean that font, so the name always
has a readable wrong meaning in the union. A reader that extracts the phrase followed the
row's spelling to object 6.

The rows this work was asked about, where the page's dictionary is
`/Font << /F1 7 0 R /F1 <spelling> >>`:

| Spelling | Readers that showed the phrase | main `2b6eda8` | This change |
| --- | --- | --- | --- |
| `6 0 R` (control) | pdfminer.six, PDFium, MuPDF, pdf.js (last copy); pypdf and poppler keep the first | found | found |
| `6.0 0 R`, `6. 0 R`, `6 0.0 R` | pdfminer.six, PDFium, pdf.js | **clean** | found, and reported |
| `+6 0 R`, `6 +0 R`, `6- 0 R` | pdfminer.six, PDFium, MuPDF, pdf.js | **clean** | found, and reported |
| `6 0R` | pdfminer.six, pdf.js | **clean** | found, and reported |
| `6<VT>0 R`, `6 0<VT>R` | pdfminer.six | **clean** | found, and reported |
| `/Font << /F1 7 0 R >> /F#6Fnt << /F1 6 0 R >>` | pdfminer.six, PDFium, MuPDF, poppler, pdf.js | **clean** | found |
| `/F1 10 0 R`, object 10 is `6 0 R` | pdfminer.six, MuPDF | **clean** | found |
| `/F1 6 0 R /F1 7 0 R` (first copy) | pypdf, poppler | found | found |

"Found" is `agent_override_imperative` from the `pdf-text` view. "Reported" is the note
`heuristic_pdf_text_unmapped`. The reader columns reproduce the table in the task exactly.

Running the same fixture through more shapes showed that the listed rows were the narrow
end of the problem. These were also **clean on main**, and every one of the six readers
showed the phrase:

| Shape | Why the base missed it |
| --- | --- |
| `/F1 << /Type /Font … /ToUnicode 5 0 R >>`, a font dictionary in place of a reference | Only references were read |
| 9,000 spaces inside the `/Font` dictionary before the entry | The 8,192-byte window |
| `/Font 11 0 R` where object 11 holds 5,000 spaces before the entry | The object lookup's 4 KB window |
| `/#46ont` or `/Fon#74` as the key | The key was matched literally |
| `/Font`, a comment, then `<<`; or a comment holding `>>` before the entry | No comments in the expressions; the first `>>` ended the match |
| `00000000006 0 R` | Ten digits at most |

Five of six showed it for an empty dictionary or a string holding `>>` before the entry
(the lazy match stopped there), and PDFium alone for `/F1<80>6 0 R`: it takes 0x80 and 0xFF
for whitespace, so the name ends early.

On the base the gate also spent 39.7 s in `pdf_text` on 4 MiB of `/Font<<`: the lazy
`.{0,8192}?>>` rescanned 8 KiB from every key, inside one `finditer` with no deadline check.
4 MiB of small objects each named by its own `/Font N 0 R` took 13.5 s, because each lookup's
4 KiB window was kept and searched whole.

## Decision

Two options were on the table: widen the regular expressions to the spellings observed, or
report the unmapped note when a `/Font` dictionary holds a value that is not a plain
reference. Neither alone is enough.

- **Widening is not enough** because the spellings are open-ended and the structure is the
  larger half: a dictionary longer than a window, a comment, a nested dictionary, and a
  font written in place are not spellings of a number. Each of those is read by all six
  readers. A regular expression that crossed nested `<<` would also have kept the quadratic
  cost.
- **Reporting alone is not enough** because a note passes the `agent-document` policy and
  is filed clean under the default one. The phrase is the finding; where a reader shows the
  text, the gate should read it.

So the three expressions are replaced by a tokenizer (`_FontNames` in `pdftext.py`), and
what it cannot settle is reported:

1. **Read.** A `/Font` key is found however its letters are escaped. Its value is read to
   its own closing `>>`, through nested dictionaries, arrays, strings, and comments, for up
   to 1 MiB. An entry written `N G R` in digits, with any whitespace or comments and any
   number of leading zeros, is a reference as before. A dictionary in place of a reference
   is read as the font. `/Font N G R` is followed to the object, read past the lookup
   window when the dictionary is longer (found again by its header, eight such objects a
   file). A reference to an object whose whole value is another reference is followed for
   16 steps (pdfminer.six followed 12; MuPDF stopped between 2 and 12).
2. **Read and report.** A reference only some readers follow is read as those readers read
   it: the object number's leading digits after any `+` (`6.9` is object 6 to pdfminer.six
   and PDFium, and none read `5.9` as 6), under generation 0 and the written one, with `R`
   joined to the generation or followed by more letters. Because another reader may take
   the same bytes for a different object, the name is also given the unresolved reading
   that a name past the reference cap gets, so text shown in it carries the note.
3. **Report.** A value no tested reader followed (`-6 0 R`, `6e0 0 R`, `6 0 r`, `null`,
   an array, a string) gives the name the unresolved reading only.
4. **Report the file.** When the names themselves are in doubt, every string the file shows
   sets the note: a dictionary that does not close before its object ends or within its
   limits; a vertical tab, 0x80, or 0xFF between a font dictionary's tokens (whitespace to
   pypdf and pdfminer.six, or to PDFium, and part of a token to the others; a sweep of all
   256 byte values as the separator found no other disputed byte); or a `/Font` reference
   that is not plain. The lexer takes those three bytes for whitespace, so the lenient
   reading is the one decoded.

Nothing is made incomplete. A font dictionary this reader cannot settle is a file some
reader may still open, and an incomplete result would exit 2 under every policy.

Under the policies, with the file dropped in an inbox (`yara-gate scan <file> --home …
--rules … --policy …`, exit code and where the file was filed):

| Fixture | main | This change |
| --- | --- | --- |
| `fontdict-fraction.pdf` (`6.0 0 R`), agent-ingest | **0, clean** | 1, blocked |
| `fontdict-inline.pdf`, agent-ingest | **0, clean** | 1, blocked |
| `fontdict-null.pdf` (phrase behind `null`, note only), agent-ingest | 0, clean | 1, blocked |
| the same three, default and agent-document | 0, clean | 0, clean, findings recorded |
| `fontdict-repeated.pdf` (control), agent-ingest | 1, blocked | 1, blocked |
| `fontdict-padded-plain.pdf` (benign), all three policies | 0, clean | 0, clean |

SHA-256: `fontdict-fraction.pdf` `7954aefd…e156`, `fontdict-escaped-key.pdf`
`68947577…d458`, `fontdict-alias.pdf` `b0978e81…1009`, `fontdict-inline.pdf`
`270019ee…4a26`, `fontdict-null.pdf` `c9422c5e…bea8`, `fontdict-padded-plain.pdf`
`8a8e8ae9…d249`. All are rebuilt by `font_dictionary_cases()` in `check_added_rules.py`.

## Every row

[`probe_pdf_font_readers.py`](../research/probe_pdf_font_readers.py) holds 65 rows.
`--verify` checks the gate's outcome for each; `--readers` reruns the readers and compares
them with [`pdf-font-readers.json`](../research/pdf-font-readers.json), which this run
wrote. In summary:

- **Found, no note (23 rows):** plain references in every arrangement above, an inline
  font, escaped keys, comments, long dictionaries, zero-padded numbers, a NUL separator,
  and reference chains.
- **Found and reported (28 rows):** `6.0`, `6.`, `6.9`, `+6`, `++6`, `6-`, `6+`, `6-1`,
  `6.0.0` as the number; `0.0`, `+0`, `-0`, `.0`, `0.9`, `-1`, `x` as the generation;
  `0R`, `0.0R`, `+0R`, `R0`; the three disputed whitespace bytes, between the numbers or
  after the name; `/Font 11.0 0 R` and `/Font 11 0R`. Each was followed by at least one
  reader.
- **Reported only (12 rows):** `-6`, `6e0`, `0x6`, `6 R`, `6 0 0 R`, `6 0 r`, `60R`,
  backspace or 0xA0 as the separator, `null`, `[6 0 R]`, `(6 0 R)`. No reader showed the
  phrase.
- **Clean (2 rows):** `/Font [<< /F1 6 0 R >>]`, which no reader follows; and `6 1 R`,
  below.

## Not closed here

- **A plain reference whose generation no header has (`6 1 R` for `6 0 obj`).**
  pdfminer.six, PDFium, and MuPDF showed the phrase; the gate is clean on main and after
  this change. [#206](https://github.com/cgfixit/yara-gate/pull/206) reads a font through
  every definition of its object number, which closes it: on the trial merge below the row
  is found. It is left to that pull request.
- **A disputed whitespace byte in the content stream.** `/F1<80>12 Tf` selects `/F1` in
  PDFium and `/F1<VT>12 Tf` in pdfminer.six; the gate's content lexer reads a longer name
  that no dictionary lists. With these fixtures the two-byte codes still raise the note;
  one-byte codes would not. It is a second lexer (`_tokens`) with its own benign class and
  is now a backlog candidate.
- **A font resource dictionary longer than 4 KB inside an object stream** is reported, not
  read: the lookup returns a window of a member and there is no header to find it by.
- **Per-page reading** ([#205](https://github.com/cgfixit/yara-gate/pull/205)) narrows
  what this union holds; see the trial merge.

## Benign controls

**Near misses.** `font_dictionary_cases()` scans the same shapes around an ordinary
sentence: the repeated name, the escaped key, the reference to a reference, the inline
font, and the padded dictionary are clean before and after. `6.0 0 R` around the ordinary
sentence gains the note; that is the cost of a spelling readers disagree on, and no
generator examined writes one.

**Real files (runtime, code-level sweep).** 231 PDFs, 72.7 MB, made or found in this
container: 28 LibreOffice 24.2.7.2 exports (Writer/Web, Writer, PDF/A-2 tagged, Calc), 35
Chromium 153.0.8010.12 `page.pdf()` exports (Skia/PDF m153), 30 from reportlab 5.1.0, fpdf2 2.9.0,
matplotlib 3.11.2 (Type 3 and Type 42), and PyMuPDF, 14 cairo files (`pdftocairo`), 111
rewrites of those (merges of 2 to 9 sources by pypdf, `pdfunite`, MuPDF, and qpdf 12.4.2;
object streams, QDF, linearized, uncompressed, incremental saves), and 13 found on the
machine. Each was scanned by main and by this change with the same rules, and `pdf_text`
was run directly on both. Text in Latin, Greek, Cyrillic, CJK, Arabic, and Hebrew.

- Changed files: **0 of 231**. Verdict, incomplete reason, every finding's rule, severity,
  and view, the counts of blocks, paragraphs, and hidden pieces, the `unmapped` flag, and
  a SHA-256 over all decoded text are identical. 198 files have text blocks, 94,434 in all.
- What the new reader met: 2,134 names, 2,855 references, 159 dictionaries behind
  `/Font N G R` in 115 files. No inline font, no value that is not a plain reference, no
  unclosed dictionary, no disputed byte, no dictionary past the lookup window.
- `pdf_text` over the whole set took 9.6 s on main and 8.9 s here.

The sweep is what was on this machine, not a sample of the files a gate meets. In
particular it holds no scanner output and no Acrobat or Word export.

**Shipped corpus.** `measure_precision.py --fail-over` passes on the 328 generated files.
`record_pages_demo.py --baseline web-demo/recordings.json` reports the 58 scenarios under
three policies unchanged.

## Time

`pdf_text` alone on 4 MiB inputs, one run each (runtime):

| Input | main | This change |
| --- | --- | --- |
| `/Font<<` repeated | 39.7 s | 1.3 s |
| `/Font<<(` repeated | 34.5 s | 0.3 s |
| `/Font<<<4` repeated | 31.9 s | 1.4 s |
| objects each named by its own `/Font N 0 R` | 13.5 s | 1.3 s |
| `/Font<</F1 1 0 R>>` repeated (closed) | 0.5 s | 1.7 s |
| one chain of references to references | 0.2 s | 2.8 s |
| `/Font<<` then `/A 1 0 R` repeated | under 0.1 s | 0.8 s |
| unclosed objects, each a `/Font` target | — | 2.1 s |
| 64 definitions of one long dictionary | — | 0.4 s |

The reading is linear by construction: a `/Font` key inside a dictionary being read is
handled by that reading, and the search for keys skips what was read, so no byte is lexed
twice within a source; strings are scanned once and bounded at 64 KiB; nesting stops at 64;
each level of a reference chain is one pass over the file, 17 at most; rereads of long
dictionaries share one 1 MiB allowance. Where this change is slower it is doing the work
the expressions skipped. On 64 MiB of random bytes or of ordinary content operators the key
search takes 0.05 s (0.08 s for the two expressions it replaces).

`check_worst_case_timing.py` gains `pdf-font-keys.pdf` and `pdf-font-objects.pdf` and passes
with 31 inputs; the two take 3.6 s and 4.1 s through `scan_bytes`, and the slowest input is
5.5 s.

## Open pull requests

Listed on November 10: #205 (page fonts), #206 (font definitions), #207 (hidden HTML).
Each was merged into this branch in a scratch worktree.

- **#205** (`f83c738`): one conflict in `pdftext._fonts` and one in `samples.py`. Keep
  this branch's collection (`names.read`, `names.follow`, `references, truncated = …`),
  drop the `cache` line #205 removed, and keep both sample builders. One line then needs a
  hand: `_fonts` receives a reader in place of the maps, so the inline-font loop takes the
  maps from it (`reader` exposes its `_Cmaps`). With that, Ruff, `mypy --strict src
  scripts`, `tests/test_pdftext.py` and `tests/test_pdf_font_dictionaries.py` (137 tests),
  `probe_pdf_font_readers.py --verify`, `probe_detection_gaps.py --verify`, and
  `check_added_rules.py` (240 cases) pass on the merge. #205's page map already declines a
  page whose dictionary repeats a key or does not parse, and leaves a name whose value is
  not a reference to the union, so every row above falls back to this reading.
- **#206** (`3707639`): conflicts in the limits block and `_fonts` of `pdftext.py`, and in
  the two check scripts where both append cases (keep both). In `_fonts`, keep this
  branch's collection and #206's `_Definitions` for the tail. Two things need a hand:
  `names.follow` should look objects up through `_Definitions` by number, so a font
  resource dictionary defined twice is still read through each definition (an eight-line
  adapter with `prime` and `__call__`); and the inline-font loop calls #206's
  `cmaps.fonts(...)` in place of `_font([body], …)`. With that, Ruff, mypy, 109 tests,
  `probe_detection_gaps.py --verify`, and `check_added_rules.py` (252 cases) pass, and
  `probe_pdf_font_readers.py --verify` differs in the one expected row: `6 1 R` is found.
  Change that row to `found` when both have merged.
- **#207**: one conflict where both append to `check_worst_case_timing.py`; keep both.

#205 and #206 were not merged with each other here.

## Checks run

- `uv run ruff check .` and `uv run ruff format --check .`: pass.
- `uv run mypy --strict src scripts`: pass, 24 source files.
- `uv run pytest tests/test_pdf_font_dictionaries.py tests/test_pdftext.py`: 91 passed.
  The broader suite is left to hosted CI.
- `docs/verification/check_added_rules.py`: 237 cases plus 4, pass. Each of the 13 `hit`
  rows and 3 `unmapped` rows of `font_dictionary_cases()` was scanned on main first: clean.
- `docs/verification/check_worst_case_timing.py`: 31 inputs, pass.
- `docs/research/probe_rule_coverage.py --verify`, `probe_detection_gaps.py --verify`,
  `probe_pdf_font_readers.py --verify`: pass.
- `docs/verification/measure_precision.py --fail-over`, `check_text_controls.py`,
  `check_doc_links.py`: pass.

## Limits

- Six readers at one version each. Acrobat, Preview, PDFBox, and browser builds of PDFium
  were not run; a row marked "reported only" is one none of these six followed.
- A font resource dictionary is still any `/Font` key's value anywhere in the file,
  including inside a string or an unused object. That over-reads on purpose.
- The note says text may be unread. It does not say which string, and a file that sets
  the file-wide flag reports from its first shown string on.
- Hidden text, annotation text, and the per-string cap of four font readings are
  unchanged.
