# PDF fonts read per page — November 10, 2026

Base: main `2b6eda8` (Merge #204). Linux x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85
bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local` and `rules/rules.lock`.

## Defect

The PDF text reader mapped a font resource name to every font that name meant anywhere in the
file, because it did not know which page drew which content stream. A merged PDF keeps each
source's `/F1`, so on a merge of N sources every string was decoded N ways.
[2026-11-07-pdf-font-readings.md](2026-11-07-pdf-font-readings.md) capped that at four
readings and reported the rest as `heuristic_pdf_text_unmapped`. That made the miss visible,
but it held benign merges under `agent-ingest`. Under `agent-document` it passed them unread.
Each reading also emits its own text blocks, so merges of 8 or more sources reached the
20,000-block limit and were `incomplete`.

## Change

`src/yara_gate/pdfpages.py` maps each page content stream to the fonts its page's own
`/Resources` name. `pdftext.pdf_text` builds the map only when some name means two fonts;
where no name does, there is nothing to tell apart and the page tree is not read.

The map narrows what is read. It is safe only when no reader shows text through a font the
map left out, and readers recover from malformed syntax in different ways. So the map is
built only for a file that is written plainly throughout, and anything else keeps the
file-wide union, which is the behavior before this change.

- **One strict pass over the file.** It reads every token outside stream bodies and literal
  strings. Between objects it takes comments, cross-reference sections, and trailers. Each
  object is `N G obj`, exactly one well-formed value, and `endobj`: a dictionary's keys are
  names, containers close in order, and nothing is left over. A stream is stepped over by
  its `/Length`, using the annotation reader's rule (`pdfannotations.stream_span`, factored
  out unchanged).
- **Plain tokens only.** Outside strings and streams every byte is printable ASCII, a tab,
  or a line end. A number is a decimal with an optional sign. A reference is two runs of
  digits and `R`. A comment may follow anything but a number, where it could split a
  reference. A hex string holds hex digits. Anything else turns the map off.
- **Header check.** Any `obj` in the file's bytes that could end an object header must be
  one the pass opened an object at. That covers a header written inside a string, a comment,
  or a stream.
- **Stream numbers.** Every stream the text reader decoded must be one the pass stepped
  over, with the same object number.
- **Cross-reference check.** Every occurrence of the bytes `startxref` is followed
  (`pdfxref.xref_tables(..., anywhere=True)`), except the `startxref 0` of a linearized
  file's first-page trailer. Each type-1 entry must point at the first digit of a header
  with its object number and generation. Each type-2 entry must name a position in an object
  stream where that stream's own table lists the same number.
- **Object streams.** The header must be exactly the pairs `/N` counts, the first object
  must be at `/First`, and each member's place must hold exactly one well-formed value. A
  reader may take the objects in the order they are written instead of at the header's
  offsets.
- **Pages.** A page is any object with `/Contents` at its top level whose dictionary repeats
  no key and escapes no name with `#`. Its `/Contents` is followed through nested arrays and
  references to arrays.
- **Reference count.** A stream gets its pages' fonts only when every reference to its
  object number, in the file and in every object-stream member, is one of those `/Contents`
  references. A reference from anywhere else (an annotation's appearance, a Type 3 font's
  glyph procedures, a page that did not parse, a page written in the trailer) can run the
  stream with other resources.
- **Resources.** Only a page's own `/Resources` count. A reference resolves when its object
  is defined once, or every definition has the same value, under the generation the
  reference gives, and the cross-reference table lists it in use under that generation with
  no section listing it free. With no table at all, an object-stream member does not
  resolve. A reader that reads null in any of these cases can take the page's parent's
  resources instead.
- **Names.** A name is given a stream's fonts only when every page that draws the stream
  lists it, as a reference to one font dictionary that resolves. Any other name falls back
  to the union. Past 64 fonts for one name, the stream falls back.
- **`pdftext.pdf_text`.** A page content stream selects fonts through `_PageFonts`. A font
  selected in an earlier stream is carried into the next one by its name and read through
  the union.

| Situation | Falls back for |
| --- | --- |
| Anything but comments, cross-reference sections, and trailers between objects; an object that is not one well-formed value; a token that is not written plainly | the whole file |
| A stream whose `/Length` does not land, or is kept in another object and not written as a plain reference | the whole file |
| Bytes that read as an object header inside a string, a comment, or a stream | the whole file |
| A decoded stream the pass did not step over, or numbered differently by the stream reader | the whole file |
| A stream with `/N` and `/First` but no `/Type /ObjStm`; an object stream that could not be read or is not written plainly | the whole file |
| A cross-reference entry that does not agree with the headers, or a table that cannot be read | the whole file |
| A `/Contents` array that cannot be followed, or that something else references | the whole file |
| More than 1,000,000 tokens, 100,000 objects, 20,000 objects with `/Contents`, 2 MiB of objects parsed, or 2,000 streams; an object number past 8,388,607 | the whole file |
| A reference to the stream from anywhere but a parsed page's `/Contents` | that stream |
| A page that draws it has no `/Resources` of its own, or its `/Resources` or `/Font` does not resolve | that stream |
| A name one of the stream's pages does not list, or lists as anything but a reference to one font dictionary; a font carried in from an earlier stream | that name |

## Checked against readers

The first three versions of this change were reasoned from the PDF syntax and from memory of
reader behavior, and each was wrong: each gave a stream its page's fonts in cases where a
real reader still shows the text through another font. The fourth was checked by running
readers. [`docs/research/probe_pdf_reader_agreement.py`](../research/probe_pdf_reader_agreement.py)
builds files with a shown page and a decoy page that both draw one stream, written so that
only the shown page's font decodes the phrase. It runs the text reader with the map and with
the map turned off, and runs six readers on the same bytes:

| Reader | Version |
| --- | --- |
| pypdf | 5.1.0 |
| pdfminer.six | 20260107 |
| PDFium, through pypdfium2 5.13.0 | 153.0.7999.0 |
| MuPDF, through PyMuPDF | 1.28.6 |
| poppler `pdftotext` | 24.02.0 |
| pdf.js (`pdfjs-dist`, Node 22.23.4) | 6.5.438 |

What the readers do, observed on the probe's hand-written fixtures. "Shows" means the reader
extracts the phrase:

| Shape of the shown page | Readers that show the phrase | The map |
| --- | --- | --- |
| `/Contents 5.0 0 R`, `5 0.0 R` | PDFium, pdf.js, pdfminer.six | off for the file |
| `/Contents 5- 0 R` | MuPDF, PDFium, pdf.js, pdfminer.six | off |
| `/Contents 5 0R` | pdf.js, pdfminer.six, poppler | off |
| a vertical tab between the tokens of the reference | pdfminer.six, pypdf | off |
| `/Contents 5 0 R#` (found by the fuzz pass) | pypdf | off |
| `/Contents 10 0 R`, object 10 is `5 0 R` | pdfminer.six | union for the stream |
| the page is a dictionary inside `/Kids`, not an object | MuPDF, PDFium, pdf.js, pypdf | union for the stream |
| the page is written inside the trailer | MuPDF, pdf.js, pypdf | union for the stream |
| the same, its reference split by a comment | MuPDF, pdf.js | off |
| header `3 0obj`, `3.0 0 obj`, or with a vertical tab | two to three readers each | off |
| `/F1` twice in `/Font`, phrase font first | poppler, pypdf | page not read; union |
| `/F1` twice, phrase font last | MuPDF, PDFium, pdf.js, pdfminer.six | page not read; union |
| `/Resources` twice, phrase first / last | pypdf / the other five | page not read; union |
| no own `/Resources`; `/Parent` names the decoy and the `/Kids` owner the phrase | pdfminer.six, poppler, pypdf | union for the stream |
| the same with the two swapped | MuPDF, PDFium, pdf.js | union for the stream |
| `/Resources 10 0 R`; `10 0 obj` names the decoy, `10 1 obj` the phrase | MuPDF, PDFium, pdfminer.six | union for the stream |
| own resources name the decoy, the parent the phrase; object 10 is free or not in the table | PDFium | union for the stream |
| the same; the reference and the object differ in generation | poppler | union for the stream |
| the same; own resources are `<< >>` | pdf.js | union for the name |
| the same; own `/Resources` is `null`, or names a missing object | two to three readers each | union for the stream |
| the same; a second key `/Resources#00 null` (fuzz) | poppler | page not read; union |
| a string where a key belongs, holding `/Contents 5 0 R` (fuzz) | PDFium | off |
| `/F1 10 0 R`, object 10 is `6 0 R` (fuzz) | MuPDF, pdfminer.six | union for the name |
| an object stream with an object before `/First`, or two objects in one member's place | pdfminer.six | off |
| a type-2 entry whose position holds another member's number | pdfminer.six | off |
| own resources are an object-stream member and the file has no cross-reference table (fuzz) | poppler, which does not read the member and takes the parent's resources | union for the stream |
| an untyped stream with `/N` and `/First`, named by a type-2 entry | MuPDF, pdf.js, pdfminer.six, poppler | off |

On the 141 fixtures no reader shows text the map narrowed away. Ten are gaps the union
already has, where a font reference is written `6.0 0 R` or the like, or `/Font` is spelled
`/F#6Fnt`: readers show the phrase and neither reading has it. They are in
[the detection backlog](../research/detection-backlog.md).

The fuzz pass picks one of 16 structures for the shown page's chain, applies one to three
token mutations (separators, number and name spellings, repeated keys, strings with escapes,
dropped and junk tokens), and varies the cross-reference table. It keeps the files where the
map reads less than the union and runs the six readers on those only.

| Run | Mutants | The map reads less | Of those, a reader shows the phrase |
| --- | --- | --- | --- |
| `f83c738` plus rules for reference spellings and object-stream order | 3,000 | 9 | 1 (`5 0 R#`) |
| After fixing that | 40,000 | 83 | 0 |
| With mutations of the table and of the parent's resources added | 40,000 | 1,193, of which 1,073 were checked | 46 (two shapes) |
| After fixing those | 120,000 | 3,454, of which 3,334 were checked | 5 (two shapes) |
| After the strict pass replaced the string-aware scan | 120,000 | 3,451 | 0 |
| The committed probe, with comments allowed where they cannot split a reference | 120,000 | 3,807 | 0 |

The two runs that checked fewer files than they kept lost one batch each when a reader
process ran out of memory. The last run was started before the token limit was lowered from
2,000,000 to 1,000,000; no mutant has more than a few hundred tokens.

Every shape a run found is a test in `tests/test_pdftext.py` and a row above.

### What earlier commits on this branch missed

| Commit | What it did | Missed |
| --- | --- | --- |
| `2d10eb0` to `6e38a64` | Found objects with a header regex, followed `/Parent`, never read the table | Repeated keys, an escaped `/Contents`, a glyph procedure, two generations |
| `251b169` | One string-aware pass; own or `/Parent` resources | Nested `/Contents` arrays, an 11-digit header, an untyped object stream, a table that renumbers an object, an annotation's appearance, a carried font |
| `f83c738` | Counted references by regex; checked the table | Every row above marked "off" for a reference spelling, the object-stream order rows, the free, unlisted, and generation rows, the empty own resources row, and the fuzz rows |

`f83c738` also looked each indirect stream length up with its own scan of the file. A 2.1 MB
QDF save of a 20-source merge took 29 s where main takes 1.4 s. The pass now looks all of
them up in one scan.

## Results on real files

Before and after, main `2b6eda8` against this change, all three policies
(default / agent-ingest / agent-document):

| Files | main | this change |
| --- | --- | --- |
| 20 single-generator exports (12 Chromium 153, 8 LibreOffice 24.2) | 1 reading per name | identical verdicts |
| pypdf 5.1.0 merges of 2 and 4 Chromium exports | 2, 4 readings; clean | 1; clean |
| merges of 5 and 6 sources (3 files) | 5–6 readings; advisory / block / advisory (note) | 1; clean / clean / clean |
| merges of 8, 12, and 20 sources (3 files) | `incomplete` (`pdf text blocks exceed 20000`) | 1; clean / clean / clean |
| 4 of the merges rewritten by qpdf 11.9.1 with object streams | 3 with the note, 1 incomplete | 1 reading; clean |
| 3 of the merges in qpdf's QDF mode | 1 with the note, 2 incomplete | 1 reading; clean |
| 6 linearized saves of the merges | incomplete | incomplete: `pdf xref malformed`, which main reports for every linearized file once the text reader finishes ([backlog](../research/detection-backlog.md)) |
| pypdf and qpdf merges of 6 cairo files and of 6 matplotlib files (4 files) | advisory / block / advisory (note) | clean / clean / clean |
| 48 single files from reportlab, fpdf2, matplotlib, MuPDF (plain and with object streams), cairo, and PDFium re-saves, and the other 12 merges of them | 43 clean; 12 with fpdf2's open-action note; 5 plain MuPDF files incomplete (`pdf xref malformed`) | identical |
| 4 of the single exports re-saved by qpdf, plain and linearized (8 files) | plain as the export; linearized incomplete (`pdf xref malformed`) | identical |
| 8 n-up sheets, each source page a form XObject (qpdf overlay, MuPDF `show_pdf_page`) | 4 sources: clean; 6 and 8 sources: advisory / block / advisory (note) | identical: a form still reads the union |

That is 121 files. The 17 that change verdict are the merges above. Two linearized merges,
incomplete on both, no longer carry the note; no other verdict or finding differs. The
incomplete MuPDF and linearized files are a defect main has in its own read of the
cross-reference table ([backlog](../research/detection-backlog.md)). On every one of the 121
the file passes the strict pass and the map's own cross-reference check, and the map is
built with no page stream left to the union. The files come from ten
writers: Chromium (Skia), LibreOffice, pypdf, qpdf (plain, object streams, QDF, linearized),
reportlab, fpdf2, matplotlib, MuPDF, cairo, and PDFium. reportlab and cairo write a comment
inside a dictionary, and MuPDF a blank line before `trailer`; both are accepted.

## Commands and results (this container)

On the final tree:

- Full `uv run pytest -q tests`: 727 passed, 5 skipped.
- `tests/test_pdftext.py`, `tests/test_pdfxref.py`, `tests/test_pdfannotations.py`: 187
  tests. The page-map tests cover each row of the tables above: per-page reading, each
  whole-file and per-stream fallback, each reader difference with the reader named in a
  comment, the comments and blank line real writers produce, a linearized file's two
  sections, and the limits.
- `docs/research/probe_pdf_reader_agreement.py fixtures`: exit 0. 141 files, six readers,
  MISS 0, gap 10.
- `docs/research/probe_pdf_reader_agreement.py fuzz --seed 51 --seeds 8 --count 15000`: exit
  0. 120,000 mutants, 3,807 where the map reads less, MISS 0.
- `docs/verification/check_added_rules.py`: passed, 218 cases plus 4 vendor-override cases.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 230 `ok`. The 13 `fonts` cases
  include four shown-page-beside-a-decoy cases and three spellings from the reader probe
  (`5.0 0 R`, a string where a key belongs, a second `/Resources#00` key).
- `docs/research/probe_rule_coverage.py --verify`: exit 0.
- `docs/verification/measure_precision.py --fail-over`: exit 0, zero incomplete.
  `heuristic_pdf_text_unmapped` hits no file.
- `docs/verification/check_worst_case_timing.py`: PASS, 31 inputs of exactly 4 MiB. Two are
  for the page map, and both build it: `pdf-page-fonts.pdf` 6.29 s, the slowest input, and
  `pdf-page-references.pdf` 2.43 s.
- `check_rule_pairs.py` (115 rules), `lint_rules.py` (85 rules), `check_doc_links.py` (599
  links), `check_text_controls.py`, `ruff check .`, `ruff format --check .`, and
  `mypy --strict src scripts` (25 files): clean.
- `docs/verification/sweep_rule_changes.py` was not run. It scans with two rule trees and one
  scanner, and this change is to the scanner, not the rules. The code-level equivalent is
  the main-against-branch run over the 121 real files above.
- `docs/research/detection-backlog.md` records what was found on main on the way (font
  reference spellings, a font behind a second reference, linearized files held as
  incomplete, one file scan per indirect stream length) and what the map declines.

## Cost

Full scans of 4 MiB inputs, main `2b6eda8` → this change, one run each. In every row `/F1`
means two fonts, so the map is attempted:

| Input | main | this change | Map |
| --- | --- | --- | --- |
| `pdf-page-fonts.pdf` (8,198 pages drawing one stream) | 4.86 s | 6.26 s | built |
| `pdf-page-references.pdf` (260,000 references to one stream) | 2.12 s | 2.56 s | built |
| 700,000 references in one array | 4.02 s | 4.38 s | built; the scan is incomplete on both (annotation token limit) |
| 2,000,000 numbers in one array | 4.23 s | 4.67 s | given up at 1,000,000 tokens |
| 1,000,000 short strings in one array | 3.07 s | 3.58 s | given up at 1,000,000 tokens |
| an object stream of 6,000 arrays of references | 2.83 s | 2.96 s | built |
| an object stream of 60,000 small members | 2.07 s | 2.26 s | built |

The map alone takes at most 0.8 s on these and on seven more inputs built to slow the token
pass (digit runs, long whitespace, sign and dot soup, names, 15,000 page members). On the 121
real files the pass takes at most 0.33 s and the whole map 0.56 s.

The real merges that are now read to the end take longer than on main, where they stopped
at the block limit: the 20-source merge 3.1 s instead of 1.3 s.

## Residual risks and boundaries

- **Six readers are not every reader.** The map falls back wherever one of the six, at the
  versions above, resolved a page's fonts differently from another, and wherever the fuzz
  pass found a difference. A reader not run here, or a spelling the fuzz pass does not
  generate, can still differ. The plain-syntax rule is meant to cover that: a reader has
  nothing to recover from in a well-formed file.
- **One assumption has no check.** A reader reaches a content stream only through a reference
  to its object number. Every such reference is counted, whatever names it.
- **Files that fall back** read as before this change, so a merge like that keeps the cap
  and its note: a file with malformed or unusual syntax anywhere, a table that does not match
  the headers, pages that inherit their resources, or more than 2 MiB of page objects. Only
  the ten writers above were tried; another writer's output may not pass the strict pass.
- **Form XObjects** still use the file-wide union. An n-up sheet of six or more sources,
  where each source page is a form, keeps the cap and its note (8 real files above).
- **Fonts selected another way.** A font selected through an ExtGState `/Font` entry (`gs`)
  is not read, as before.
- **The union has its own gaps**, found on the way and not changed here: a font reference in
  a spelling only some readers take, a font behind a second reference, and a font object
  defined more than once are not read on main either.
- **Synthetic sample.** The fixtures are synthetic and the real files locally generated.
  They are not a production false-positive rate.
