# PDF fonts read per page — November 10, 2026

Base: main `163ec4a` (Merge #203) for the first measurements, then main `2b6eda8` (Merge
#204) merged in for the corrected code and every result under "Commands and results". Linux
x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85 bundled local rules, zero skips, no
vendor download. Every scan used a disposable copy of `rules/local` and `rules/rules.lock`.

## Defect

The PDF text reader mapped a font resource name to every font that name meant anywhere in the
file, because it did not know which page drew which content stream. A merged PDF keeps each
source's `/F1`, so on a merge of N sources every string was decoded N ways.
[2026-11-07-pdf-font-readings.md](2026-11-07-pdf-font-readings.md) capped that at four
readings and reported the rest as `heuristic_pdf_text_unmapped`. That made the miss visible,
but it held benign merges under `agent-ingest`. Under `agent-document` it passed them unread.
Each reading also emits its own text blocks, so merges of 8 or more sources reached the
20,000-block limit and were `incomplete`.

On main `163ec4a`, with `samples.merged_pdf` (each page's `/F1` is its own font, and only
page *n*'s maps the glyph ids to the phrase):

| Fixture | main | this change |
| --- | --- | --- |
| `fonts-5-last.pdf`, `fonts-8-last.pdf` | advisory, `heuristic_pdf_text_unmapped` only | advisory, `agent_override_imperative` |
| `fonts-3-carried.pdf` (phrase in a carried reading behind 3 decoys) | `heuristic_pdf_text_unmapped` only | `agent_override_imperative` |
| `fonts-5-plain.pdf` (benign) | advisory, `heuristic_pdf_text_unmapped` | clean |
| `fonts-4-last.pdf`, `fonts-2-carried.pdf`, `fonts-4-plain.pdf` | unchanged | unchanged |
| `fonts-5-shared-last.pdf` (one stream drawn by all 5 pages) | `heuristic_pdf_text_unmapped` | same: the stream can mean every page's font |

Real files: 12 Chromium 153 exports, 8 LibreOffice 24.2 exports, and 8 merges of them made
with pypdf 5.1.0. The table gives the most readings any name had at a text operator, and the
verdict under each policy (default / agent-ingest / agent-document).

| File | main | this change |
| --- | --- | --- |
| 20 single-generator exports | 1 reading; verdicts as before | identical |
| `merge-chrome-2`, `merge-chrome-4` | 2, 4; clean | 1; clean |
| `merge-chrome-5`, `merge-lo-5`, `merge-mixed-6` | 5–6; advisory / block / advisory (note) | 1; clean / clean / clean |
| `merge-lo-8`, `merge-chrome-12`, `merge-mixed-20` | 8–20; incomplete (`pdf text blocks exceed 20000`) | 1; clean / clean / clean |

## Change

`src/yara_gate/pdfpages.py` maps each page content stream to the fonts its page's own
`/Resources` name. `pdftext.pdf_text` builds the map only when some name means two fonts;
where no name does, there is nothing to tell apart and the page tree is not read.

The map narrows what is read, so it is built only from structure every reader agrees on.
Anything else keeps the file-wide union, which is the behavior before this change.

- **Layout pass:** one pass finds every `N G obj ... endobj` in file order. It keeps literal
  strings whole and steps over each stream by its `/Length`, using the annotation reader's
  rule (`pdfannotations.stream_span`, factored out unchanged). It marks objects that hold a
  `/Contents` name, compared after `#xx` escapes are decoded.
- **Header check:** any `obj` in the file's bytes that could end an object header (the bytes
  before it end in a digit, or sit on a comment line) must be one the pass opened an object
  at. That covers a header written inside a string or a stream, and spellings only some
  lexers read (`99 0obj`, `99 +0 obj`).
- **Stream numbers:** every stream the text reader decoded must be one the pass stepped
  over, with the same object number.
- **Cross-reference check:** every occurrence of the bytes `startxref` is followed
  (`pdfxref.xref_tables(..., anywhere=True)`). Each type-1 entry must point at the first
  digit of a header with its object number. Each type-2 entry must name a position in an
  object stream where that stream's own table lists the same number (`PdfObjects.member_tables`,
  new). A file with no `startxref` at all is rebuilt from its headers by every reader.
- **Pages:** a page is any object with `/Contents` at its top level that parses, with the
  ordinary PDF lexer, as one dictionary with no key repeated. Its `/Contents` is followed
  through nested arrays and references to arrays.
- **Reference count:** a stream gets its pages' fonts only when every reference to its
  object number in the file's bytes is one of those `/Contents` references. A reference
  from anywhere else (an annotation's appearance, a Type 3 font's glyph procedures, a page
  that did not parse) can run the stream with other resources.
- **Resources:** only a page's own `/Resources` count. The entry may be direct or a
  reference, and so may its `/Font` entry. A reference is resolved by object number alone,
  and an object number defined more than once with different values does not resolve.
- **A stream several pages list:** gets the union of their fonts. Past 64 fonts for one name,
  the stream falls back.
- **`pdftext.pdf_text`:** a page content stream selects fonts through `_PageFonts`. A name
  the page lists is resolved when a `Tf` in that stream selects it; every other name, and
  every form XObject or other stream, uses the file-wide union exactly as before. A font
  selected in an earlier stream is carried into the next one by its name and read through
  the union.

| Situation | Falls back for |
| --- | --- |
| The objects are not a plain run of `N G obj ... endobj`: an `obj` inside an open object, a stray or missing `endobj`, a stream whose `/Length` does not land, an unclosed string, a comment inside an object | the whole file |
| Bytes that read as an object header inside a string, a comment, or a stream | the whole file |
| A decoded stream the pass did not step over, or numbered differently by the stream reader (a header with more than 10 digits) | the whole file |
| A stream with `/N` and `/First` but no `/Type /ObjStm`; an object stream that could not be read (`PdfObjects.opaque`, new) | the whole file |
| A cross-reference entry that does not agree with the headers, or a table that cannot be read | the whole file |
| A `/Contents` array that cannot be followed (nested deeper than 32, leading back to itself, or holding an unreadable object), or that something else references | the whole file |
| More than 20,000 objects with `/Contents`, more than 2 MiB of objects parsed, more than 100,000 objects, or more than 2,000 streams | the whole file |
| The objects are not a `PdfObjects` | the whole file |
| A reference to the stream from anywhere but a parsed page's `/Contents` | that stream |
| A page that draws it has no `/Resources` of its own, or its `/Resources` or `/Font` is missing, unreadable, or defined more than once with different values, under any generation | that stream |
| A name the page's `/Font` dictionary does not list; a font carried in from an earlier stream | that name |

## Correction: text the first versions could miss

The first version of this change (`2d10eb0` through `6e38a64`) found objects with a header
regex, cut each object at the next header match, looked for the literal bytes `/Contents`,
followed `/Parent`, and never read the cross-reference table. A first correction
(`251b169`) replaced the object search. Both narrowed a stream's fonts in cases where a
reader still uses another font. Each fixture below has a shown page whose font decodes the
phrase and a decoy page, which no reader shows, that draws the same text with another font.
"Found" is advisory with `agent_override_imperative`.

| Fixture | main `2b6eda8` | Earlier commit | Now |
| --- | --- | --- | --- |
| The shown page's `/Font` lists `/F1` twice, phrase font first | found | **clean** on `6e38a64` | found |
| The shown page has `/Resources` twice, phrase font first | found | **clean** on `6e38a64` | found |
| The shown page's key is written `/C#6Fntents` | found | **clean** on `6e38a64` | found |
| The stream is also a glyph procedure of a Type 3 font whose resources name the phrase font | found | **clean** on `6e38a64` | found |
| `/Resources 10 0 R`: object 10 generation 0 names the decoy, generation 1 the phrase font | found | **clean** on `6e38a64` | found |
| The content stream's header is written `00000000005 0 obj` | found | **clean** on `251b169` | found |
| `/Resources 10 0 R`, and a stream with `/N` and `/First` but no `/Type` holds another object 10 | found | **clean** on `251b169` | found |
| `/Contents [[5 0 R]]` | found | **clean** on `251b169` | found |
| `/Contents [10 0 R]`, and object 10 is `[5 0 R]` | found | **clean** on `251b169` | found |
| `/Contents 10 0 R`, object 10 is `[11 0 R]`, object 11 is `[5 0 R]` | found | **clean** on `251b169` | found |
| The page's first stream selects `/F1`, its second shows the text, and the decoy's stream lies between them in the file | found | **clean** on `251b169` | found |
| The decoy page draws the stream, and an annotation on the shown page names it as its appearance | found | **clean** on `251b169` | found |
| The same, with the annotation's reference split by a comment | found | **clean** on `251b169` | found |
| The shown page has no `/Resources`; its `/Parent` names the decoy font and the node that lists it in `/Kids` names the phrase font | found | **clean** on `251b169` | found |
| A cross-reference table gives object 10 (decoy resources) the offset of object 11 (phrase resources) | found | **clean** on `251b169` | found |
| A type-2 cross-reference entry puts object 10 at a place in an object stream whose own table calls that member 99 | found | **clean** on `251b169` | found |

Which reader does what in each row was not checked against reader sources or by running
readers. From memory of their code: pdf.js keeps the last copy of a repeated key and pypdf
(not strict) the first; pdf.js takes a compressed object by its position in the object
stream; pypdf (not strict) accepts a header whose number differs from the table's; pypdf and
pdfminer.six inherit page attributes down the `/Kids` they walk. The map falls back in every
row, so it does not depend on those being right.

Two gaps turned up on the way that main has and this change does not touch. They are listed
in [the detection backlog](../research/detection-backlog.md):

- A font object defined more than once is read through its first definition only.
- `pdfxref._startxref_candidates` reads the file from the top and tracks strings through
  stream bodies. On all 29 real PDFs here it finds no `startxref`, though each has one, so
  the annotation reader's cross-reference check does not run on them. One `(` byte in a
  stream body is enough.

## Commands and results (this container)

On the corrected code, with main `2b6eda8` merged in:

- Full `uv run pytest -q tests`: 680 passed, 5 skipped.
- `tests/test_pdftext.py`, 73 tests. The ones this change adds:
  - Per-page reading: each page reads its own font (5 blocks, not unmapped), and one stream
    on 5 pages is still capped and reported; a page's own resources behind references; pages
    inside an object stream; a page beside a decoy page; page content behind nested arrays
    (three forms).
  - Fallbacks for the whole file: ten layouts that are not a plain run of objects, a comment
    inside an object, a stream the two readers number differently, an object stream without
    its `/Type`, an unreadable object stream, a cross-reference table that renumbers an
    object, one that cannot be read, a compressed entry that names another member, a
    `/Contents` array that names itself or is referenced from elsewhere, and the object and
    byte limits.
  - Fallbacks for one stream or name: a reference from outside page content (four
    spellings), an unparsable page object, `/Contents` in the trailer, inherited resources,
    resources defined twice, one object number under two generations, a repeated key (four
    orders), an escaped `/Contents` key, a glyph procedure, a name the page does not list,
    and a font carried in from another stream.
  - The page tree is not read when no name means two fonts.

  Of the test cases, 18 fail on the first version (`6e38a64`) and pass on the first
  correction. A further 18 fail on the first correction (`251b169`) and pass now; 12 of
  those call the map function directly, whose signature changed, and the shapes behind them
  are in the table above, each observed with a scan.
- `docs/verification/check_added_rules.py`: passed, 218 cases plus 4 vendor-override cases.
  `font_reading_cases()` adds three shared-stream cases and expects the phrase rule on the
  per-page fixtures.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 227 `ok`. The ten `fonts` cases
  include one stream on five pages, which is still reported as unmapped, and four
  shown-page-beside-a-decoy cases (plain, escaped key, `/F1` listed twice, and the decoy's
  stream named as an annotation's appearance).
- `docs/research/probe_rule_coverage.py --verify`: exit 0.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete.
  `heuristic_pdf_text_unmapped` hits no file; `pdf/merged-5-fonts.pdf` is clean. The
  remaining hits are the four tagged Windows files.
- `docs/verification/check_worst_case_timing.py`: PASS, 31 inputs of exactly 4 MiB. Two are
  for the page map, and both build it: `pdf-page-fonts.pdf` (8,198 pages that all draw one
  stream, each naming ten fonts no other page names, just under the 2 MiB the map parses),
  6.23 s, and `pdf-page-references.pdf` (one page and an array of about 260,000 references
  to its content stream), 2.33 s. `pdf-page-fonts.pdf` was the slowest input.
- Real files, main `2b6eda8` against the corrected code, all three policies:
  - The 20 single-generator exports and the third-party file: identical verdicts.
  - The 8 pypdf merges: one reading per name. The six that were held or incomplete on main
    are clean, as in the table at the top.
  - Four of the merges rewritten by qpdf 11.9.1 (pikepdf 9.4.2) with object streams and a
    cross-reference stream, 205 to 833 type-2 entries each: every entry agrees with the
    headers, one reading per name, clean. On main three have the unmapped note and one is
    incomplete.
  - In all 33 files the layout pass finds a plain run of objects, every cross-reference
    entry agrees, and the map leaves no stream unsettled. The pass took at most 0.15 s, the
    cross-reference check 0.07 s, and the whole map 0.26 s.
- `docs/verification/sweep_rule_changes.py` was not run. It scans with two rule trees and one
  scanner, and this change is to the scanner, not the rules. The code-level equivalent is
  the main-versus-branch run over the real files above. This machine has three PDFs outside
  the scratch sample.
- `docs/research/detection-backlog.md` records as candidates: form XObject and ExtGState
  fonts, inherited page resources, a font object defined more than once, and the
  `startxref` scanner. It records an incomplete reason, and a higher reading cap, as
  declined.
- `check_rule_pairs.py` (115 rules), `lint_rules.py` (85 rules), `check_doc_links.py`,
  `check_text_controls.py`, `ruff check .`, `ruff format --check .`, and
  `mypy --strict src scripts` (25 files): clean.

Cost on 4 MiB adversarial inputs, main `2b6eda8` → this change, one run each. In the first
four, `/F1` means two fonts, so the map is attempted:

| Input | main | this change | Map |
| --- | --- | --- | --- |
| `pdf-page-fonts.pdf` | 4.36 s | 5.53 s | built |
| `pdf-page-references.pdf` | 1.90 s | 2.39 s | built |
| 58,403 annotation objects with a text `/Contents` | 5.26 s | 6.12 s | given up at 20,000 |
| 215,251 empty objects | 1.34 s | 1.61 s | given up at 100,000 |
| `pdf-page-objects.pdf` (no fonts) | 4.77 s | 5.07 s | not attempted |

The map alone, on 4 MiB built to slow each part: one run of digits 0.14 s; comment lines of
digits 0.54 s; `1 ` repeated 0.29 s; digit pairs with long gaps 0.19 s; a million `1 0R`
references 0.25 s; `(()) ` strings in one array 0.63 s; names with `#` escapes 0.81 s.

On the real files, `merge-mixed-20.pdf` took 2.9 s instead of 1.8 s, because it is now read
to the end instead of stopping at the block limit.

## Residual risks and boundaries

- **Form XObjects** still use the file-wide union, so a form drawn on several pages keeps the
  four-reading cap and its note. Reading a form's own `/Resources` is a separate change.
- **Pages that inherit their resources** keep the union too, so a merge of such files keeps
  the cap and its note.
- **Fonts selected another way.** A font selected through an ExtGState `/Font` entry (`gs`)
  is not read, as before.
- **A font object defined more than once** is read through its first definition, on main and
  here. Text only a later definition decodes is not read.
- **Readers can differ.** The map falls back wherever this review found that two readers
  could resolve a page's fonts differently. That list comes from reading this code against
  the PDF syntax and from memory of reader behavior, not from running readers or reading
  their sources. One assumption has no fallback: a reader runs a content stream as a form
  XObject only when a resource dictionary references it, and that reference keeps the union.
- **Files that fall back** read as before this change, so a merge like that keeps the cap
  and its note: a comment inside an object (qpdf's QDF mode writes them), header-like text
  inside a string, a repeated key in a page object, a cross-reference table that does not
  match the headers, or more than 2 MiB of page objects.
- **Cost.** Where a name means two fonts, the map adds up to about 1.2 s on 4 MiB.
- **Synthetic sample.** The fixtures are synthetic and locally generated. They are not a
  production false-positive rate.
