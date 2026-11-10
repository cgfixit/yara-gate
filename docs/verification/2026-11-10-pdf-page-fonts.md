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

`src/yara_gate/pdfpages.py` maps each page content stream to the fonts its page's
`/Resources` name. `pdftext.pdf_text` builds the map only when some name means two fonts;
where no name does, there is nothing to tell apart and the page tree is not read.

- **Layout pass:** one pass finds every `N G obj ... endobj` in file order. It keeps literal
  strings whole, skips comments, and steps over each stream by its `/Length`, using the
  annotation reader's rule (`pdfannotations.stream_span`, factored out unchanged). It marks
  objects that hold a `/Contents` or `/CharProcs` name, compared after `#xx` escapes are
  decoded.
- **Header check:** every run of bytes that a lexer could read as `N G obj` must end where
  the pass found an object. The test is wider than the pass's own: any integer spelling,
  comments between the tokens, no space needed before `obj`.
- **Parsing:** only marked objects and the objects they reference are parsed, with the
  ordinary PDF lexer, from the object's start to its own `endobj` or `stream`. A dictionary
  that repeats a key does not parse.
- **Reading `/Resources`:** the entry may be direct or a reference, and so may its `/Font`
  entry. When the page has no `/Resources`, the walk follows `/Parent` up to 32 levels. Each
  parent's result is memoized, and a `/Parent` loop stops. A reference is resolved by object
  number alone.
- **A stream several pages list:** gets the union of their fonts. Past 64 fonts for one name,
  the stream falls back.
- **`pdftext.pdf_text`:** a page content stream selects fonts through `_PageFonts`. A name
  the page lists is resolved on first `Tf`; every other name, and every form XObject or other
  stream, uses the file-wide union exactly as before.

The map narrows what is read, so it is built only from structure every reader agrees on.
Each case below keeps the file-wide union, the behavior before this change:

| Situation | Falls back for |
| --- | --- |
| The objects are not a plain run of `N G obj ... endobj`: an `obj` inside an open object, a stray or missing `endobj`, a stream whose `/Length` does not land, an unclosed string | the whole file |
| Bytes that read as an object header inside a string, a comment, or a stream | the whole file |
| A `/Contents` or `/CharProcs` key outside every object (a trailer) | the whole file |
| An object that holds `/Contents` or `/CharProcs` does not parse, or repeats a dictionary key | the whole file |
| A `/Contents` reference or array nested below a page's top level | the whole file |
| A `/CharProcs` that does not resolve to one dictionary | the whole file |
| An object stream could not be read (`PdfObjects.opaque`, new) | the whole file |
| More than 20,000 objects with `/Contents` or `/CharProcs`, more than 2 MiB of them, or more than 100,000 objects | the whole file |
| The objects are not a `PdfObjects` | the whole file |
| A `/Parent`, `/Resources` or `/Font` link that is missing, unreadable, or defined more than once with different values, under any generation | that page's streams |
| The stream is also a Type 3 glyph procedure, which runs with its font's resources | that stream |
| A name the page's `/Font` dictionary does not list | that name |

## Correction: pages the first version could miss

The first version of this change (`2d10eb0`, through `6e38a64`) found objects with a header
regex, cut each object at the next header match, and looked for the literal bytes
`/Contents`. That narrowed a stream's fonts in cases where a reader still uses another font.
Each fixture below has a shown page whose `/F1` decodes the phrase, and a decoy page, which
no reader shows, that draws the same stream with another font:

| Fixture | main `2b6eda8` | first version `6e38a64` | now |
| --- | --- | --- | --- |
| The shown page's `/Font` lists `/F1` twice, phrase font first | found | **clean** | found |
| The shown page has `/Resources` twice, phrase font first | found | **clean** | found |
| The shown page's key is written `/C#6Fntents` | found | **clean** | found |
| The stream is also a glyph procedure of a Type 3 font whose resources name the phrase font | found | **clean** | found |
| `/Resources 10 0 R`: object 10 generation 0 names the decoy, generation 1 the phrase font | found | **clean** | found |

"Found" is advisory with `agent_override_imperative`. The same review led to the layout pass
and the header check, which also cover a header written inside a string or a comment and the
header spellings `99 0obj`, `99 +0 obj`, and `99 0 %c` then `obj`. For those, the fixtures
show only that the first version kept narrowing where this one falls back.

Which reader keeps which copy of a repeated key, and which readers ignore a generation
number or run text operators inside a Type 3 glyph, was not checked against reader sources.
The map falls back in each case, so it does not depend on the answer.

## Commands and results (this container)

On the corrected code, with main `2b6eda8` merged in:

- Full `uv run pytest -q tests`: 662 passed, 5 skipped.
- `tests/test_pdftext.py`, 55 tests. The ones this change adds:
  - Per-page reading: each page reads its own font (5 blocks, not unmapped), and one stream
    on 5 pages is still capped and reported; inherited and indirect resources; pages inside
    an object stream; a page beside a decoy page.
  - Fallbacks for the whole file: an unparsable `/Contents` object, an unreadable object
    stream, ten layouts that are not a plain run of objects (a header in a string, in a
    comment, and in three lexer-only spellings; an object opened inside another; an unclosed
    and a twice-closed object; a stream length that does not land; an unclosed string),
    `/Contents` in the trailer, and the object and byte limits.
  - Fallbacks for one stream or name: resources defined twice, one object number under two
    generations, a repeated key (four orders), an escaped `/Contents` key, a glyph
    procedure, and a name the page does not list.
  - The page tree is not read when no name means two fonts.

  Of these, 18 test cases fail on the first version (`6e38a64`) and pass now.
- `docs/verification/check_added_rules.py`: passed, 218 cases plus 4 vendor-override cases.
  `font_reading_cases()` adds three shared-stream cases and expects the phrase rule on the
  per-page fixtures.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 226 `ok`. The nine `fonts` cases
  include one stream on five pages, which is still reported as unmapped, and three
  shown-page-beside-a-decoy cases (plain, escaped key, `/F1` listed twice).
- `docs/research/probe_rule_coverage.py --verify`: exit 0.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete.
  `heuristic_pdf_text_unmapped` hits no file; `pdf/merged-5-fonts.pdf` is clean. The
  remaining hits are the four tagged Windows files.
- `docs/verification/check_worst_case_timing.py`: PASS, 31 inputs of exactly 4 MiB. Two are
  for the page map, and both build it: `pdf-page-fonts.pdf` (pages that all draw one stream,
  each naming ten fonts no other page names, just under the 2 MiB the map reads), 6.08 s,
  and `pdf-page-parents.pdf` (pages under a 32-level `/Parent` chain, each holding a
  150-byte string), 2.47 s. `pdf-page-fonts.pdf` was the slowest input.
- `docs/verification/sweep_rule_changes.py` was not run. It scans with two rule trees and one
  scanner, and this change is to the scanner, not the rules. The code-level equivalent is
  the main-versus-branch run over the 28 generated PDFs above, repeated on the corrected
  code with the same result. This machine has three PDFs outside the scratch sample.
- `docs/research/detection-backlog.md` records the form XObject and ExtGState boundaries,
  and a font object defined more than once, as candidates. It records an incomplete reason,
  and a higher reading cap, as declined.
- `check_rule_pairs.py` (115 rules), `lint_rules.py` (85 rules), `check_doc_links.py`,
  `check_text_controls.py`, `ruff check .`, `ruff format --check .`, and
  `mypy --strict src scripts` (25 files): clean.

Cost on 4 MiB adversarial inputs, main `2b6eda8` → this change, one run each. In the first
four, `/F1` means two fonts, so the map is attempted:

| Input | main | this change | Map |
| --- | --- | --- | --- |
| `pdf-page-fonts.pdf` (8,198 pages) | 4.81 s | 5.52 s | built |
| `pdf-page-parents.pdf` (9,641 pages) | 1.97 s | 2.72 s | built |
| 58,403 annotation objects with a text `/Contents` | 4.96 s | 5.90 s | given up at 20,000 |
| 215,251 empty objects | 1.07 s | 1.78 s | given up at 100,000 |
| `pdf-page-objects.pdf` (no fonts) | 5.30 s | 5.17 s | not attempted |

The layout pass alone, on 4 MiB built to slow it: one run of digits 0.10 s; comment lines of
digits 0.39 s; `(()) ` strings in one array 0.65 s; names with `#` escapes 0.73 s. A string
over 1 MiB ends the pass at once.

On the real files, `merge-mixed-20.pdf` took 2.8 s instead of 1.8 s, because it is now read
to the end instead of stopping at the block limit.

## Residual risks and boundaries

- **Form XObjects** still use the file-wide union, so a form drawn on several pages keeps the
  four-reading cap and its note. Reading a form's own `/Resources` is a separate change.
- **Fonts selected another way.** A font selected through an ExtGState `/Font` entry (`gs`)
  is not read, as before.
- **A font object defined more than once** is read through its first definition, on main and
  here. Text only a later definition decodes is not read. It is listed in the backlog.
- **Readers can differ.** The map falls back wherever this review found that two readers
  could resolve a page's fonts differently. That list comes from reading this code against
  the PDF syntax, not from running readers. A page content stream that some reader also runs
  as a form XObject without a `/Subtype /Form` entry would still be narrowed. No reader's
  source was read for that.
- **Files that fall back.** A file with header-like text inside a string or a comment, a
  repeated dictionary key in a page object, or more than 2 MiB of page objects reads as
  before this change, so a merge like that keeps the cap and its note.
- **Cost.** Where a name means two fonts, the map adds up to about 0.9 s on 4 MiB.
- **Synthetic sample.** The fixtures are synthetic and locally generated. They are not a
  production false-positive rate.
