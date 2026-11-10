# PDF fonts read per page — November 10, 2026

Base: main `163ec4a` (Merge #203). Linux x86_64 container, Python 3.12.3, YARA-X 1.23.0,
85 bundled local rules, zero skips, no vendor download. Every scan used a disposable copy
of `rules/local` and `rules/rules.lock`.

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

`src/yara_gate/pdfpages.py` builds one object index per file, in a single pass. It holds
every raw `N G obj` definition and every object-stream member, so no lookup rescans the file.
From that index it maps each page content stream to the fonts its page's `/Resources` name:

- **Reading `/Resources`:** the entry may be direct or a reference, and so may its `/Font`
  entry. When the page has no `/Resources`, the walk follows `/Parent` up to 32 levels. Each
  parent's result is memoized, and a `/Parent` loop stops.
- **A stream several pages list:** gets the union of their fonts. Past 64 fonts for one name,
  the stream falls back.
- **`pdftext.pdf_text`:** a page content stream selects fonts through `_PageFonts`. A name
  the page lists is resolved on first `Tf`; every other name, and every form XObject or other
  stream, uses the file-wide union exactly as before.

The map is conservative. Each case below keeps the file-wide union, the behavior before this
change:

| Situation | Falls back for |
| --- | --- |
| An object that holds `/Contents` does not parse | the whole file |
| An object stream could not be read (`PdfObjects.opaque`, new) | the whole file |
| A `/Contents` reference nested below a page's top level | the whole file |
| More than 20,000 objects with `/Contents` | the whole file |
| The objects are not a `PdfObjects` | the whole file |
| A `/Parent`, `/Resources` or `/Font` link that is missing, unreadable, or defined twice with different values (an incremental update) | that page's streams |
| A name the page's `/Font` dictionary does not list | that name |

The fallback cases cannot hide a page from the map. A page the index misses could only be
one that failed to parse or lives in an unreadable object stream, and both fall back for the
whole file. A decoy page that draws the same stream only adds its fonts to the union.

## Commands and results (this container)

- Full `uv run pytest -q tests`: 641 passed, 5 skipped. The focused run of the PDF, scanner,
  text, heuristics, demo, and timing test files: 370 passed.
- Seven new tests in `tests/test_pdftext.py`:
  - Each page reads its own font (5 blocks, not unmapped), and one stream on 5 pages is
    still capped and reported.
  - Inherited and indirect resources.
  - An unparsable `/Contents` object falls back for the whole file.
  - A name the page does not list uses the union.
  - Resources defined twice fall back for their stream.
  - Pages inside an object stream are read.
  - An unreadable object stream falls back.

  Five of the seven fail on main. The two that pass there pin fallback behavior main already
  has. The two existing cap tests now use one shared stream, where the cap still applies.
- `docs/verification/check_added_rules.py`: passed, 218 cases plus 4 vendor-override cases.
  `font_reading_cases()` adds three shared-stream cases and now expects the phrase rule on
  the per-page fixtures.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 216 `ok`. The six `fonts` cases
  include one stream on five pages, which is still reported as unmapped.
- `docs/research/probe_rule_coverage.py --verify`: exit 0.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete.
  `heuristic_pdf_text_unmapped` now hits no file; `pdf/merged-5-fonts.pdf` is clean. The
  remaining hits are the four tagged Windows files.
- `docs/verification/check_worst_case_timing.py`: PASS, 31 inputs of exactly 4 MiB. Two are
  new: `pdf-page-fonts.pdf` (small pages that all draw one stream, each naming new fonts),
  5.94 s, and `pdf-page-parents.pdf` (pages under a 31-level `/Parent` chain), 4.38 s. The
  slowest was `pdf-page-objects.pdf` at 6.06 s.
- `check_rule_pairs.py` (115 rules), `lint_rules.py` (85 rules), `ruff check .`,
  `ruff format --check .`, and `mypy --strict src` (22 files): clean.

Cost on 4 MiB adversarial inputs, main → this change, one run each:

| Input | main | this change |
| --- | --- | --- |
| pages sharing one stream, each naming new fonts | 5.33 s | 6.26 s |
| pages under a 31-level `/Parent` chain | 4.21 s | 4.81 s |
| objects whose strings say `/Contents` | 3.15 s | 3.61 s |
| only object headers | 0.97 s | 2.26 s |

On the real files, `merge-mixed-20.pdf` took 3.3 s instead of 1.8 s, because it is now read
to the end instead of stopping at the block limit.

## Residual risks and boundaries

- **Form XObjects** still use the file-wide union, so a form drawn on several pages keeps the
  four-reading cap and its note. Reading a form's own `/Resources` is a separate change.
- **Fonts selected another way.** A font selected through an ExtGState `/Font` entry (`gs`)
  is not read, as before.
- **Readers can differ.** Readers that tolerate a page tree this reader does not parse can
  differ. Every such case falls back to the union rather than to a narrower map.
- **Cost.** The index adds one pass over the object headers; on a 4 MiB file of only headers
  that is about 1.3 s.
- **Synthetic sample.** The fixtures are synthetic and locally generated. They are not a
  production false-positive rate. Hosted CI has not run this change.
