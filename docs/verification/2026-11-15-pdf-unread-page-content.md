# PDF page content no view decodes (#223)

Date: 2026-11-15. Base: `main` at `3cff4d1`. Engine: YARA-X 1.23.0, Python 3.12.3, Linux
container. Rules: the shipped `rules/local` and `rules/rules.lock`, no vendor packs.

## What changed

A PDF stream that is page content, and whose filter chain the PDF views cannot decode, used
to drop out of every view with no trace. It is now the note `heuristic_pdf_content_unread`,
and the report gains `pdf_content_unread`, a count of those streams by filter.

- **Page content** is a stream that a `/Contents` entry names and whose dictionary marks it
  as no image, form, or font program, or a form XObject (`/Subtype /Form`). The `/Contents`
  entry may be a direct reference, a direct array, an array object, or a page dictionary
  stored in an object stream. A stream that nothing names is not page content, and neither
  is an image, a font, or an object stream.
- **Cannot decode** covers three cases:
  - a filter with no decoder here (CCITTFax, JBIG2, JPX, DCT, Crypt, or a name no reader
    knows);
  - an ASCIIHex or ASCII85 stage with nothing after it;
  - LZW past 2 MiB or RunLength past 8 MiB encoded.

  A Flate, LZW, or RunLength stream whose bytes fail to decode is not reported. Neither is a
  stream with no dictionary that parses.
- **The count** is keyed by the standard filter name of ISO 32000-1 Table 6
  (`LZWDecode`, `CCITTFaxDecode`, ...), or `other`. A name taken from the file never reaches
  the report. JSON reports and SARIF run properties carry it. The demo response and the Pages
  allowlist do not.
- **Grading** follows `heuristic_pdf_text_unmapped`: a note. `default` reports advisory with
  exit 0. `agent-ingest` holds the file (exit 1). `agent-document` records it and passes the
  file (exit 0). Incomplete was weighed and declined; the backlog has the reason.

## The miss, on the base revision

The fixtures are built with `probe_detection_gaps.py`'s own helpers. The over-cap LZW stream
is a short encoding of the override sentence, split across two `Tj` strings, followed by
2 MiB of padding after the end-of-data code.

| Fixture | `3cff4d1` (default / ingest / document) | This change |
| --- | --- | --- |
| LZW page content under the cap, override sentence (control) | advisory / block / advisory, `agent_prompt_injection_phrases` | unchanged |
| LZW page content past the cap, same sentence | **clean / clean / clean** | advisory / block / advisory, `heuristic_pdf_content_unread`, `{"LZWDecode": 1}` |
| The same past the cap, benign twin sentence | clean / clean / clean | the note, as above: the gate did not read it |
| Page content under `/CCITTFaxDecode` | clean ×3 | the note, `{"CCITTFaxDecode": 1}` |
| Page content under `/BogusDecode` | clean ×3 | the note, `{"other": 1}` |
| Form XObject past the LZW cap | clean ×3 | the note, `{"LZWDecode": 1}` |
| Zip holding the past-the-cap PDF | clean ×3 | the note on `zip:0` |
| DCT image beside a readable page (benign) | clean ×3 | clean ×3 |
| LZW image past the cap (benign) | clean ×3 | clean ×3 |
| An LZW stream past the cap that nothing names (benign) | clean ×3 | clean ×3 |

What readers show (poppler `pdftotext` 24.02.0, pypdf 7.1.0 in a separate environment):

| Fixture | poppler | pypdf |
| --- | --- | --- |
| LZW and RunLength page content past the caps | the override sentence | the override sentence |
| ASCIIHex alone, ASCII85 alone | the override sentence | the override sentence |
| Page content under CCITTFax | nothing | the sentence: it passes the bytes through as they are |
| A `/Contents` array member under JPX | the readable member only | both members, the JPX bytes as they are |
| Page content under an unknown filter | nothing | `NotImplementedError` |
| Form XObject under JBIG2 | nothing | nothing |

The LZW, RunLength, and ASCII-only cases are text that common readers show and the gate did
not read. The CCITTFax and JPX cases are shown by one of the two readers. The note says what
the gate did not read, not what any reader shows.

## Inventory and benign sweep

The container holds two PDFs, so the corpus was generated with no download. It has 626 files
(624 unique):

| Generator | Files |
| --- | ---: |
| LibreOffice 24.2.7 Writer and Calc, from installed text, Python stdlib sources, and CSV | 195 |
| The same as PDF/A-1, tagged | 40 |
| reportlab, page compression on and off, some with images | 120 |
| fpdf2 | 60 |
| matplotlib | 25 |
| Pillow image PDFs (modes 1, L, RGB, P, CMYK, LA, RGBA; single and multi-page) | 14 |
| Chromium print (Playwright) | 50 |
| pdftocairo rewrites | 80 |
| pypdf rewrites, half with compressed content streams | 40 |
| The two installed PDFs | 2 |

Filters by stream class, across the 624 unique files:

| Class | Filter | Streams |
| --- | --- | ---: |
| Page content | `FlateDecode` | 2,260 |
| Page content | `ASCII85Decode` then `FlateDecode` | 136 |
| Page content | none | 147 |
| Image | `FlateDecode` | 30 |
| Image | `ASCII85Decode` then `FlateDecode` | 40 |
| Image | `DCTDecode` | 9 |
| Image | `JPXDecode` | 6 |
| Image | `CCITTFaxDecode` | 3 |
| Image | `ASCIIHexDecode` | 3 |
| Other (fonts, maps, object streams) | `FlateDecode` / none | 2,189 / 42 |

No page content stream uses a filter the views cannot decode, so no file is marked. The only
unsupported filters in the corpus are on 18 images, and none is reported.

`main` (`3cff4d1`, its own worktree) and this change each scanned all 624 files under
`default`, `agent-ingest`, and `agent-document`, with the same rules, in separate processes:

- **0 of 1,872 outcomes changed**: verdict, finding set (rule, severity, view), and
  incomplete reason.
- No file took more than twice as long plus half a second. The sums were 173.3 s on `main` and
  171.9 s here.

On both revisions, 335 of these files are advisory under `default` and held under
`agent-ingest`. Every one is from the pre-existing note `heuristic_pdf_OpenAction_goto`:
LibreOffice, pypdf rewrites of its output, and fpdf2 write a GoTo `/OpenAction`. That is
unrelated to this change and documented in [rules.md](../rules.md).

## Timing

The pass that marks a stream unread runs only when some stream's filter was not decoded. It
reads the `/Contents` references once, the decoded object streams once, and every array
object in the file once.

| Input, 4 MiB | `3cff4d1` | This change |
| --- | ---: | ---: |
| 990 CCITTFax content streams in one `/Contents` array | 0.87 s, clean | 0.93 s, the note, `{"CCITTFaxDecode": 990}` |
| One JPX content stream beside array objects of 9,000 references, each named by `/Contents` | 4.37 s, clean | 5.04 s, the note |

The second input is `pdf-unread-content.pdf` in the worst-case tripwire, which now has 83
inputs. On its own it scanned in 4.5 s, under the 10 s ceiling. A first version rebuilt the set of
named streams for each array; it now updates the set in place, so the pass is linear in the
file.

## Live demo and public replay

- **Live workbench.** `yara-gate demo --rules <disposable copy>` was driven in headless
  Chromium (Playwright) with "Run every pair". Under each of `agent-ingest`,
  `agent-document`, and `default`: 81 of 81 results as expected, 0 findings on benign twins,
  no console errors. The glyph-ID PDF pair scanned side by side shows block (attack) beside
  clean (twin). The workbench scans only the catalog and pasted text, so the new note itself
  is checked through the library and CLI, not the page.
- **Recorder.** `record_pages_demo.py --baseline web-demo/recordings.json` reported that
  outcomes match for 82 scenarios × 3 policies, with only provenance refreshed. The committed
  recordings are not changed.
- **Pages site.** `build_pages.py` validated 246 policy recordings. In Chromium, the limits
  paragraph now names the filters and the note. It used to say LZW page streams are skipped,
  which has been out of date since #233. It shows no console errors and no horizontal scroll
  at 390 px.

## Installed CLI

Each policy ran on a disposable home and a disposable rules copy, scanning the inbox fixtures
`unread.pdf` (LZW past the cap), `image.pdf` (LZW image past the cap), and `nested.zip`
(holding `unread.pdf`).

| Policy | Exit | `unread.pdf` | `nested.zip` | `image.pdf` |
| --- | ---: | --- | --- | --- |
| `agent-ingest` | 1 | `blocked/` | `blocked/` | `clean/` |
| `agent-document` | 0 | `clean/` | `clean/` | `clean/` |
| `default` | 0 | `clean/` | `clean/` | `clean/` |

The JSON reports carry `"pdf_content_unread": {"LZWDecode": 1}`. The nested finding's
`member_path` is `["zip:0"]`. `scan -` from stdin exits 1 under `agent-ingest` and 0 under
`agent-document`.

## What was run

| Check | Result |
| --- | --- |
| `probe_detection_gaps.py --verify` | 631 ok, with 11 new `unread` cases; open B3, B5, and generic XML text, as before |
| `probe_rule_coverage.py --verify`, `measure_precision.py --fail-over`, `check_rule_pairs.py` (119 rules, with the new pair), `check_added_rules.py` (246 + 4) | Pass |
| `check_worst_case_timing.py` | See below |
| `record_pages_demo.py --baseline`, `build_pages.py` | Outcomes match; 246 recordings validated |
| `pytest` on `test_report` (with the new test), `test_pages_build`, `test_demo`, `test_pdftext`, `test_scanner`, `test_pdfannotations`, `test_pdfxref` | 516 passed. The full suite is left to hosted CI |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `check_text_controls.py`, `check_doc_links.py` | Clean |

TIMING_PLACEHOLDER

`probe_pdf_reader_agreement.py` and `probe_pdf_font_reader_agreement.py` were not run. This
change does not alter what the page map accepts, which fonts are read, or any text a view
holds. It only reports streams that no view held.

## Not established

- Real-world PDFs with unsupported page-content filters. Older Acrobat and Distiller output
  (PDF 1.2 and earlier) used LZW for content, and none was available offline. The benign rate
  of the note on those is unmeasured. Content from such a generator under 2 MiB is decoded,
  as before.
- A Flate page stream that does not inflate is not reported. Readers recover partial output
  from such a stream, and its benign rate was not counted.
- An object stream the views cannot decode can still hide a redefined object; that is a
  separate backlog row.
- Synthetic fixtures. This is evidence for the shapes listed, not a detection rate.
