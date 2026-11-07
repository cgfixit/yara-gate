# Hidden Office and PDF text verification (2026-11-07)

Base: `682cf08fbb37d8778f87b2470902f8de6e4b02a9` (`main`, #179 merged).
Linux x86_64 container, Python 3.12.3, locked YARA-X 1.23.0. Disposable rules
copies (85 bundled rules, no vendor packs, no downloads) and disposable gate homes.
Nothing was executed, unpacked to disk, rendered, or fetched. Candidate scanner
source hashes:

- `src/yara_gate/content.py`: `cd0994d7b2d774574eb501b2185dfd244c67e17295970660e30eb7fd6f2e51a4`
- `src/yara_gate/pdftext.py`: `0d0d8b22704157f6b74e424ec5cf6ceaf9a36d566b034e0979631cdcda1391a6`
- `src/yara_gate/scanner.py`: `31efe5c08dc3c1643c6f587e2981085f74cc4720c1c776b54196ba52bc104a1c`

## The defect on the base

[#110](https://github.com/cgfixit/yara-gate/issues/110), Phase 2 of
[#171](https://github.com/cgfixit/yara-gate/issues/171). On the base, the gap probe's
three hidden-text cases (a docx run under `w:vanish`, PDF text in render mode `3 Tr`,
PDF text in a white fill) each gave only `agent_prompt_injection_phrases`, a note:
`advisory` under the default policy, `block` under `agent-ingest`, and `advisory` with
exit 0 under `agent-document`. A document that hides an instruction from the person
reviewing it therefore passed the document read rule, while the same trick in HTML
(`agent_hidden_html`) was already held. Reproduced with
`docs/research/probe_detection_gaps.py`: 159 ok, 6 open, the three #110 cases among
the open ones.

## What changed

- `content.ooxml_hidden_texts` reads the text of runs a reader does not show, one
  piece per hidden stretch, from a run's, shape's, or slide's own properties (Word
  `vanish`/`specVanish`/`webHidden`, 1 pt or smaller, near-white without shading;
  PowerPoint 1 pt runs, hidden shapes and slides; Excel rich-text runs at 1 pt or in
  near-white). Tracked-change earlier properties and paragraph-mark properties do not
  count. A part with none of the names that can hide text is skipped unread.
- `pdftext` follows the render mode, the fill colour, and the areas each content
  stream paints, and collects text drawn in render mode 3 or 7, in near-white over
  nothing painted, and (in page content) under 1 pt or outside every `/MediaBox`.
  Visible `pdf-text` and `pdf-paragraph` output is unchanged; the hidden grouping reuses
  the decoded readings.
- `scanner._hidden_text_findings` scans those pieces as `ooxml-hidden-text` and
  `pdf-hidden-text` (then `+text-folded`). An `agent_` rule match there at note or
  advisory severity, other than the Unicode-control and base64 rules, adds one advisory
  `heuristic_hidden_text` per member, labeled with the view. No rule file, severity,
  or policy table changed.

Decisions, with the reason for each:

- **Advisory, one id.** Matches `agent_hidden_html`, keeps reports compact, and makes
  `agent-document` hold the file. The rule's own note still comes from the views that
  read every run, so a report says both what was said and that it was hidden.
- **Hidden text alone is not reported.** Templates, watermarks, TOC page numbers
  (`webHidden`), and OCR layers hide text constantly; the conjunction is the signal.
  The probe's vanished "Draft", vanished placeholder, and OCR invoice line stay clean.
- **No OCR exemption.** An OCR layer is render mode 3 over a page image, and so is an
  attacker's; exempting text over an image would let any picture hide an instruction.
  A scanned page whose text layer reads as an override phrase is held under
  `agent-document` (recorded in the probe as an accepted boundary).
- **White counts only over nothing painted.** The first sweep below found white table
  headers in every LibreOffice slide export; calling all white text hidden would hold
  a dark-theme deck that quotes an attack. Painted areas are bounded at 32 per stream,
  and areas past the cap are ignored, so a handful of scattered dots cannot widen one
  box over the page (an earlier merge-into-last draft allowed exactly that, and the
  timing fixture caught it).

## Local execution

- `docs/research/probe_detection_gaps.py --verify`: 189 ok, 3 open (base 159 ok,
  6 open), no FAIL or STALE. The three #110 markers are removed. Added cases: Word
  white, near-white, 1 pt, and look-alike spelling under `vanish` (held, the last
  through `ooxml-hidden-text+text-folded`); white in a dark cell, white with run
  shading, `vanish w:val="0"`, a tracked change whose earlier formatting was hidden,
  and a hidden paragraph mark (shown: note only); hidden halves around a shown word,
  a hidden placeholder, and a tracked deletion (clean); a hidden PowerPoint shape and a
  1 pt run (held) beside an 18 pt control (note); an Excel white rich-text run (held);
  PDF `7 Tr`, CMYK white, 0.5 pt, and off-page text (held); white restored by `Q`,
  grey fill, white on a dark box, and white on a page image (note); white beside a
  dark box (held); hidden halves around a shown word (clean); an OCR-shaped page
  holding the phrase (held, accepted).
- `docs/research/probe_rule_coverage.py --verify`: passed.
- `check_rule_pairs.py` (115 rules), `check_added_rules.py` (180 plus 4 override
  cases), `check_scan_only.py` (7 cases), and `measure_precision.py --fail-over`
  (324 files, 0 incomplete, same table as base): passed.
- Ruff check and format, `mypy --strict src`, and `check_text_controls.py`: passed.
- `scripts/record_pages_demo.py --baseline web-demo/recordings.json` on the
  committed candidate: 41 scenarios under 3 policies match the reviewed baseline; only
  provenance changed, and the public recordings are not modified here.
- The existing `tests/test_pdftext.py` scenarios (deadline on a huge `TJ`, text past
  the block cap, `q`/`Q` font restore, a continuation stream, an unresolved two-byte
  font) were exercised directly as code and behave as before. The pytest suite is left
  to hosted CI.

Direct CLI run, disposable home, `--policy agent-document`, four inbox files:

| File | Exit | Placed | Findings |
| --- | --- | --- | --- |
| docx, phrase in a vanished run | 1 | `blocked/` | phrase note (`raw`, `ooxml-text`), `heuristic_hidden_text` (`ooxml-hidden-text`, `zip:1`) |
| PDF, phrase in `3 Tr` | 1 | `blocked/` | phrase note (`raw`, `pdf-text`), `heuristic_hidden_text` (`pdf-hidden-text`) |
| docx, phrase quoted in a shown run | 0 | `clean/` | phrase note only |
| docx, vanished "Draft" | 0 | `clean/` | none |

SARIF results for the derived findings carry an empty region, so no member or view
offset becomes an outer-file offset. The vanished-run bytes resubmitted under a new
name were held again (exit 1, the slot keeps the latest name). `scan -` with
`--name memo.docx` gave `block` under `agent-document`, `advisory` with exit 0 under
the default policy, and kept only the name's final component.

## Benign sweep

538 generated Office and PDF files, scanned in place by the base (a git worktree on
`PYTHONPATH`) and by the candidate under the default policy and `agent-document`:
the repository's 94 Markdown documents converted by pandoc 3.1.3 to docx (with a TOC)
and pptx (90 converted), and by openpyxl 3.1.5 to xlsx (a white-on-dark header row
and bold rich-text runs); LibreOffice 24.2.7.2 re-saves of 80 docx and 20 xlsx and PDF
exports of 80 docx and 76 pptx; and 4 files already on the host. 65 of them quote an
override phrase in shown text.

- The first candidate gave zero verdict or finding differences but read hidden text
  in 102 PDFs. Two causes, both fixed: a shown string was judged to be whitespace by
  its raw bytes, so a subset font's glyph code `0x20` read as a letter was glued into
  hidden text; and white table-header text in the slide exports was judged hidden.
- Final candidate: zero verdict or finding differences across 538 files and both
  policies, no `heuristic_hidden_text`, and no hidden view read anywhere.

Generated documents from two tools are not real-world traffic: this is not a
false-positive rate, and Word, PowerPoint, Acrobat, and OCR software were not used.

## Adversarial timing

One `scan_bytes` run per input, each exactly 4 MiB and built by
`check_worst_case_timing.py`, against the base and then the candidate, compilation
warmed outside the timer. This container measured about 1.35 times slower than the
hosted Ubuntu runner on the existing cases (for example `markdown-lines.md` 2.64 s
here, 1.95 s in [run 42317988835](https://github.com/cgfixit/yara-gate/actions/runs/42317988835)).

| 4 MiB input | Base seconds | Candidate seconds | Candidate outcome |
| --- | --- | --- | --- |
| `ooxml-comment.zip` (existing) | 1.126 | 1.083 | clean |
| `ooxml-hidden-runs.zip` (58,251 hidden pieces) | 0.876 | 3.388 | advisory (`agent_base64_blob`, as on base) |
| `pdf-hidden-stretch.pdf` | 4.180 | 5.285 | clean |
| `pdf-white-areas.pdf` (32 areas, a new point per string) | 3.758 | 5.091 | clean |
| `pdf-hidden-blocks.pdf` | 3.376 | 0.785 | incomplete, `pdf text blocks exceed 20000` |

The four new inputs are in the CI tripwire, which now runs 20 inputs (all passed here,
the slowest at 5.3 s against the 10 s ceiling); the three reader cases must show their
hidden view in `views_scanned`. Most of the PDF time is the existing text reader,
which had no PDF input in the tripwire before. The hidden-runs cost is one YARA pass
per piece, the same envelope as the other piece readers under `MAX_TEXT_PIECES`.
`pdf-hidden-blocks.pdf` alternates hidden and shown strings until the hidden
grouping reaches the existing 20,000-block cap, so a file that was clean on the base
is now incomplete: held, never passed. On real documents the Office reader cost
1.4 s over 32.7 MB of parts, about 3.5 ms a document.

## Not established

Synthetic fixtures and generated documents on one Linux host. The hiding signals come
from the OOXML and PDF specifications and were not checked against a real viewer, as
#171 asks before shipping; text hidden through styles, layouts, masters, cell formats,
hidden sheets, rows, or columns, DrawingML colours, clipping, transparency, a later
opaque fill, or a CropBox is not detected, and a bogus `/MediaBox` widens the page
union. None of this is a recall or false-positive rate, and it is not a general
prompt-injection defense.

## Review after merging current main into the PR branch

The review started from merge commit `a5337a8` with `main` at `05f94ca`. On
macOS arm64 with locked Python 3.12.12 and YARA-X 1.23.0, eight new cases
reproduced visibility errors in the real scanner. The follow-up passed all eight.

- Word comments could introduce a fake `w:vanish` or terminate a real hidden
  run. The tokenizer skips comments. Inherited shape visibility and container
  shading use the current stack entry, keeping nested lookups constant time.
- PDF stroke-only and fill-plus-stroke text could be held because of white fill
  even with a visible outline. White stroke with dark unused fill could pass.
  The detector now checks the paint channels active in the rendering mode.
  The size check uses the length of the transformed vertical axis, so rotating
  a 1.2 pt text matrix does not put it below the 1 pt threshold.
- An invisible PDF stream could make a different page's text appear hidden.
  A paint-only stream could also be skipped on its own page. Visibility state
  now carries across adjacent streams linked by a direct array in a raw page
  dictionary. That link does not cover indirect arrays or compressed page
  dictionaries. See [the rule boundaries](../rules.md#hidden-office-and-pdf-text).

`probe_detection_gaps.py --verify` reported 197 passing cases and three known
open gaps, with 85 bundled rules and no vendor downloads. Six focused PDF tests
passed, as did Ruff, strict mypy and the text-control check. The affected 4 MiB
Office and PDF timing fixtures finished in 1.03, 1.61 and 1.42 seconds against
the 10-second ceiling. These were single local measurements.

- `src/yara_gate/content.py`: `12222c8c8cbff3f88cb5cf22a1c13520937f4bdc2a919f8710c34416cdb44f14`
- `src/yara_gate/pdftext.py`: `6db89ec06a42ea455c1e2a477d385a307a05bd6e847b094e8e87d0b588faa2a4`
- `src/yara_gate/scanner.py`: `04ede7298bd35ae22312d3d61126e986c8811f0279a8502ed067fd36544cfe84`

A final review bound the continuation index to uniquely identified streams
already discovered by the PDF reader. The detection probe still reported 197
passes and three known open gaps. The updated `pdftext.py` SHA-256 is
`d80e6642930179cfd8632b534b809c59dffeadf3cfa87b117ae0ad3ac44400c9`.

## Linear continuation index

On `91af406`, the continuation index rescanned a 4 KiB window for object headers at every
`/Contents[` match. In this Linux container (Python 3.12.3, YARA-X 1.23.0), a 4 MiB file of
two content streams followed by repeated `/Contents[` hit the 30-second scan deadline
(incomplete, `timeout`). The same file took 2.30 s on `682cf08` and 2.53 s on `5575468`. 4 MiB
of small page objects, each with a two-stream `/Contents` array, took 11.82 s, against 1.25 s
and 1.38 s. Profiling put about 9 s per MiB inside the window rescans.

Headers are now indexed once and found by bisection. The `endobj` search moves forward only,
and each page object is parsed once. One page's references merge idempotently, so the result
cannot change. The original function, taken from `91af406`, and the new one returned identical
maps for every PDF in the 538-file sweep, every gap-probe PDF, 3,000 random byte mixtures, and
4,000 structured documents. The structured documents had random `/Contents` arrays, non-zero
generations, reused streams, window-edge padding, missing `endobj`, and duplicate keys; 2,705
of them gave a non-empty map.

The same two inputs now take 2.72 s and 3.17 s. Both join the CI tripwire as
`pdf-contents-arrays.pdf` and `pdf-page-objects.pdf`, and all 22 inputs passed. Also passed:
the gap probe (197 ok, 3 open), the coverage probe, `tests/test_pdftext.py` (6 passed), Ruff,
`mypy --strict src`, and `check_text_controls.py`.

- `src/yara_gate/pdftext.py`: `c65ecdf577a287792174721525c231a6388480c6cf31601ccccf8ad764372df0`

A forward-only cursor then replaced the header offset lists and parsed-object
set. On a 2 MiB input with 262,144 object headers, Python-traced peak memory in
the continuation parser fell from 19,306,926 to 3,650 bytes. The two versions
returned the same continuation maps on 4,000 generated inputs, and the detection
probe still passed 197 cases with three known gaps. The two new 4 MiB fixtures
ran locally in 0.97 s and 1.09 s. `pdftext.py` SHA-256 is
`3b375a24ff50be57b63e535c8dd19b21d3bff3e60cf68f9ec9b00d58fc167e0d`.
