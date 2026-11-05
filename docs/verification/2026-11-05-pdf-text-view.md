# PDF text-operator view (2026-11-05)

Source: `main` at `7f9934c`, branch `views/pdf-text-operators`. Linux x86_64, Python 3.12,
locked YARA-X 1.22.1, a disposable copy of the shipped rules (82 local rules, no vendor packs).
No PDF was rendered or opened in a viewer; generated PDFs hold inert text.

## Baseline

The raw and `pdf-flate` views read a phrase only when one string held it whole. On `main`, a
kerned `[(Please disre) -20 (gard ...)] TJ`, a hex `<...> Tj`, a phrase with one word in bold,
a wrapped line, and any text stored as glyph IDs with a `ToUnicode` map (Chrome, LibreOffice,
and Word all write this) scanned clean.

## Change

- `content.pdf_streams` decodes every stream once; `pdf_views` reads it, unchanged in output.
- `pdftext.py` tokenizes content streams (inline image data skipped), follows the CTM and the
  text matrix, decodes `Tj`/`TJ`/`'`/`"` strings through each font (WinAnsi, or the font's
  `ToUnicode` `bfchar`/`bfrange` map, fonts found in direct, indirect, and object-stream
  resource dictionaries, up to four readings when one name means different fonts), joins each
  text object as a block, and groups blocks by baseline into paragraphs.
- The scanner runs one YARA pass per block (`pdf-text`) and per multi-block paragraph
  (`pdf-paragraph`), keeps one finding per rule and view, and reports the note `heuristic_pdf_text_unmapped` when a composite font has no
  readable map or an unresolved font shows two-byte codes.
- Inside the PDF text loop only, a `yara_x.Scanner` is reused per compiled ruleset
  and thread (`threading.local`); every call still sets the timeout and every global. Hosted CI
  on the first push caught that reuse everywhere reorders a report's findings (the Pages
  recorder refused `hidden_html`: same findings, other order), so every other view builds a
  fresh Scanner as on `main`, and each view's findings are sorted by rule id.

## Design note: the scanning unit

The request was to join each Tj/TJ text block and scan each block separately. A first draft did
exactly that per `BT ... ET`, and on real Chrome and LibreOffice output a bold word or a line
wrap starts a new text object, so the phrase was missed. A second draft scanned paragraphs
instead, which met the detection goal but not the requested unit. The view now does both:

- `pdf-text`: each text object's strings joined and scanned on its own, cut at a paragraph
  break so a LaTeX page (one `BT` per page) does not join two paragraphs;
- `pdf-paragraph`: a paragraph that spans two or more blocks, scanned whole. A paragraph
  ends at a baseline jump of more than 1.7 font sizes; two paragraphs are never joined.

A first draft also added a space at every `Td`; Chrome positions single glyphs with a
same-line `Td`, which gave "W e fixed". Same-baseline moves now add nothing.

## Real-document differential

150 plain-text files from the host (`/usr/share/doc` READMEs, changelogs, copyright files,
licences) were converted to PDF by LibreOffice, and 50 of them by Chromium with paragraphs
split on blank lines and every seventh word in bold. Each PDF was scanned and compared with
a scan of its own source text, so a `pdf-text` or `pdf-paragraph` finding that the text does
not have would be introduced by the reconstruction.

| Set | PDFs | Introduced by reconstruction | `heuristic_pdf_text_unmapped` | Incomplete |
| --- | --- | --- | --- | --- |
| Benign host documents | 200 | 0 | 0 | 0 |

The sources had no findings of their own. To test the hit side on the same real layouts, the
phrase was planted as a paragraph in the middle of 20 of them and rendered by both
generators:

| Generator | Plain text | `main` | Branch | View |
| --- | --- | --- | --- | --- |
| LibreOffice | 20/20 | 0/20 | 20/20 | `pdf-text` |
| Chromium, bold every seventh word | 20/20 | 0/20 | 20/20 | `pdf-paragraph` |

## Outcomes

| Probe | `main` | Branch |
| --- | --- | --- |
| Synthetic: LaTeX-style `-333` spaces with a wrap, kerned `TJ`, hex `Tj`, octal and line-continuation escapes, uncompressed stream, `'` operator, inline image before the text | clean | note `agent_override_imperative` (`pdf-text`) |
| Synthetic Identity-H with `ToUnicode` (`bfchar`, `bfrange`, array `bfrange`), font in an object stream through an indirect `/Font` dictionary, `/F1` naming two fonts | clean | detected |
| Identity-H without `ToUnicode`; unresolved two-byte font | clean | `heuristic_pdf_text_unmapped` |
| Two paragraphs 300 points apart; benign kerned text; benign glyph-ID text | clean | clean |
| Chrome `page.pdf()`: phrase, bold word, wrapped at 120 px | clean | detected |
| LibreOffice HTML export: bold and italic inside the phrase | clean | detected |
| Chrome and LibreOffice benign letters, a 200-section report, a table, a two-paragraph near miss, and two real third-party PDFs on the host | clean or a raw `heuristic_pdf_OpenAction_goto` note as on `main` | the same, no new finding |

`check_added_rules.py` gains 9 PDF cases; with `src/` reverted, the 6 hits miss and the 3
benign cases pass. `check_rule_pairs.py` adds `heuristic_pdf_text_unmapped`.

## Cost

A 132 KB Chromium PDF with 1,500 paragraphs: 0.12 s on `main`, 1.52 s with a Scanner per
paragraph, 0.47 s after reusing one and replacing the character tokenizer with a regex, and
0.73 s with both units (10,501 block passes and 1,511 paragraph passes). The 200-PDF
differential corpus scanned in 15.4 s.

## Checks

`lint_rules.py`, `check_rule_pairs.py` (110), `check_added_rules.py` (106),
`check_scan_only.py`, `check_intake.py`, `check_text_controls.py`,
`measure_precision.py --fail-over` (per-rule counts identical to `main`, no heuristic hit),
`probe_rule_coverage.py --verify`, `yara-gate selftest`, ruff, `mypy --strict src`, and focused
pytest (heuristics, scanner, report, policies, CLI JSON, text fast paths, demo: 253 passed).

## Not established

The real-document corpus is host text rendered by two generators, not third-party PDFs from the wild (scanned, print-to-PDF, or Word-authored files).
Column layouts that share a baseline join without a space; Type 3 fonts and fonts whose codes
need the font program are not decoded.
