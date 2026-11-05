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
  text object as a block, and cuts a block where its text jumps to a new paragraph.
- The scanner runs one YARA pass per block (`pdf-text`), keeps one finding per rule, and reports the note `heuristic_pdf_text_unmapped` when a composite font has no
  readable map or an unresolved font shows two-byte codes.
- Inside the PDF text loop only, a `yara_x.Scanner` is reused per compiled ruleset
  and thread (`threading.local`); every call still sets the timeout and every global. Hosted CI
  on the first push caught that reuse everywhere reorders a report's findings (the Pages
  recorder refused `hidden_html`: same findings, other order), so every other view builds a
  fresh Scanner as on `main`, and each view's findings are sorted by rule id.

## Design note: the scanning unit

The request was to join each Tj/TJ text block and scan each block separately; that is what
`pdf-text` does. A block is one text object (`BT ... ET`), also cut where its text jumps more
than 1.7 font sizes to a new paragraph, so LaTeX's one text object per page cannot join two
paragraphs. Cutting only narrows the unit.

The cost of the unit, measured below: Chrome and LibreOffice start a new text object at every
font change, and Chrome at every line, so a phrase with a word in bold or a wrap inside it is
split and missed. A view that also scans paragraphs spanning several blocks closes that gap;
it is proposed separately in a stacked draft PR so it can be accepted or declined on its own.

A first draft also added a space at every `Td`; Chrome positions single glyphs with a
same-line `Td`, which gave "W e fixed". Same-baseline moves now add nothing.

## Real-document differential

150 plain-text files from the host (`/usr/share/doc` READMEs, changelogs, copyright files,
licences) were converted to PDF by LibreOffice, and 50 of them by Chromium with paragraphs
split on blank lines and every seventh word in bold. Each PDF was scanned and compared with
a scan of its own source text, so a `pdf-text` finding that the text does not have would be introduced by the reconstruction.

| Set | PDFs | Introduced by reconstruction | `heuristic_pdf_text_unmapped` | Incomplete |
| --- | --- | --- | --- | --- |
| Benign host documents | 200 | 0 | 0 | 0 |

The sources had no findings of their own. To test the hit side on the same real layouts, the
phrase was planted as a paragraph in the middle of 20 of them and rendered by both
generators:

| Generator | Plain text | `main` | Branch |
| --- | --- | --- | --- |
| LibreOffice | 20/20 | 0/20 | 20/20 |
| Chromium, bold every seventh word | 20/20 | 0/20 | 0/20: every planted phrase is split by bold |

## Outcomes

| Probe | `main` | Branch |
| --- | --- | --- |
| Synthetic: LaTeX-style `-333` spaces with a wrap, kerned `TJ`, hex `Tj`, octal and line-continuation escapes, uncompressed stream, `'` operator, inline image before the text | clean | note `agent_override_imperative` (`pdf-text`) |
| Synthetic Identity-H with `ToUnicode` (`bfchar`, `bfrange`, array `bfrange`), font in an object stream through an indirect `/Font` dictionary, `/F1` naming two fonts | clean | detected |
| Identity-H without `ToUnicode`; unresolved two-byte font | clean | `heuristic_pdf_text_unmapped` |
| Two paragraphs 300 points apart; benign kerned text; benign glyph-ID text | clean | clean |
| Chrome `page.pdf()` and LibreOffice: a contiguous phrase, and a LibreOffice paragraph narrower than the phrase | clean | detected |
| Chrome and LibreOffice: a word in bold or italic inside the phrase; Chrome wrapped at 120 px | clean | clean (split across text objects) |
| Chrome and LibreOffice benign letters, a 200-section report, a table, a two-paragraph near miss, and two real third-party PDFs on the host | clean or a raw `heuristic_pdf_OpenAction_goto` note as on `main` | the same, no new finding |

`check_added_rules.py` gains 10 PDF cases; with `src/` reverted, the 7 hits miss and the 3
benign cases pass. `check_rule_pairs.py` adds `heuristic_pdf_text_unmapped`.

## Third-party PDFs

132 unique PDFs from the test resources of two PyPI source packages (`pikepdf` 10.17.0: 61,
`pypdf` 6.21.4: 71), written by many producers and including malformed, encrypted, CJK,
Type 3, and form-XObject files. Extracted with `tar --wildcards '*.pdf'` into empty
directories and only scanned. Each was scanned under `default` by `main` (a worktree) and by
the branch, and the verdicts, findings, incomplete reasons, and times compared.

The first run found two defects that generated PDFs had not shown, both false
`heuristic_pdf_text_unmapped` notes:

- `fontsampler.pdf` (clean on `main`): a Type0 font that embeds its descendant font and a long
  `/W` array puts `/ToUnicode` past the 4 KB object-lookup window. A truncated window now
  falls back to the whole object, up to `endobj` (1 MB at most).
- `example.pdf`: a page's `/Contents` array is one stream to a reader, so a font selected in one
  stream is in effect in the next. The selected font and size now carry across streams.

The run also showed `issue-604.pdf` (8 MB) at 8.5 s against 1.7 s on `main`: font lookups
called the raw-object index once per key. They are now primed in two batches, and the object
header index is built once.

| Run | New findings | Lost findings | Verdict changes | Incomplete changes |
| --- | --- | --- | --- | --- |
| First | 2 × `heuristic_pdf_text_unmapped` | 0 | 1 (`fontsampler.pdf` clean to advisory) | 0 |
| After the fixes | 0 | 0 | 0 | 0 |

`check_added_rules.py` gains `cid-long-font.pdf` and `cid-split-contents.pdf`; with the
previous `pdftext.py`, the first gives a false note and the second a miss.

## Cost

A 132 KB Chromium PDF with 1,500 paragraphs: 0.12 s on `main`, 1.52 s with a Scanner per
paragraph, 0.47 s after reusing one and replacing the character tokenizer with a regex, and
0.77 s with blocks cut at paragraph breaks (10,501 block passes). The 200-PDF differential
corpus scanned in 13.1 s. The 132 third-party PDFs take 4.5 s on `main` and 8.7 s on the
branch; the slowest, `issue-604.pdf` (8 MB, 378,000 operators), 1.7 s and 3.8 s.

## Checks

`lint_rules.py`, `check_rule_pairs.py` (110), `check_added_rules.py` (107),
`check_scan_only.py`, `check_intake.py`, `check_text_controls.py`,
`measure_precision.py --fail-over` (per-rule counts identical to `main`, no heuristic hit),
`probe_rule_coverage.py --verify`, `yara-gate selftest`, ruff, `mypy --strict src`, and focused
pytest (heuristics, scanner, report, policies, CLI JSON, text fast paths, demo: 253 passed).

## Not established

The third-party set is library test PDFs, not a sample of what users send; no scanned-image PDF has text to read, and Word-authored PDFs are represented only through these sets.
Column layouts that share a baseline join without a space; Type 3 fonts and fonts whose codes
need the font program are not decoded.
