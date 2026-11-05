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
  resource dictionaries, up to four readings when one name means different fonts), and groups
  text by baseline into paragraphs.
- The scanner runs one YARA pass per paragraph as the `pdf-text` view, keeps one finding per
  rule, and reports the note `heuristic_pdf_text_unmapped` when a composite font has no
  readable map or an unresolved font shows two-byte codes.
- Inside the `pdf-text` paragraph loop only, a `yara_x.Scanner` is reused per compiled ruleset
  and thread (`threading.local`); every call still sets the timeout and every global. Hosted CI
  on the first push caught that reuse everywhere reorders a report's findings (the Pages
  recorder refused `hidden_html`: same findings, other order), so every other view builds a
  fresh Scanner as on `main`, and the view's findings are sorted by rule id.

## Design note

The first draft scanned each `BT ... ET` text object alone. Chrome starts a new text object at
every font change and line, so a bold word or a wrap split the phrase and it was missed. The
view now follows the HTML-block pattern of #145 item 5 in PDF terms: inline runs on one
baseline join, the next line within 1.7 font sizes joins with a newline (the lexical rules
accept hard wraps), and a larger jump starts a separately scanned paragraph. A first draft
also added a space at every `Td`; Chrome positions single glyphs with a same-line `Td`, which
gave "W e fixed". Same-baseline moves now add nothing.

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
paragraph, 0.47 s after reusing one and replacing the character tokenizer with a regex.

## Checks

`lint_rules.py`, `check_rule_pairs.py` (110), `check_added_rules.py` (106),
`check_scan_only.py`, `check_intake.py`, `check_text_controls.py`,
`measure_precision.py --fail-over` (per-rule counts identical to `main`, no heuristic hit),
`probe_rule_coverage.py --verify`, `yara-gate selftest`, ruff, `mypy --strict src`, and focused
pytest (heuristics, scanner, report, policies, CLI JSON, text fast paths, demo: 253 passed).

## Not established

No corpus of real-world third-party PDFs beyond the two on this host and the generated ones.
Column layouts that share a baseline join without a space; Type 3 fonts and fonts whose codes
need the font program are not decoded.
