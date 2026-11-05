# PDF paragraph view (2026-11-05)

Stacked on `views/pdf-text-operators` (#162). Linux x86_64, Python 3.12, locked YARA-X 1.22.1, a
disposable copy of the shipped rules (82 local rules, no vendor packs). Nothing was rendered or
opened in a viewer.

## Why

#162 scans each PDF text block (`BT ... ET`) on its own, as requested. Chrome and LibreOffice
start a new text object at every font change, and Chrome at every line, so a phrase with a word
in bold or italics, or a line wrap, is split across blocks and missed.

## Change

`pdf-paragraph`: a paragraph that spans two or more blocks is also scanned whole, one YARA pass
each. Blocks on the same baseline join with nothing, the next line within 1.7 font sizes joins
with a newline (the lexical rules accept hard wraps), and a larger jump ends the paragraph. Two
paragraphs are never joined, and a paragraph made of one block is not scanned twice. One finding
per rule is kept, sorted by rule id.

## Outcomes

| Probe | #162 (blocks only) | This branch |
| --- | --- | --- |
| Chrome: a word in bold inside the phrase; the phrase wrapped at 120 px | clean | `agent_override_imperative` (`pdf-paragraph`) |
| LibreOffice: bold and italic inside the phrase | clean | detected (`pdf-paragraph`) |
| Phrase planted in 20 host documents, Chromium, every seventh word bold | 0/20 | 20/20 |
| The same 20, LibreOffice | 20/20 | 20/20 |
| Two paragraphs 300 points apart; the LibreOffice two-paragraph near miss | clean | clean |
| 200 benign host documents (LibreOffice 150, Chromium 50) against their source text | 0 introduced | 0 introduced |
| 132 third-party test PDFs (pikepdf, pypdf) against `main` | 0 new findings | 0 new findings, 0 verdict changes |

`check_added_rules.py` restores `bold.pdf` (a phrase in three text objects on one baseline),
which #162 does not match.

## Cost

A 132 KB Chromium PDF with 1,500 paragraphs: 0.77 s on #162 and 0.73 to 0.77 s here (1,511
paragraph passes added to 10,501 block passes; the difference is within run-to-run noise). The
132 third-party PDFs take 8.7 s on both.

## Checks

`check_added_rules.py` (108), `check_rule_pairs.py` (110), `measure_precision.py --fail-over`,
ruff, `mypy --strict src`, `check_text_controls.py`, and the focused pytest files for the scanner
and heuristics.

## Not established

The third-party set is library test PDFs, not a sample of what users send. Columns that share a
baseline join without a space.
