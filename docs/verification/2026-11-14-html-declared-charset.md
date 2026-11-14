# HTML and XML in a declared legacy charset — November 14, 2026

Base: `main` at `f54c57e`. Linux 6.18 x86_64 container, 4 CPUs, Python 3.12.3, YARA-X 1.23.0,
bundled local rules only (88), no vendor download. Every scan used a disposable copy of
`rules/local` and the real `scan_bytes` API. Chromium 153.0.8010.12 headless, through
Playwright 1.63.0, loaded each inert document from a `file://` URL with every other request
aborted. Nothing was executed and the scanner fetched nothing. The container was shared with
other runs, so wall times are comparisons on one machine, not benchmarks.

Issue: [#240](https://github.com/cgfixit/yara-gate/issues/240).

## 1. The gap

**Verified on `f54c57e`.** `_decoded_text` and `text_views` read text as UTF-16 when it has a
byte order mark or looks like UTF-16, and as UTF-8 otherwise. A page in windows-1251 became
U+FFFD on `utf8-replaced`, and the UTF-8 byte patterns of
`agent_prompt_injection_multilingual` matched nothing:

| Page | `f54c57e`, `agent-document` | `agent-ingest` |
| --- | --- | --- |
| Russian override phrase, UTF-8, `<meta charset="utf-8">` (control) | advisory: `raw`, `text-folded` | block |
| The same phrase in windows-1251, `<meta charset=windows-1251>` | clean | clean (admitted) |
| The same, declared through `http-equiv` | clean | clean |
| Ordinary Russian text in windows-1251 (benign) | clean | clean |

`probe_detection_gaps.py` now holds 23 charset cases. On `f54c57e`, 16 miss, each clean under
`agent-ingest`: windows-1251, `x-cp1251`, KOI8-R, ISO-8859-1 (French), Shift_JIS,
ISO-2022-JP, GB2312, EUC-KR, windows-1256, an XHTML and an XML declaration, a look-alike
English phrase in windows-1251, and three tokenizer shapes. All 23 hold with the change.

## 2. What a browser decodes

**Verified with Chromium 153.** Every document held Russian text written in windows-1251 and
declared only other encodings, so `document.characterSet` says whether a declaration was
honoured (KOI8-R, ISO-8859-5, and so on) or passed over (windows-1251, the detector's guess
from the bytes):

| Shape | Chromium |
| --- | --- |
| `<meta charset>`, or `http-equiv=content-type` with `content`, in any attribute order, quoting, or case | honoured |
| `content` naming a charset with no `http-equiv` | passed over |
| A meta anywhere in the head: after a 1,100-byte comment, 5,000 bytes of script, 70 KiB of style, 3,000 bytes of text | honoured |
| A meta after `<body>` that starts at byte 990; one at byte 1,030 | honoured; passed over |
| After `<object>` and `<param>` tags past 1,024 bytes | passed over: `param` ends the head |
| Inside a comment, a `script`, a `title`, a `textarea`, an attribute value | passed over |
| Inside a `noscript` | honoured |
| After `<!-->`, `<!--->`, or `--!>`, which close a comment | honoured |
| In a script after `<!--<script></script>`, the double escape | passed over |
| After `<script><!-- a <!--><script></script>`: `<!-->` inside the escape ends it, so that `</script>` ends the script | honoured |
| `--!>` inside an escaped or a doubly escaped script, before a meta | passed over: `--!>` closes a comment, not a script escape |
| `<meta x"charset=koi8-r>`: the quote is part of the attribute name | passed over |
| `<meta charset=a charset=b>`; `content` then `charset`; `charset` then `content` | b; `charset`; `charset` |
| `charset=""` then a `content` | passed over |
| The first meta names UTF-8; the first names an unknown label (`cp037`) | UTF-8; the next meta decides |
| UTF-8 byte order mark before a windows-1251 meta | UTF-8 |
| `utf-16`, `utf-16le`; `x-user-defined`; `iso-2022-kr`, `hz-gb-2312` | UTF-8; windows-1252; replacement |
| `utf-7` | passed over: not a WHATWG label |
| `latin1` or `us-ascii` | windows-1252 |
| `x-cp1251`, `x-sjis`, `ks_c_5601-1987`, `gb2312`, `big5` | windows-1251, Shift_JIS, EUC-KR, GBK, Big5 |
| An XML declaration at byte 0 of `.xml`, `.xhtml`, `.svg` | honoured; a meta in `.xhtml` is not read |
| An XML declaration in `.html` with no meta; with a meta | honoured; the meta wins |
| `<?XML`, `Encoding=`, or a space before `<?xml` | passed over |
| No declaration at all | **windows-1251**: the detector reads the page |

The detector row is not built here: issue #240 asks that a page with no declaration stay
UTF-8. It is in the [backlog](../research/detection-backlog.md#further-candidates-not-yet-in-the-probe).

## 3. Change

`content.decoded_text` is the one reading both `scanner._decoded_text` and `text_views` use;
the scanner hands its reading to `text_views`, so a unit is decoded once. When the bytes are
not UTF-8 and the file is not a mail message, `declared_codec` looks for a meta as Chromium's
prescan does (comments, bogus comments, raw-text bodies, script escapes, and attributes as
the tokenizer reads them; the head, then the first 1,024 bytes) and then for an XML
declaration at byte 0. A file named `.xml`, `.xhtml`, `.xht`, or `.svg` is read through its
declaration first and then through a meta. Labels are the 228 of the WHATWG Encoding
Standard's `encodings.json`, read from that file and mapped to the Python codec of each
encoding's decoder (GBK as gb18030, Big5 as big5hkscs, Shift_JIS as cp932, EUC-KR as cp949,
ISO-8859-1 and ASCII as cp1252, ISO-2022-JP as iso2022_jp_ext for half-width katakana).
Undefined bytes become U+FFFD. The text is the `decoded-charset` view, and every other text
view is read from it, as from `decoded-utf16`. windows-1255, windows-1256, and ISO-8859-8 drop
U+200C to U+200F, as transcoded mail parts already do.

One extension past the issue's "bytes are not UTF-8": a page declared ISO-2022-JP that holds an
escape is transcoded although its seven-bit bytes are valid UTF-8, because Chromium shows
the Japanese text and its UTF-8 reading is escape sequences.

## 4. Agreement with Chromium

`probe_html_charset_browser.py` compares `declared_codec` with `document.characterSet`:

| Set | Documents | ok | wide | DIFF |
| --- | --- | --- | --- | --- |
| `directed` | 29 | 28 | 1 | 0 |
| `fuzz --seed 1` | 3,000 | 2,617 | 383 | 0 |
| `fuzz --seed 2` | 3,000 | 2,640 | 360 | 0 |
| `fuzz --seed 3` | 3,000 | 2,653 | 347 | 0 |
| `fuzz --seed 4` | 3,000 | 2,655 | 345 | 0 |
| `fuzz --seed 5` | 3,000 | 2,639 | 361 | 0 |

`wide` is a file named as XML that the scanner reads through a meta, which Chromium does not
read in those files. In each fuzz set about 700 documents were decoded through a declared
legacy encoding, about 950 fell to the detector, and about 1,250 were UTF-8. The first three
sets were rerun after the attribute reader was rewritten for speed, with the same results.

Review then found a shape none of them held: `<!-->` inside an escaped script closes the
escape, because its dashes end in `-->`, and the reader had taken it for one more `<!--`. On
`<script><!-- a <!--><script></script><meta charset=koi8-r></script>` the reader then
escaped twice at the inner `<script>` and read the meta as script text, while Chromium
honours it. The reader now looks for `-->` from inside such a `<!--`. That document is the
27th directed case and the shape is in the fuzz vocabulary of seeds 4 and 5; seeds 1 to 3
were compared again with the fix and still agree.

CodeQL's `py/bad-tag-filter` flagged the script-escape pattern on the pull request for
matching `-->` and not `--!>`. Chromium keeps a script escape open across `--!>`, at either
depth, and the reader does too; the two shapes are directed cases 28 and 29, so a reader that
took `--!>` as the end of an escape would fail the probe.

## 5. Benign files

Each file was scanned on `f54c57e` and with the change, under the default policy and
`agent-ingest`, comparing verdicts, the incomplete reason, and findings as (rule, severity,
view). The scanner was the only thing that differed: one rules copy, no vendor rules.

| Set | Files | Read through a declared charset | Changed |
| --- | --- | --- | --- |
| chardet 5.2.0's test corpus (PyPI sdist) and the copy gsutil bundles, by content | 431 | 272, all RSS and Atom feeds, by their XML declaration, in 15 codecs | 0 |
| The same corpus's 21 legacy HTML pages with their meta put back, and its 55 legacy text files in a page that declares their charset | 76 | 74 by a meta | 0 |
| Every other installed text file that is not UTF-8 or holds an ESC (vim language files and keymaps, terminfo entries, fonts, interpreter caches) | 278 | 0 | 0 |
| A random sample of ordinary installed text (`.html`, `.xml`, `.svg`, `.md`, `.py`, `.json`, and others; 393 markup files) | 2,863 | 0 | 0 |

The 272 feeds are windows-1251 (33), ISO-8859-5 (30), EUC-KR (29), Shift_JIS (28), EUC-JP
(25), Big5 (24), GB2312 (18), windows-1255 (18), KOI8-R (18), IBM866 (17), ISO-8859-2 (11),
ISO-8859-7 (9), windows-1250 (6), TIS-620 (5), and windows-1254 (1). Another 17 feeds declare
`IBM855` and 16 declare `MacCyrillic`. Neither is a WHATWG label, Chromium 153 passes over
both (and `cp855`), and they stay UTF-8. Python's own codec aliases would have decoded them.
chardet's HTML pages ship without their meta, which is the no-declaration case and stays
UTF-8; the 76 rebuilt pages exercise the meta path on the same real text. These are collision
counts on a detector's test set, not a false-positive rate.

The same harness, run on the 23 gap-probe documents, reported the 16 fixed cases and left the
7 benign and boundary ones unchanged, so a change would have shown. Turning off the
direction-mark drop changed none of the 24 corpus documents in windows-1255, windows-1256, or
ISO-8859-8. It did change the probe's benign Hebrew page, which gains `agent_invisible_unicode`
on `decoded-charset`; the Persian page with zero-width non-joiners is clean either way.

## 6. Time

The reader runs only for text that is not UTF-8 (or holds an ESC), and once per unit: the
scanner hands its reading to `text_views`.

| 4 MiB input | Prescan | Scan, `f54c57e` | Scan, change |
| --- | --- | --- | --- |
| Head of `<link>` tags, a meta at the end | 0.67 to 0.93 s | 2.10 s | 3.23 s |
| Head of `<meta a=b>` tags | 0.80 s | 1.85 s | 2.88 s |
| One meta with two million attributes | 0.81 s | 1.65 s | 2.41 s |
| A script of `<!--<script></script>` escapes | 0.34 s | 2.98 s | 3.54 s |
| `<` repeated in the head | 0.04 s (1.64 s before the reader jumped to a `<` that opens markup) | 2.94 s | 3.39 s |
| Ordinary Russian text, declared windows-1251 | 0.001 s | 2.06 s | 3.02 s |
| The same text in UTF-8 | not run | 1.88 s | 1.95 s |

A declared page now costs what UTF-16 does: its raw bytes and its transcoded text are both
scanned, and the transcoded Cyrillic is 7.5 MiB. `check_worst_case_timing.py` passed all 81
inputs on both revisions, 166.5 s of scans on `f54c57e` and 165.7 s with the change, with the
same verdict, reason, and views for every input; the slowest was `pdf-page-fonts.pdf`, 6.03 s
and 6.40 s. No input was added to that step: its five-minute limit is already thin
([timing record](2026-11-14-macos-timing-flake.md)), and the prescan inputs above stay under
4 s.

## 7. What was run

| Check | Result |
| --- | --- |
| `probe_html_charset_browser.py directed`, then `fuzz --seed 1` to `5` (3,000 each), with `html_charset_oracle.js` | 0 DIFF (section 4) |
| `probe_detection_gaps.py --verify` | Pass. 566 cases (543 on `f54c57e`): 564 hold, 2 open (B3, B5, unchanged); the 23 charset cases hold |
| `probe_rule_coverage.py --verify` | Pass |
| `record_pages_demo.py --baseline web-demo/recordings.json` | Outcomes match the reviewed recordings, 82 scenarios under three policies |
| `check_worst_case_timing.py`, on both revisions | PASS, 81 inputs |
| `pytest tests/test_scanner.py tests/test_filetype.py -k "utf16 or legacy or stray or mail or charset or joiner or html or text_views or json"` | 67 passed |
| Ruff check and format, `mypy --strict src scripts`, `check_text_controls.py`, `check_doc_links.py` | Pass |

## Not established

- Firefox and Safari were not run. The HTML standard's "change the encoding" step lets a
  browser reload a page whose later meta names another charset (assessment, from the
  standard's text); Chromium passed over such a meta here, and the scanner follows Chromium.
- pandoc, BeautifulSoup, lxml, and `xml.etree` were not run on these documents. The backlog's
  earlier note that they decode a declared charset was not re-checked.
- The page served over HTTP with a `Content-Type` charset was not tested: a saved file has
  none, and a header would override the meta in a browser.
- The chardet corpus is a test set for an encoding detector, not a sample of what agents
  ingest; its counts are collision counts, not a false-positive rate.
