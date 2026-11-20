# PDF page content as one stream, and JSON with comments — November 13, 2026

Base: `main` at `0abcbe1`. Changes: `0bd55d5` (JSON), `9a3b6f4` (PDF), `64724cb` (probe cases,
timing inputs, docs, and this record), `5f7df1d` (a timing fix the sweep found), and the commit
that fills in this record's figures. Linux 6.18 x86_64 container,
Python 3.12.3, YARA-X 1.23.0, 87 bundled local rules, zero skips, no vendor download. Every
scan used a disposable copy of `rules/local`. Nothing was executed, unpacked to disk, or
fetched by the scanner.

The three candidates came from the [detection backlog](../research/detection-backlog.md)'s
further-candidates table, where each was recorded as verified on `2cff88f`. Each was scanned
again on `0abcbe1` before the change, beside a control the gate already held.

## 1. JSON after a byte order mark or comments

**Gap (verified on `0abcbe1`).** `_json_shaped` tested the first character. A payload that
opened with a UTF-8 byte order mark, or a `//` or `/* */` comment, got no `json-unescaped`
view, so an instruction written with one `I` escape was clean under every policy. The
MCP walk required the file to open with `{` or `[` and to be strict JSON, so a poisoned tool
list with a mark, a comment, or a trailing comma was clean too; the same list without them is
held as `heuristic_mcp_hidden_instruction`.

**Readers.** Python's `json.loads` reads the mark from bytes. VS Code reads `mcp.json`,
`settings.json`, and `devcontainer.json` through jsonc-parser, which takes comments and
trailing commas. jsonc-parser 3.3.1 under Node 22.23.4 parses every attack fixture with no
error and returns the tool description or the escaped sentence; `JSON.parse` rejects the
comment and trailing-comma files.

**Change.** The view opens after a mark, white space, and comments within the first 8,192
characters, skipped one comment at a time with `str.find`, as `_opens_as_html` skips HTML
comments. The MCP walk strips a mark and, only when strict JSON fails, reads the file with
comments and trailing commas removed outside strings (`_jsonc`): one forward pass, each
comment skipped with `bytes.find`, a file of at most 1 MiB, and none at all when a comment
never closes. A file strict JSON reads is read exactly as before.

**Agreement.** 3,000 generated files mixing `//` and `/* */` comments (between tokens and
inside strings), trailing commas, nesting, and escaped slashes: `json.loads` after `_jsonc`
and jsonc-parser 3.3.1 give the same value, or both reject, on 3,000 of 3,000.

## 2. A page's `/Contents` array read as one stream

**Gap (verified on `0abcbe1`).** `_blocks` read each content stream on its own, so a
sentence split between two streams of one page's `/Contents` array was clean under every
policy: split inside one text object, mid-word, one word per stream, compressed, or with the
streams in reverse file order. ISO 32000-1 7.8.2 defines the array as one stream, its parts
joined at token boundaries.

**Change.** Before the page is read, the streams of each array are joined in array order
with a line feed, keyed by the first stream, and the other members are skipped when the loop
meets them. Arrays come from `_contents_predecessors` (a direct array in a raw page
dictionary) and from `_other_contents`: a `/Contents N 0 R` whose object is an array with
one definition, and a direct array in a page dictionary stored in an object stream (read from
streams whose dictionary is `/Type /ObjStm` only). An empty member, written plainly or
deflated, is passed over. A member reused at another place, one not decoded, one whose
dictionary is not page content, or one the page map gives other fonts ends the run, and at
most 1,024 streams are joined; the streams on either side are read as before.

## 3. A page content stream that fails the text sniff

**Gap (verified on `0abcbe1`).** `pdf_streams` kept a stream's bytes for the text reader only
when they sniffed as text. A 256-byte inline image (`BI ... ID ... EI`) or a binary string
literal before the text made the page's stream unread: the phrase over two string operators
after it was clean, with no `heuristic_pdf_text_unmapped`.

**Change.** A stream that fails the sniff is still given to the text reader when it holds
`BT`, a `/Contents` entry in the file's own bytes names it (directly or in a direct array),
and its dictionary has none of `/Subtype`, `/Type`, `/PatternType`, `/BBox`, `/Matrix`, or
`/Length1` to `/Length3` (an image, a form or other drawn object, or a font program). The
tokenizer already skips inline image data. `pdf-flate` is unchanged: it still holds only
streams that sniff as text.

## Fixtures and readers

The probe's `streams` and `jsonc` groups (24 cases) are each attack beside a control and a
benign twin, with the boundaries that stay as they were.

| Case | `0abcbe1` | This change | poppler 24.02.0 / pypdf 6.17.0 / pdfminer.six 20260107 |
| --- | --- | --- | --- |
| One stream, phrase over two strings (control) | held | held | shown / shown / shown |
| Array, split inside one text object | clean | held | shown / shown / shown |
| Array, compressed | clean | held | shown / shown / shown |
| Array, one word per stream | clean | held | shown / shown / shown |
| Array, streams in reverse file order | clean | held | shown / shown / shown |
| Array kept in an object of its own | clean | held | shown / shown / shown |
| Array with an empty stream between | clean | held | shown / shown / shown |
| Array, ordinary text (benign) | clean | clean | not the phrase |
| Phrase split between two pages (boundary) | clean | clean | not the phrase |
| Inline image first | clean | held | shown / shown / shown |
| Binary strings first | clean | held | shown / shown / shown |
| Inline image, ordinary text (benign) | clean | clean | not the phrase |
| Image XObject holding content operators (boundary) | clean | clean | not the phrase |
| JSON with a mark, a `//` comment, or a `/* */` comment, escaped phrase | clean | held | jsonc-parser: parsed |
| JSON comment first, ordinary text (benign) | clean | clean | |
| INI section after a comment (boundary) | clean | clean | |
| MCP tool list with a mark, comments, or a trailing comma | clean | held | jsonc-parser: parsed |
| MCP tool list with comments, ordinary text (benign) | clean | clean | |
| MCP tool list after an unclosed comment (boundary) | clean | clean | jsonc-parser: error |

"Held" is advisory under `default` and `agent-document`, block under `agent-ingest`, for the
phrase; the MCP heuristic is advisory, so it is held under both agent policies. The 30 PDF
fixtures written for these shapes in the earlier probe (direct and indirect arrays, a page in
an object stream, empty members, inline images, binary strings, each with a benign twin) give
the same result: every attack held, every twin clean.

## Benign files, `0abcbe1` against this change

`main` at `0abcbe1` and this change, each from its own source tree with the same rules,
scanned every file under `default` and `agent-document`.

| Corpus | Files | Files that changed |
| --- | --- | --- |
| PDFs on the machine: generator output (LibreOffice, Chromium, reportlab, pypdf, PDFium, pdftocairo, MuPDF, Pillow), test-suite files, earlier probe fixtures, and the tripwire's inputs, unique by content | 8,622 | 29, every one an attack fixture that went from clean to held: 21 written for these shapes in the earlier probe and 8 of this change's own. 0 benign files gained a finding, lost one, or became incomplete |
| Every file on the machine that the new JSON test opens and the old did not, or a `.json` file with a mark or that needs comments read | 26 of 238,674 examined (17 unique): two C headers that open with a comment and a brace, and tsconfig files | 0 |
| Every strict `.json` file under 1 MiB on the machine, as written | 2,936 | 0 |
| The same 2,936 with a byte order mark added, and again with a `//` comment first and a trailing comma | 5,872 | 0: each gives the rules and verdicts its original gave on `main`. On `main` the same variants lost a finding on 2 of the 23 originals that have one (`heuristic_mcp_shell`, `agent_config_approval_bypass`) |

Of the 8,622, 82 hold a direct `/Contents`
array in their own bytes and 601 an object stream, so real arrays were few: most of the array
evidence is the fixtures above and the backlog's earlier prototype, which changed 0 of 340
generator PDFs while joining 126 chains in 19 stamped files.

The first head sweep found one regression, in time, not in findings: the tripwire's
`pdf-contents-arrays.pdf`, 4 MiB of `/Contents[`, took 10.2 s against 3.0 s, because the new
array pattern ran up to 64 KB from every match looking for `]`. An array of references holds
only digits, `R`, and white space, so the pattern now takes only those (`5f7df1d`), and the
input is back to 3.0 s. `pdf-contents-refs.pdf` drives the same pattern where it collects the
references for a stream that fails the sniff: 7.4 s for that pattern alone before the fix,
0.02 s after.

## Timing

Four 4 MiB inputs join the tripwire, so it scans 76: `jsonc-comment-openers.json` (a file
of unclosed `/*`), `pdf-contents-array.pdf` (one page whose `/Contents` array names 400
streams), `pdf-binary-content.pdf` (a page content stream of every byte value, named by
a page), and `pdf-contents-refs.pdf` (below). All 76 passed on Linux x86_64, Python 3.12.3, with the scan ceiling at 10 s: the new inputs took 0.44 s, 3.4 s, 0.44 s, and 2.8 s, and the slowest overall 5.0 s (`pdf-page-fonts.pdf`). The comment reader at its 1 MiB cap took at most 0.28 s (all commas);
the 400-stream page took 3.7 s against 3.6 s on `0abcbe1`, where it was read stream by stream.

## What was run

| Check | Result |
| --- | --- |
| `probe_detection_gaps.py --verify` | 500 ok; open B3, B5, B6, B8 as before; the 24 new cases ok, and each attack among them FAIL on `0abcbe1` |
| `probe_pdf_reader_agreement.py fixtures` / `fuzz --seed 1 --count 15000` | 141 files, MISS 0 / 532 files, MISS 0 (mupdf, pdfium, pdfminer.six, poppler, pypdf) |
| `probe_pdf_font_reader_agreement.py fixtures` / `fuzz --seed 1 --count 15000` | 107 files, MISS 0 / 186 files, MISS 0 |
| `probe_rule_coverage.py --verify`, `measure_precision.py --fail-over`, `check_rule_pairs.py`, `check_added_rules.py` | Pass |
| `check_worst_case_timing.py` | 76 inputs, all under the ceiling |
| `record_pages_demo.py --baseline web-demo/recordings.json` | Outcomes match: 82 scenarios |
| `pytest` on `test_pdftext`, `test_scanner`, `test_pdf_text_folding`, `test_pdfannotations`, `test_pdfxref`, `test_cli_json`, `test_heuristics`, `test_demo`, `test_office_parts_by_content` | 926 passed; the full suite is left to hosted CI |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `check_text_controls.py`, `check_doc_links.py` | Clean |

## Not established

- Real pages written with `/Contents` arrays were not in the benign corpus in number; the
  arrays measured are those of the generator-written files above.
- A content stream that fails the sniff and is named only from a page dictionary inside an
  object stream is still not read.
- No editor other than jsonc-parser's VS Code use was run for JSON with comments.
- Synthetic fixtures. This is evidence for the shapes listed, not a detection rate.
