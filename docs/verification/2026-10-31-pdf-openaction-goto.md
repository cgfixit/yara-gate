# PDF /OpenAction: a page open is a note (#106)

Base: `main` `1c3de50`. YARA-X `1.22.1`, Python 3.12, Linux container. Shipped local rules copied into disposable rules roots. Synthetic inert PDFs and two local consumer checkouts. Nothing was executed, rendered, or downloaded.

## Root cause

`pdf_token_findings` emitted `Severity.block` for any `/OpenAction` name and never read its value. A PDF that opens on page 3 (`/OpenAction [3 0 R /Fit]`) blocked like one that runs JavaScript on open. Reproduced on `1c3de50`: `<< /Type /Catalog /OpenAction [3 0 R /Fit] >>` blocked as `heuristic_pdf_OpenAction` under every policy.

## What changed

`pdf_token_findings` now asks `_open_action_is_goto` before it reports `/OpenAction`. For every occurrence the name scanner finds, that check reads the value from the occurrence's own position with the existing tokenizer, which skips strings and comments and decodes `#xx` escapes. Reading per occurrence matters: the `pdf-flate` view joins every inflated stream, and an unbalanced parenthesis in an earlier content stream swallowed the catalog when the whole view was tokenized at once. The tokenizer gained an opt-in marker for skipped strings, so a string where a name belongs is visible to the parser. The encryption check calls the tokenizer without the marker and is unchanged.

References resolve through `PdfObjects` (`content.py`). It returns every definition of an object number and generation in the file: each raw `N G obj`, and at generation 0 each member of a FlateDecode object stream, read from the stream's `/N` pairs and `/First` offset (ISO 32000-1 7.5.7). Object streams are indexed only when a reference is looked up, under the scan's expansion budget and deadline. A stream with `/DecodeParms`, another filter, a header that does not parse, or offsets outside its data is skipped.

A file gets the note `heuristic_pdf_OpenAction_goto` only when every occurrence opens a page. A page open is one of these:

- a direct destination array of numbers, `R`, `null`, and a fit type (`/XYZ`, `/Fit`, `/FitH`, `/FitV`, `/FitR`, `/FitB`, `/FitBH`, `/FitBV`);
- a dictionary whose `/S` is the name `/GoTo` and that has no `/Next` and no duplicate key;
- a reference `N G R` with at least one definition, every one of which, raw or in an object stream, is one of those two.

Everything else keeps `heuristic_pdf_OpenAction` at block. `/JavaScript`, `/JS`, `/Launch`, `/AA`, `/EmbeddedFile`, and `/RichMedia` are unchanged. The `pdf-flate` view goes through the same function.

## Flate-view bypass found while testing, and fixed

On `main` `1c3de50`, `pdf_views` looked for `/FlateDecode` only after the last `<<` before the `stream` keyword. That is the innermost dictionary, so a stream dictionary with a nested `/DecodeParms << /Columns 1 >>` after `/Filter` was never inflated. An object stream holding `<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>` with that dictionary scanned **clean** under every policy; without `/DecodeParms` it blocked. A `#xx`-encoded `/Fl#61teDecode`, which a reader decodes, was skipped the same way, and PNG predictors were listed as not covered.

`_decoded_stream` (`content.py`) now serves the view and the object-stream index. It takes the stream's dictionary as the text after the last `N G obj` before the keyword, reads it with the PDF tokenizer through `pdf_stream_parameters` (`heuristics.py`), inflates when the first filter is FlateDecode, and reverses a PNG predictor (10 to 15) or 8-bit TIFF predictor 2 under the scan's deadline.

| Stream dictionary of an object stream holding the JavaScript open action | main | branch |
| --- | --- | --- |
| `/Filter /FlateDecode` | block | block |
| `/Filter /FlateDecode /DecodeParms << /Columns 1 >>` | **clean** | block |
| `/DecodeParms << /Predictor 1 >> /Filter /FlateDecode` | **clean** | block |
| `/Filter /Fl#61teDecode` | **clean** | block |
| `/Filter [/FlateDecode]` | block | block |
| `/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 16 >>`, PNG Up rows | **clean** | block |

A content stream with an injection phrase behind a PNG Sub predictor (11) or TIFF predictor 2 now gives the phrase note in `pdf-flate`.

Image streams (`/Subtype /Image`, unless `/Type` is `/ObjStm`) are inflated as on `main` but their predictor is not reversed. Reversing a Paeth-filtered 1000 by 1200 RGB image in Python took a 3.6 MB PDF from 0.24 s on `main` to 1.33 s; with the exemption it takes 0.33 s, and an object stream that also claims `/Subtype /Image` is still decoded. Across the 16 consumer PDFs, total scan time was 4.57 s on `main` and 4.97 s on the branch, and the only verdict changes are the two files below. A predictor-encoded object stream with a catalog and `5 0 R` gives the goto note for a page destination and blocks for a URI action.

## Direct scans

`scan_bytes`, as default / agent-ingest / agent-document:

| Value of `/OpenAction` | Verdicts | Finding |
| --- | --- | --- |
| `[3 0 R /Fit]`, `[0 /XYZ 0 792 null]` | advisory / block / advisory | goto note |
| `<< /S /GoTo /D [3 0 R /Fit] >>`, `/D (chapter1)`, `/S /G#6FTo` | advisory / block / advisory | goto note |
| `5 0 R`, object 5 a destination array or a GoTo dictionary | advisory / block / advisory | goto note |
| A catalog in a FlateDecode object stream with a destination array | advisory / block / advisory | goto note in `pdf-flate` |
| Catalog and `5 0 R` both in an object stream, object 5 a destination or GoTo; a raw catalog pointing into a stream | advisory / block / advisory | goto note |
| Object 5 in a stream is a URI action; or a page open in the stream but redefined raw as a URI action; or a Launch copy in a second stream | block | `heuristic_pdf_OpenAction` |
| Object stream with a broken header, a generation-1 reference, a missing object, or a reference to a reference | block | `heuristic_pdf_OpenAction` |
| Object stream declaring `/Predictor 12` over bytes that are not PNG rows | clean: no row decodes, as in a viewer | none |
| `/S /Launch`, `/S /JavaScript`, `/S /Java#53cript` | block | `heuristic_pdf_OpenAction` plus the action's own name |
| `/S /URI`, `/S /GoToR`, `/S /SubmitForm` | block | `heuristic_pdf_OpenAction` |
| No `/S`; `/S (/GoTo)` as a string; `/S /GoTo /S /URI` | block | `heuristic_pdf_OpenAction` |
| GoTo with `/Next << /S /URI … >>` | block | `heuristic_pdf_OpenAction` |
| `5 0 R` with no object 5; object 5 a URI action; object 5 defined twice, once as a URI action; object 5 itself a reference | block | `heuristic_pdf_OpenAction` |
| A value that is a name (`/JavaScript`), or an array holding a dictionary | block | `heuristic_pdf_OpenAction` |
| A `(/OpenAction [3 0 R /Fit])` string decoy beside a real URI action | block | `heuristic_pdf_OpenAction` |
| The same decoy with no real open action | advisory / block / advisory | goto note: the only value present opens a page |
| A page open, then an incremental update that sets a URI action | block | `heuristic_pdf_OpenAction` |
| A page open plus `/AA` | block | `heuristic_pdf_AA`, goto note |
| Truncated before the closing bracket | block | `heuristic_pdf_OpenAction` |

The existing heuristic tests' inputs keep their ids, offsets, and severities, including the `#xx`-escaped names and the token-boundary cases from the [name-boundary verification](pdf-name-boundaries.md).

## Checks

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src
uv run python docs/verification/lint_rules.py
uv run python docs/verification/check_rule_pairs.py      # 102 rules
uv run python docs/verification/check_added_rules.py     # 68 cases
uv run python docs/verification/measure_precision.py --fail-over
uv run python docs/verification/check_text_controls.py
uv run python docs/verification/check_scan_only.py
uv run python docs/verification/check_intake.py
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run yara-gate selftest
```

All passed. Each new test in `tests/test_heuristics.py` was also run by calling the test function directly; that run caught a `%`-format bug in the object-stream helper before it reached CI. The probe's `navigation.pdf` moved from block to advisory. The probe gained `goto_open.pdf` (advisory) and `uri_open.pdf` (block). The pairs gained a URI-versus-destination pair for `heuristic_pdf_OpenAction` and a GoTo-versus-`/Next` pair for the note.

## Consumer trees

All 1,469 files of 1 MB or less in CyClaw `a5b5212` and cg-agent-harness `ff5df3a`, 12 of them PDFs. Two files changed findings, and none became stricter under any policy.

- `CyClaw Glossary.pdf` went from block to the goto note: held by `agent-ingest`, released by `agent-document`.
- `CyClaw_SandboxWss_v1.8.0_Validation_Report_Combined.pdf`, a pdfTeX file, keeps its catalog in an object stream with `/OpenAction 1 0 R`; object 1 is `<< /S /GoTo /D [3 0 R /Fit] >>` in the same stream. Its open action is now the goto note. Before #127 merged, the file also blocked through `agent_invisible_unicode` matching chance bytes; with #127 on `main` (`693bca1`) it scans advisory, with the goto note as its only finding.

## Limits

- An object stream with a filter other than FlateDecode is not indexed, so a reference into it blocks.
- A stream whose `/DecodeParms` names a predictor other than PNG (10 to 15) or 8-bit TIFF (2), or whose PNG rows use an unknown filter type, is left out of the view. A viewer applying that predictor gets the same bytes the scanner would reject.
- A GoTo action is trusted to stay inside the document. The destination is not checked against the page tree.

## Codex review of `df17a8f`, and the fixes

Codex reported five findings. Each was reproduced on `df17a8f` through the real functions before it was changed:

| Finding | On `df17a8f` | After |
| --- | --- | --- |
| P1: `/Type /Obj#53tm`, an escaped name, hid an object stream from the index, so a compressed URI-action redefinition of a raw page open was downgraded | goto note | `heuristic_pdf_OpenAction` block |
| P1: `/Predictor 12 /Columns 16` placed directly in the stream dictionary, not in `/DecodeParms`, was applied and suppressed a compressed JavaScript open action | no findings | JavaScript and OpenAction block |
| P1: `/Foo (2 0 obj)` inside a stream dictionary was taken as an object header, so the filter was lost | no findings | JavaScript and OpenAction block |
| P1: the raw-object index copied 4 KiB for every object header | 17.3 MB for an 81 KB input with 4,096 headers | about 0 MB |
| P2: the predictor loops checked the deadline every 1,024 rows | a 4 MiB Paeth row ran 1.12 s past a 20 ms budget | stops at the deadline (0.03 s) |

**Root cause and fix.** Stream dictionaries were read by byte patterns. Now `pdf_stream_info` (`heuristics.py`) takes the text after an `N G obj` header in the 4 KiB before `stream`. It accepts that text only if it tokenizes into exactly one balanced dictionary, with strings and comments skipped, and the last header that passes wins. The fields are read from that parsed dictionary: `/Filter`, `/Type`, `/Subtype`, `/N`, and `/First` as decoded names. Predictor parameters come only from the stream's own `/DecodeParms`, or for a filter array, its first entry. An indirect `/DecodeParms` leaves the predictor unknown, and the stream is read as inflated. When no dictionary parses, the stream is inflated without a predictor if `/FlateDecode` appears before it, which is the earlier reading, so a malformed dictionary does not hide a stream.

**Memory and work bounds:**
- `PdfRawObjects` searches per object number and keeps offsets only.
- Object-stream members are kept as offsets into decoded streams that the budget already counts.
- More than 64 definitions of one object, or more than 64 `/OpenAction` names, is not a page open.
- The predictor loops check the deadline every 64 KiB, inside rows as well as between them.

**Regression tests.** `tests/test_heuristics.py` covers each finding: the three dictionary forms, the escaped object-stream name, the definition cap, and the in-row deadline. All 86 cases in that file were run by direct call.

**Unchanged outcomes.** The OpenAction matrix (31 cases), the object-stream matrix (11), and the flate-bypass matrix (11) give the same results as before. The 1,469-file consumer sweep gives the same outcome for every file. The 16 consumer PDFs take 5.52 s in total, against 4.57 s on `main`.
