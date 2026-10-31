# PDF /OpenAction: a page open is a note (#106)

Base: `main` `1c3de50`. YARA-X `1.22.1`, Python 3.12, Linux container. Shipped local rules copied into disposable rules roots. Synthetic inert PDFs and two local consumer checkouts. Nothing was executed, rendered, or downloaded.

## Root cause

`pdf_token_findings` emitted `Severity.block` for any `/OpenAction` name and never read its value. A PDF that opens on page 3 (`/OpenAction [3 0 R /Fit]`) blocked like one that runs JavaScript on open. Reproduced on `1c3de50`: `<< /Type /Catalog /OpenAction [3 0 R /Fit] >>` blocked as `heuristic_pdf_OpenAction` under every policy.

## What changed

`pdf_token_findings` now asks `_open_action_is_goto` before it reports `/OpenAction`. That check reads the value with the existing top-level tokenizer, which skips strings, comments, and stream bodies and decodes `#xx` escapes. The tokenizer gained an opt-in marker for skipped strings, so a string where a name belongs is visible to the parser. The encryption check calls the tokenizer without the marker and is unchanged.

A file gets the note `heuristic_pdf_OpenAction_goto` only when every `/OpenAction` the tokenizer reaches opens a page, and the tokenizer reaches every occurrence the name scanner finds. A page open is one of these:

- a direct destination array of numbers, `R`, `null`, and a fit type (`/XYZ`, `/Fit`, `/FitH`, `/FitV`, `/FitR`, `/FitB`, `/FitBH`, `/FitBV`);
- a dictionary whose `/S` is the name `/GoTo` and that has no `/Next` and no duplicate key;
- a reference `N G R` whose every `N G obj` definition in the same data is one of those two.

Everything else keeps `heuristic_pdf_OpenAction` at block. `/JavaScript`, `/JS`, `/Launch`, `/AA`, `/EmbeddedFile`, and `/RichMedia` are unchanged. The `pdf-flate` view goes through the same function.

## Direct scans

`scan_bytes`, as default / agent-ingest / agent-document:

| Value of `/OpenAction` | Verdicts | Finding |
| --- | --- | --- |
| `[3 0 R /Fit]`, `[0 /XYZ 0 792 null]` | advisory / block / advisory | goto note |
| `<< /S /GoTo /D [3 0 R /Fit] >>`, `/D (chapter1)`, `/S /G#6FTo` | advisory / block / advisory | goto note |
| `5 0 R`, object 5 a destination array or a GoTo dictionary | advisory / block / advisory | goto note |
| A catalog in a FlateDecode object stream with a destination array | advisory / block / advisory | goto note in `pdf-flate` |
| `/S /Launch`, `/S /JavaScript`, `/S /Java#53cript` | block | `heuristic_pdf_OpenAction` plus the action's own name |
| `/S /URI`, `/S /GoToR`, `/S /SubmitForm` | block | `heuristic_pdf_OpenAction` |
| No `/S`; `/S (/GoTo)` as a string; `/S /GoTo /S /URI` | block | `heuristic_pdf_OpenAction` |
| GoTo with `/Next << /S /URI … >>` | block | `heuristic_pdf_OpenAction` |
| `5 0 R` with no object 5; object 5 a URI action; object 5 defined twice, once as a URI action; object 5 itself a reference | block | `heuristic_pdf_OpenAction` |
| A value that is a name (`/JavaScript`), or an array holding a dictionary | block | `heuristic_pdf_OpenAction` |
| A `(/OpenAction [3 0 R /Fit])` string decoy beside a real URI action; the decoy alone | block | `heuristic_pdf_OpenAction` |
| A page open, then an incremental update that sets a URI action | block | `heuristic_pdf_OpenAction` |
| A page open plus `/AA` | block | `heuristic_pdf_AA`, goto note |
| Truncated before the closing bracket | block | `heuristic_pdf_OpenAction` |

The existing heuristic tests' inputs keep their ids, offsets, and severities, including the `#xx`-escaped names and the token-boundary cases from the [name-boundary verification](pdf-name-boundaries.md).

## Checks

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src
uv run python docs/verification/lint_rules.py
uv run python docs/verification/check_rule_pairs.py      # 102 rules
uv run python docs/verification/check_added_rules.py     # 64 cases
uv run python docs/verification/measure_precision.py --fail-over
uv run python docs/verification/check_text_controls.py
uv run python docs/verification/check_scan_only.py
uv run python docs/verification/check_intake.py
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run yara-gate selftest
```

All passed. The probe's `navigation.pdf` moved from block to advisory. The probe gained `goto_open.pdf` (advisory) and `uri_open.pdf` (block). The pairs gained a URI-versus-destination pair for `heuristic_pdf_OpenAction` and a GoTo-versus-`/Next` pair for the note.

## Consumer trees

All 1,469 files of 1 MB or less in CyClaw `a5b5212` and cg-agent-harness `ff5df3a`, 12 of them PDFs. One file changed outcome, and none became stricter.

- `CyClaw Glossary.pdf` went from block to the goto note: held by `agent-ingest`, released by `agent-document`.
- `CyClaw_SandboxWss_v1.8.0_Validation_Report_Combined.pdf` still blocks. Its catalog sits in a compressed object stream and says `/OpenAction 1 0 R`, and object 1 is in that stream too, so the reference does not resolve.

## Limits

- A reference into an object stream does not resolve. LaTeX and other PDF 1.5 writers often store the catalog and its open action that way, so those files still block. Resolving them means parsing each object stream's offset table; that is a separate change.
- A GoTo action is trusted to stay inside the document. The destination is not checked against the page tree.
