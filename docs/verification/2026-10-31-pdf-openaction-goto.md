# PDF /OpenAction: a page open is a note (#106), on #129's stream reader

Base: `main` `67446d0`, after #129 merged. YARA-X `1.22.1`, Python 3.12, Linux container, disposable rules roots. This replaces #128, which carried its own copy of the stream reader that #129 now provides. Nothing was executed, rendered, or downloaded.

## Root cause

`pdf_token_findings` emitted `Severity.block` for any `/OpenAction` name and never read its value. A PDF that opens on page 3 (`/OpenAction [3 0 R /Fit]`) blocked like one that runs JavaScript on open, under every policy.

## What changed

**`heuristics.py`:**
- `/OpenAction` is the note `heuristic_pdf_OpenAction_goto` only when every occurrence the name scanner finds is a page open. A page open is a destination array, a `/GoTo` dictionary with no `/Next` and no duplicate key, or a reference whose every definition is one of those.
- Each occurrence is read from its own position with the PDF tokenizer, which skips strings and comments and decodes `#xx` escapes.
- `PdfRawObjects` searches per object and keeps offsets.
- More than 64 definitions of one object, or more than 64 `/OpenAction` names, are not a page open.
- Every other action type, a missing or string `/S`, a chained `/Next`, and an unresolved reference still block as `heuristic_pdf_OpenAction`.

**`content.py`, on #129's parser:**
- **`PdfObjects`** resolves a reference through raw definitions and through FlateDecode object-stream members (ISO 32000-1 7.5.7). It is indexed on first use, with members kept as offsets into budgeted buffers, and `/Type /ObjStm` is read as a decoded name. pdfTeX-style PDFs, whose catalog and `/GoTo` action sit in an object stream, get the note. A raw redefinition counts against a stream copy.
- **`_pdf_stream_bytes`** is now shared by the flate view and the object-stream index. It never drops a stream that inflates. When predictor parameters are out of range, the predictor is one a reader rejects, a PNG row type is unknown, or the 4 KB prefix is not text, the inflated bytes are kept for `sniff` and the text rules.
- **`_pdf_stream_dict`** tries the object headers in its window from the nearest back, and accepts the first one followed by exactly one dictionary. A `(2 0 obj)` string inside a dictionary no longer costs the stream its real dictionary and predictor.
- **`_unpredict`** clamps the row to the data length, so `/Columns` near the file limit times 32 colors at 16 bits cannot allocate gigabytes. `_png_rows` and `_tiff_rows` check the deadline every 64 KiB inside rows.

`scanner.py` passes `PdfObjects` to the raw and `pdf-flate` PDF name checks.

## Bypasses on `main` `67446d0` closed here

A compressed object stream holding `<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>`:

| Stream dictionary | `67446d0` | this branch |
| --- | --- | --- |
| `/DecodeParms << /Predictor 12 /Columns 16 >>`, PNG Up rows, plus `/Note (2 0 obj)` | clean | block |
| `/Predictor 12 /Columns 99999999999` | clean | block |
| `/Predictor 12 /Colors 33 /Columns 2` | clean | block |
| `/Predictor 5` | clean | block |
| `/Predictor 12 /Columns 16` over data with an unknown PNG row type | clean | block |
| `/DecodeParms << /Predictor 5 >> /Filter /FlateDecode` | clean (blocked on `693bca1`) | block |

Codex's five findings on #128's own reader (`df17a8f`) were reproduced against this branch. All stay fixed:
- an escaped `/Obj#53tm` blocks;
- stray predictor keys and a `(2 0 obj)` string no longer hide content;
- the object-lookup peak is about 0 MB for 4,096 headers;
- a 4 MiB Paeth row stops at a 20 ms deadline.

## Direct scans

- **OpenAction.** The 31-case matrix is unchanged from #128: destination arrays, GoTo forms, `/G#6FTo`, and resolvable references are notes, and every other action type, decoy, redefinition, and malformed value blocks.
- **Object streams.** The 11-case matrix gives a note for a catalog and page open in a stream. A URI action in a stream, a raw URI redefinition of a stream page open, or a Launch copy in a second stream blocks. A broken header, generation 1, a missing object, or a reference to a reference blocks.
- **Real PDFs.** CyClaw's `CyClaw_SandboxWss_v1.8.0_Validation_Report_Combined.pdf`, a pdfTeX file whose `/OpenAction 1 0 R` resolves to `<< /S /GoTo /D [3 0 R /Fit] >>` inside an object stream, scans advisory with the goto note as its only finding.

## Checks

These all passed:
- ruff check and format, `mypy --strict src`;
- `lint_rules.py`, `check_rules_lock.py`, `check_rule_pairs.py` (105), and `check_added_rules.py` (72);
- `measure_precision.py --fail-over`, `check_text_controls.py`, `check_scan_only.py`, and `check_intake.py`;
- `probe_rule_coverage.py --verify --benign-stdlib`, with `navigation.pdf` now advisory and `goto_open.pdf` and `uri_open.pdf` added;
- `yara-gate selftest`.

All 91 cases in `tests/test_heuristics.py`, and #129's three tests in `tests/test_scanner.py`, were run by calling the test functions directly.

## Consumer trees

All 1,469 files of 1 MB or less in CyClaw `a5b5212` and cg-agent-harness `ff5df3a`, compared with `main` `67446d0`:

| Policy | main: clean / advisory / block | branch |
| --- | --- | --- |
| default | 1347 / 116 / 6 | 1347 / 118 / 4 |
| agent-ingest | 1347 / 0 / 122 | 1347 / 0 / 122 |
| agent-document | 1347 / 75 / 47 | 1347 / 77 / 45 |

Two CyClaw PDFs move from block to the goto note, `CyClaw Glossary.pdf` and the validation report above, and nothing becomes stricter. The 16 consumer PDFs take 4.70 s in total, against 4.53 s on `main`.

## Limits

- **Only the first filter is decoded**, and references are followed one level for filters, as in #129.
- **A GoTo action is trusted to stay inside the document.** Its destination is not checked against the page tree.
- **A file with more than 64 definitions of its open-action object blocks.** That is the conservative reading.

## Codex review follow-up (f1cbe8f)

Three findings on the code review, each reproduced on f1cbe8f with an inert file before the fix:

- **P1, unfiltered object stream.** `/OpenAction 5 0 R`, a benign raw object 5, and an unfiltered `/ObjStm` redefining object 5 as a `/URI` action gave only the note, because `_pdf_stream_bytes` returns None without a `/Filter` and the index skipped the stream. The index now reads an unfiltered stream as its own bytes, and any `/ObjStm` it cannot read (a filter it cannot undo, a header that does not parse, offsets outside the data, a dictionary without a usable /N or /First) marks the index opaque, so every reference then carries one extra empty definition and is not a page open. The finding stays a block. Reproduced result: note before, block after.
- **P2, deadline.** 64 distinct `/OpenAction` references on an 8 MiB file took 9.3 s against a 1 s budget, one full-file regex per reference. `PdfRawObjects.prime` now finds every referenced object in one pass over the headers (about 0.4 to 0.7 s on the same input), keeps only offsets for the wanted keys, and calls the budget check every 4096 matches and before each search. An expired budget raises `ContentLimit`, so the scan ends incomplete. Header digit runs are matched up to 32 digits so leading zeros still count.
- **P2, double inflate.** Three 84 MiB object streams in a 257 KB file inflated once for the lookup and again for `pdf_views`, so a file the parent scanned at 252 MiB expanded now stopped at "extracted size exceeds 500MB". `PdfObjects.decoded` keeps what the lookup inflated, by stream offset, and `pdf_views` reuses it without charging again. Reproduced result: incomplete before, advisory after. The unfiltered fallback bytes stay out of that cache, so the `pdf-flate` view is unchanged.

Tests (all fail on f1cbe8f's source and pass now): three unreadable or redefining object streams (unfiltered URI, ASCIIHexDecode, bad header), an unfiltered object stream that is a real page open, 40 references with an expired deadline, and a charge-once check on `budget.expanded`. Consumer sweep over 1,469 files: identical to f1cbe8f. Full suite, ruff, mypy --strict, lint_rules, check_rule_pairs, check_added_rules, measure_precision --fail-over, check_text_controls, check_scan_only, the probe with --verify --benign-stdlib and selftest pass.

### Security review follow-up (f1cbe8f)

Codex's security review (P2) reported that a stale raw definition makes an object lookup non-empty even when a hidden object stream, read through a filter this reader does not undo, redefines the same object as an action. The opaque-index rule above covers a stream whose only filter is not FlateDecode (for example ASCIIHexDecode). Tracing it also found a gap the report did not name: `_pdf_flate_parms` checks only the first filter, so `[/FlateDecode /ASCIIHexDecode]` inflated once and the hex text was read as the stream's own bytes. Text that starts `35 20 30 20` then parses as a header for object 35, while a reader hex-decodes it to `5 0 ` and sees object 5. An object stream whose `/Filter` array has more than one entry is now unreadable, so the index is opaque and the reference is not a page open. The new test builds exactly that stream; it fails without the check and passes with it.

This follow-up is a separate change because #133 was merged at f1cbe8f before these fixes were pushed. Consumer sweep over 1,469 files: identical to main.

### Interaction with #134 (ASCII stages before Flate)

Merging this branch with draft #134 failed two of #134's tests,
`test_openaction_reference_into_an_ascii_wrapped_object_stream` with `[/ASCII85Decode /FlateDecode]`
and with `[/AHx /Fl]`. Both expected the page-open note and got a block. The cause is the rule
above: it made every object stream with more than one filter unreadable. #134's
`_pdf_flate_plan` undoes any number of leading ASCIIHex/ASCII85 stages and then FlateDecode, and
nothing after it. So the danger is a filter after FlateDecode, not the number of filters. The rule
is now that a `/Filter` array is readable only when its last entry is FlateDecode (`/Fl`) and
every earlier entry is an ASCII stage (`/AHx`, `/ASCIIHexDecode`, `/A85`, `/ASCII85Decode`). That
is exactly the chain #134 decodes in full.

- On this branch alone the change is behavior-neutral. `main`'s `_pdf_flate_parms` still rejects
  a chain that does not start with FlateDecode, so an ASCII-led object stream stays unreadable.
- `[/FlateDecode /ASCIIHexDecode]` and `[/FlateDecode /FlateDecode]` stay unreadable.
- The Codex test gains `[/ASCII85Decode /FlateDecode /ASCIIHexDecode]`. That is the same trailing
  filter behind an ASCII stage, and once #134 decodes the A85 stage only this check stops it.

Trial merge of this branch with #134 at `0ffb339`, CLI under `default`, `agent-ingest` and
`agent-document`, disposable home and rules copy. The baseline is #134 merged with this branch's
previous head, `5d53152`.

| Object stream holding object 5 | Merge with `5d53152` | Merge with this change |
| --- | --- | --- |
| `/FlateDecode`, page open | note (`_goto`) | note (`_goto`) |
| `[/ASCII85Decode /FlateDecode]`, page open | block | note (`_goto`) |
| `[/AHx /Fl]`, page open | block | note (`_goto`) |
| `[/FlateDecode /FlateDecode]`, page open | block | block |
| `[/FlateDecode /ASCIIHexDecode]`, Codex JavaScript | block | block |
| `[/ASCII85Decode /FlateDecode /ASCIIHexDecode]`, Codex JavaScript | block | block |

In the merged tree, restoring the previous `len(filters) > 1` rule fails #134's two cases. Removing
the check fails both Codex cases. With this change the 111 selected PDF tests pass, and the merge
has no textual conflict.

### Codex review of f209761

Two code-review findings, both reproduced on `f209761` with inert files.

- **P2, zero-padded headers.** `_PDF_HEADER` capped each digit run at 32 and had a lookbehind,
  so `000…0005 0 obj` with 33 or more digits never matched. A URI redefinition of object 5
  written that way was skipped, and `/OpenAction 5 0 R` read as the note instead of a block.
  Readers accept any number of leading zeros.
  - Digit runs are now matched whole with a possessive `[0-9]++`, then stripped of zeros.
  - A header with more than 32 significant digits is skipped. No reference resolves to it, and a
    reference with that many digits does not resolve, which already blocks.
  - On 50 MB worst-case inputs (one zero run, digit/space runs, 40-digit runs, real headers,
    near-misses) the new pattern stays linear and is as fast as the old one or faster: 0.65 s
    against 0.63 s for the zero run.
- **P1, unfiltered object streams copied per declaration.** 64 overlapping declarations ahead of
  one 1 MB tail retained 64 copies: 61 MiB peak for a 0.96 MiB file, with nothing charged to the
  budget.
  - The fallback now keeps a `memoryview` into the file, with no copy and no expansion.
  - A lookup copies at most `_PDF_VALUE_WINDOW` (4 KB) of each member, the same window a raw
    definition gets and the only part any caller parses. Lookups of every member then peak at
    1 MiB.

Tests: the three zero-padding cases and the shared-buffer check fail on `f209761` and pass here.
The full pytest suite (363 passed, 1 skipped), ruff, mypy --strict, check_text_controls,
check_rule_pairs, measure_precision --fail-over (310 files, 0 incomplete) and the probe with
--verify --benign-stdlib pass. A trial merge with `main` at `72cb0f4` (#134) is clean, and its
200 heuristics and scanner tests pass.
