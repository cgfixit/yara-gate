# PDF ASCIIHex and ASCII85 filter chains — October 31, 2026

Baseline: `main` `dcb9e0a9f339c1828b02fe3b526932ffd9ba73f3` (after #129, #130, #132; rebased onto `e1e3eb3` with #131, docs only), Python
3.12.3, YARA-X 1.22.1, Linux x86_64 (root container). Shipped local rules only: 80 compiled, 0
skipped. No vendor pack was installed, no target was executed, and every scan used a disposable
home and rules copy. Open PR #133 also edits `pdf_views`; see "Overlap with #133".

## Defect

After #129, `pdf_views` inflated a stream only when its first filter was `/FlateDecode`. A
chain such as `/Filter [/ASCII85Decode /FlateDecode]` or `[/ASCIIHexDecode /FlateDecode]` was
skipped, so its decoded text never reached the `pdf-flate` view, `pdf_token_findings`, or the
lexical YARA rules. ReportLab writes `[/ASCII85Decode /FlateDecode]` by default
(`rl_config.useA85`), so this also covers ordinary producer output, not just crafted files.

Reproduced through `yara-gate scan - --name x.pdf --json --home <tmp> --rules <tmp copy of
rules/local>` under `default`, `agent-ingest` and `agent-document`. An object stream holding
`<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>`:

| Stream filter | Baseline | After |
| --- | --- | --- |
| `/FlateDecode` (control) | block, exit 1 | block, exit 1 |
| `[/ASCII85Decode /FlateDecode]`, `<~ ~>` framed, wrapped | **clean, exit 0** | block, exit 1 |
| `[/ASCIIHexDecode /FlateDecode]`, wrapped, `>` terminated | **clean, exit 0** | block, exit 1 |
| `[/A85 /Fl]`, no `<~` | **clean, exit 0** | block, exit 1 |
| `[/AHx /Fl]` | **clean, exit 0** | block, exit 1 |
| `[/ASCIIHexDecode /ASCII85Decode /FlateDecode]` | **clean, exit 0** | block, exit 1 |
| `[/ASCII85Decode /FlateDecode]`, `/DecodeParms [null << /Predictor 12 /Columns 8 >>]` | **clean, exit 0** | block, exit 1 |

Every "after" block carries `heuristic_pdf_JS`, `heuristic_pdf_JavaScript`, and
`heuristic_pdf_OpenAction` with `view: pdf-flate`, identically under all three policies.

## Change

`src/yara_gate/content.py`:

- `_pdf_flate_plan` replaces `_pdf_flate_parms`. It walks `/Filter` (a name or an array, each
  element resolved one level) and accepts any number of leading `ASCIIHexDecode`/`AHx` and
  `ASCII85Decode`/`A85` stages followed by `FlateDecode`/`Fl`. Any other filter before Flate
  (or no Flate) returns None and the stream stays out of the view, as before.
- `/DecodeParms` is taken at FlateDecode's index when it is an array, as pdf.js and MuPDF do. A
  lone dictionary still applies when Flate is first, which preserves #129's behavior; with Flate
  at a later index it is ignored, as those readers ignore it. The predictor checks are unchanged.
- `_ascii_hex` follows pdf.js: `>` ends the data, other non-hex bytes are skipped, and an odd
  final digit is followed by 0. It decodes 64 KB of input at a time.
- `_ascii85` drops PDF whitespace (NUL, tab, LF, FF, CR, space), strips an optional leading
  `<~`, and ends at the first `~`. `z` at a group boundary is four zero bytes. Whole groups go
  through `base64.a85decode` in about 64 KB chunks. A chunk that would raise there (a group
  over 2^32, `z` inside a group, bytes outside `!`-`u`) is decoded group by group with each
  byte taken as a digit and the value wrapped to 32 bits, as pdf.js does. Malformed groups
  therefore cannot hide later data. A final group of n digits yields n - 1 bytes.
- Every stage's output goes through `_pdf_grow`. It counts against `Budget.expanded` (500 MB)
  and the per-stream 100 MB cap with the same `ContentLimit` messages as `_inflate`, and the
  deadline is checked per chunk. `z` expands 5:4 against the encoded size and is the only path
  where an ASCII stage grows. After the stages come `_inflate`, the predictor, and `sniff(...)
  == "text"`, unchanged.
- `_pdf_resolve` now tokenizes a referenced object only up to its `endobj` or `stream`, within
  the same 4 KB window. Before, any lone `>` in that window had no lexer token and dropped the
  reference. That lone `>` can be the ASCIIHex end marker or a 0x3E byte in a following stream.
  This bug is in the baseline: an indirect `/Filter 7 0 R` to `[/FlateDecode]` followed by a
  3-byte stream holding `a>b` gave no `pdf-flate` view on `main` and does now.

LZW and RunLength are out of scope. The standard library has no decoder for either. A
pure-Python decoder over a 100 MB stream would end most real files at the deadline instead of
covering them, and neither filter appears in the producers checked here. A chain that needs
either stage (leading, or between ASCII stages and Flate) stays out of the view and remains a
documented gap. An ASCII-only chain without Flate (`/Filter /ASCIIHexDecode` on plain text) is
also not added: this change keeps the view to streams that end in Flate.

`docs/integrations.md` and `docs/rules.md` said ASCII85 and PNG predictors were not decoded; they
now name the covered stages and the remaining gaps.

## Direct verification

Direct calls on the change:

- Round trips against `base64.a85encode` and `binascii.hexlify` for 0-39, 65,535, 65,536,
  81,920, and 200,001 bytes (random and all-zero, so `z` groups occur), with and without `<~`,
  wrapped at 7 and 75 columns, CRLF framing, and hex split every 3 digits with trailing data after
  `>`: equal.
- An odd final hex digit (`4142 4>` gives `AB@`). Junk bytes in hex are skipped. An overflow group
  `uuuuu`, or `z` inside a group, still lets the following `/JS (x)` decode. ASCII85 with no
  `~>` decodes. A one-digit final group yields nothing.
- `[/A85 /Fl]` with `/DecodeParms [null <<P12>>]`: view. The same with the dictionary in slot 0,
  or as a lone dictionary: no view (readers apply no predictor, and the predicted bytes are not
  text). `/Predictor 5` at slot 1: no view.
- `[/LZWDecode /FlateDecode]`, `[/AHx /RunLengthDecode /Fl]`, `/ASCIIHexDecode` alone, an
  A85+Flate random binary stream, and corrupt hex: no view, no incomplete.
- `/Fl` alone, `[/Fl /AHx]` (Flate first, as before), `/Fl#61teDecode`, and an indirect
  `/Filter 7 0 R` to `[/ASCIIHexDecode /FlateDecode]`: view.
- A 30 MB `z` run: `ContentLimit(pdf stream exceeds 100MB)` after 2.5 s. 210 MB of hex digits:
  the same limit. A 50 MB run of slow-path bytes with a 1 s deadline: `ContentLimit(timeout)` at
  1.01 s.

### Real PDFs, base `dcb9e0a` against head

Twelve files: LibreOffice 24.2 exports of `README.md`, `SECURITY.md`, `docs/rules.md`, and
`docs/integrations.md`; LibreOffice's `xpdfimport_err.pdf`; `theme-showcase.pdf`; ReportLab
5.0.1 text, Platypus, image, and `useA85 = 0` files built from `README.md` and
`screenshots/yara-gate-demo-overview.png`; and pypdf 6.17.0 rewrites of the ReportLab text file
and the LibreOffice README. ReportLab and pypdf are system packages outside the locked
environment. They were used only to produce inputs.

- The seven files with no ASCII stage have byte-identical `pdf-flate` views (SHA-256) and
  identical `Budget.expanded` on base and head.
- The five files with `[/ASCII85Decode /FlateDecode]` streams (four ReportLab, plus
  `theme-showcase.pdf` with 10 such streams) gain views. `rl_text.pdf`'s view on head is
  byte-identical to the view base gives for pypdf's plain-Flate rewrite of the same file. pypdf's
  own decoder thus confirms this one independently. The largest decode took 0.03 s.
- CLI verdicts under the three policies: no incomplete on either side. Thirty of 36 results are
  unchanged. The six that changed are all ASCII85 files:
  - `rl_text.pdf` and `rl_platypus.pdf` go from clean to advisory (`agent_prompt_injection_phrases`,
    `agent_secret_transfer_request` on `pdf-flate`), and to block under `agent-ingest` and
    `agent-document`. `README.md` quotes those phrases as documentation, and base already gives
    the same findings for the plain-Flate `rl_text_pypdf.pdf`. That is parity: the text was there
    and was hidden.
  - `rl_images.pdf` goes from clean to advisory (`agent_base64_blob` on `pdf-flate`), and to
    block under `agent-ingest` and `agent-document`. This is a **false positive**. The decoded
    RGB pixels of a light screenshot pass `sniff(...) == "text"`, and a run of them reads as
    base64. Base gives the identical finding when the same image is written as plain Flate
    (`useA85 = 0`), so the cause is the existing image-as-text gap. The change extends that gap
    to ASCII85-wrapped images, which ReportLab emits by default. Dropping `/Subtype /Image`
    streams is not done here. Readers decode `/Contents` and object streams by how they are
    referenced, not by that key, so a skip based on it would be an evasion path. It needs its
    own change.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src/yara_gate/content.py tests/test_scanner.py
uv run ruff format --check src/yara_gate/content.py tests/test_scanner.py
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_scanner.py -k "flate or decode_parms or ascii or pdf"
```

- Probe: passed, 0 failures; 529 library, 55 CLI, and 109 benign observations; 3 failure paths.
- Rule pairs: passed (104 rules). Precision: 310 files, 0 incomplete, exit 0. The per-rule table
  is identical to base `dcb9e0a`.
- Ruff, format, strict mypy, and the text control check (198 files): clean.
- The five new `test_ascii_encoded_flate_object_stream_is_decoded` cases fail on the baseline
  source and pass on the change; the 21 selected PDF tests pass. The broad pytest and selftest
  suites are left to hosted CI.

## Merged with #133

#133 merged first (`main` `03e2404`) and this branch merges it. `pdf_views` keeps #133's single
`_pdf_stream_bytes` call. `_pdf_stream_bytes` now calls `_pdf_flate_plan`, runs the ASCII stages
on the body before `_inflate`, and keeps #133's rule that a predictor this view will not apply
leaves the inflated bytes as they are. So `[/A85 /Fl]` with `/DecodeParms [null << /Predictor 5
>>]` now reaches the view, where the pre-merge branch dropped it. The wrong-slot and lone-dictionary
predictor cases still give no view: the stream inflates, but the predicted bytes are not text.

`PdfObjects._index` decodes object streams through `_pdf_stream_bytes` as well, so an
`/OpenAction 5 0 R` whose target is in an ASCII85- or ASCIIHex-wrapped object stream now
resolves. On `main` `03e2404`, a URI action there scanned **clean** (`default`); on the merge
it blocks with `heuristic_pdf_OpenAction` on `pdf-flate`, and a page-open `[3 0 R /Fit]` gives
the `heuristic_pdf_OpenAction_goto` advisory, matching the plain-Flate control in each case.
`test_openaction_reference_into_an_ascii_wrapped_object_stream` in `tests/test_heuristics.py`
(4 cases) fails on `main` and passes on the merge.

Re-run on the merge: the CLI reproduction (all 21 block); ruff, format, and strict mypy are clean; 180
scanner and heuristics tests pass. The probe passes with 531 library, 55 CLI, and 109 benign
observations, 80 rules, 0 skipped. Rule pairs pass (105 rules), added-rule checks pass (74), and
the text control check passes. Precision is 310 files, 0 incomplete, with a table identical to
`main` `03e2404`. The real-PDF rescan against `03e2404` gives the same six verdict changes as above
and byte-identical views for every file without an ASCII stage, with no incompletes.

## Limits

This is still a bounded lexical view, not a PDF parser. LZW, RunLength, and ASCII-only chains are
not decoded. Light raster images that sniff as text can hit the text rules, whether plain Flate
or, now, ASCII85-wrapped. `<~` is stripped as a lenient superset: pdf.js does not strip it, and
which other readers accept it was not checked. The `/F` and `/DP` abbreviations pdf.js reads for
`/Filter` and `/DecodeParms` are not read. References are followed one level, as before.
Synthetic inputs and a dozen real files do not establish a production false-positive rate.
