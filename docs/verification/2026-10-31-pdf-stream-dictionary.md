# PDF stream dictionary and predictors — October 31, 2026

Baseline: `main` `1c3de509c1b2b38fa047c4a796da09a8a528286f`, Python 3.12.3, YARA-X 1.22.1,
Linux x86_64 (root container). Shipped local rules only: 79 compiled, 0 skipped. No vendor pack
was installed, no target was executed, and every scan used a disposable home and rules copy.

## Defect

`pdf_views` decided whether to inflate a stream by looking for `/FlateDecode` after the last
`<<` in the 1 KB before `stream`. A nested dictionary after `/Filter`, such as
`/DecodeParms << /Columns 1 >>`, is that last `<<`, so the stream was never inflated. The
`pdf-flate` view, `pdf_token_findings`, and the lexical YARA rules then never saw its contents.

Reproduced on the baseline through `yara-gate scan - --json` under `default`, `agent-ingest`
and `agent-document`. An object stream holding
`<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>`:

| Stream dictionary | Baseline | After |
| --- | --- | --- |
| `/Filter /FlateDecode` (control) | block, exit 1 | block, exit 1 |
| `... /DecodeParms << /Columns 1 >>` | **clean, exit 0** | block, exit 1 |
| `/Filter [/FlateDecode] /DecodeParms [<< /Columns 1 >>]` | **clean, exit 0** | block, exit 1 |
| nested dictionary before `/Filter` | block, exit 1 | block, exit 1 |
| PNG predictor 12, Up rows, `/Columns 16` | **clean, exit 0** | block, exit 1 |
| TIFF predictor 2, `/Columns 16` | **clean, exit 0** | block, exit 1 |

Every "after" block carries `heuristic_pdf_JS`, `heuristic_pdf_JavaScript`, and
`heuristic_pdf_OpenAction` with `view: pdf-flate`. The result was identical under all three
policies.

## Change

`src/yara_gate/content.py`:

- The stream dictionary is the single value between the nearest `N G obj` header (within 4 KB)
  and `stream`. It is tokenized with the heuristics lexer (`#xx` names decoded, literal and hex
  strings skipped, comments dropped) and parsed into dictionaries and arrays. Parsing must
  consume every token, so a `<<` or `stream` inside a string cannot misplace it.
- The stream is inflated when `/Filter` is `/FlateDecode`, or an array whose first filter is
  `/FlateDecode`. A one-level indirect `/Filter` or `/DecodeParms` reference is resolved from
  the last matching top-level object header, with a cache per file. `[/ASCIIHexDecode
  /FlateDecode]` is not inflated: the first decoding step is not Flate.
- `/DecodeParms` (or its first array entry) selects the predictor. Missing or non-integer
  `/Predictor` means none, as in pdf.js. PNG (10-15; None, Sub, Up, Average, Paeth by row tag)
  and TIFF 2 at 8 bits per component are reversed. A predictor a reader rejects (3-9, above 15),
  TIFF at other depths, an unknown PNG row tag, or out-of-range Colors, BitsPerComponent or
  Columns keeps the stream out of the view.
- A predictor stream is first decoded only up to 4 KB. `sniff` reads no further than that
  prefix, so the full decode runs only for text. A 3 MB Paeth-filtered binary image is
  rejected in 0.08 s.
- When no dictionary parses (no header in the window, or malformed tokens), the stream is
  inflated if `/FlateDecode` occurs anywhere in the 1 KB before it, a superset of the old test.
  `stream` matches that end `endstream` are skipped.
- `_inflate`, the per-stream 100 MB cap, the 500 MB shared expansion budget, the 2000-stream
  cap, and per-chunk deadline checks are unchanged. The predictor pass checks the deadline per
  row. Its output is smaller than the inflated input, so it adds no expansion.

## Direct verification

Direct `pdf_views` calls on the change:

- PNG round trip over all five row filters, partial final rows, 1-3 byte pixels: equal.
- Indirect `/DecodeParms 9 0 R` to a PNG predictor, indirect `/Filter 8 0 R` to
  `[/FlateDecode]`, `/Fl#61teDecode`, a dictionary string holding `<<` and `stream\n`, a comment
  between `>>` and `stream`, `/DecodeParms null`, a non-integer predictor, and a dictionary with
  no header (fallback): all produce `pdf-flate` with `/JS`.
- `[/ASCIIHexDecode /FlateDecode]`, predictor 5, no `/Filter` with `/FlateDecode` only in a
  nested value, and a PNG-predicted binary `/Type /XRef` stream: no view.
- Nested `/DecodeParms` on a 120 MB bomb: `ContentLimit(pdf stream exceeds 100MB)`. Six 90 MB
  streams: `ContentLimit(extracted size exceeds 500MB)`. A 2 MB PNG text stream with a 0.2 s
  deadline: `ContentLimit(timeout)`.

Real PDFs: seven files (five LibreOffice 24.2.7.2 exports of repository Markdown and screenshots,
`theme-showcase.pdf`, LibreOffice's `xpdfimport_err.pdf`) produced byte-identical `pdf-flate`
lengths and identical `Budget.expanded` on the baseline and the change. CLI scans outside the
inbox gave the same verdicts on both: six block on `heuristic_pdf_OpenAction` (the existing
navigation-action restriction in `pdf-name-boundaries.md`), one clean, none incomplete. None of
these files uses object streams, `/DecodeParms`, or predictors, so they confirm no regression
or new budget exhaustion but do not exercise the new predictor path; no qpdf, pikepdf or pypdf
producer was available locally.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src/yara_gate/content.py tests/test_scanner.py
uv run ruff format --check src/yara_gate/content.py tests/test_scanner.py
uv run mypy --strict src
uv run pytest -q tests/test_scanner.py -k decode_parms
```

- Probe: passed, 0 failures; 524 library, 55 CLI, and 109 benign observations; 3 failure paths.
- Rule pairs: passed (101 rules). Precision: 310 files, 0 incomplete, no rule over 2%, exit 0.
- Ruff, format, and strict mypy: clean.
- The three new parametrized regression cases fail on the baseline source and pass on the
  change. The broad pytest and selftest suites are left to hosted CI.

Rebased onto `main` `693bca1` (#127, which changed `heuristics.py`, the probe, and the rule
pair check). On the rebased head: the reproduction table, the direct edge cases, ruff, format and
strict mypy are unchanged; the probe passes with 80 rules compiled, 0 skipped, and 529 library,
55 CLI and 109 benign observations; rule pairs pass (104 rules); precision is 310 files, 0
incomplete, exit 0; the eight `flate`/`decode_parms` scanner tests pass.

## Limits

This is still a bounded lexical view, not a PDF parser. Streams whose dictionary is more than
4 KB from its header fall back to the 1 KB proximity test. Only the first filter is decoded:
ASCIIHex, ASCII85, LZW, and RunLength chains are not, and a Flate stream that is followed by
another filter is inflated and must still sniff as text. References are followed one level, to
an uncompressed top-level object. A file with many distinct references can spend its deadline
resolving them and ends incomplete. Synthetic inputs do not establish a production
false-positive rate.
