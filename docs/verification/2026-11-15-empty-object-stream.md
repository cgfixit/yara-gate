# An object stream with `/N 0` — November 15, 2026

Fixes [#238](https://github.com/cgfixit/yara-gate/issues/238). Base `main` `f54c57e`.
Python 3.12.3, YARA-X 1.23.0, bundled local rules copied to a disposable rules root, no vendor
packs. Every fixture is an inert PDF built in memory; nothing was executed or fetched.

## The defect

`PdfObjects._read_objstm` accepts `/N 0 /First 0` as an empty header and returns empty number
and offset lists. `_index` then zipped them, with `strict=True`, against one bound
(`[*offsets[1:], len(decoded) - origin]`), which raised `ValueError`. The scanner caught it as
`content scan failed`. The raise happens on the first lookup through the object index, so the
`pdf-text` view and the hidden-text heuristic never ran.

The guard builds no bounds when there are no offsets. A stream with `/N 0` is recorded as a
readable stream with no members. It does not set `opaque`, which stays reserved for a stream
whose header or filters do not parse.

## Direct runtime

`scan_bytes(..., name="doc.pdf", policy="agent-document")` on a one-page PDF whose page text is
in a Flate content stream, beside an object stream `<< /Type /ObjStm /N 0 /First 0 >>` with a
body that is not a member header (unfiltered, and Flate-compressed):

| Fixture | `f54c57e` | With the guard |
| --- | --- | --- |
| Invoice page only | clean, exit 0 | clean, exit 0 |
| Invoice page + `/N 0` (either body) | incomplete, exit 2, `content scan failed` | clean, exit 0, `opaque` false |
| Invoice page + a header that does not parse (`/N 1`, `x y z w`) | clean, `opaque` true | unchanged |
| Override phrase on the page only | advisory: `pdf-flate`, `pdf-text` | unchanged |
| Override phrase + `/N 0` (either body) | incomplete, exit 2, `pdf-flate` only | advisory: `pdf-flate`, `pdf-text` |
| Override phrase + a header that does not parse | advisory: `pdf-flate`, `pdf-text`, `opaque` true | unchanged |

## Readers

The guard ignores any header bytes past `/N 0`. To check that this matches readers, a page
dictionary was stored only in an object stream, reached by a type-2 cross-reference stream
entry, with its text in an ordinary content stream:

| Reader | `/N 1` | `/N 0` |
| --- | --- | --- |
| pypdf | shows the text | raises `LimitReachedError` |
| PyMuPDF | shows | nothing |
| pypdfium2 | shows | raises `PdfiumError` |
| pdfminer.six | shows | nothing |
| poppler `pdftotext` | shows | nothing |

No reader takes a member past `/N`.

## The page map

`pdfpages.PlainFile` still refuses a file with an empty object stream, because `_members`
requires a first offset of 0. Such a file is read through the file-wide union, which reads
more than the page map does, never less. What the map accepts did not change.
`probe_pdf_reader_agreement.py` was run all the same, with pypdf, pdfminer.six, pypdfium2,
PyMuPDF, and poppler:

- `fixtures`: 141 files, MISS 0, gap 10, ok 131. The gaps are the font-reference rows the
  backlog already lists.
- `fuzz --seed 1 --count 15000`: 532 files where the map read less than the union, MISS 0,
  gap 0.

## Checks

- `tests/test_scanner.py::test_an_empty_object_stream_leaves_the_page_scan_complete` (both
  bodies) and `tests/test_heuristics.py::test_an_object_stream_with_no_objects_is_empty_not_opaque`
  fail on `f54c57e` and pass with the guard.
- `pytest` on the PDF, heuristic, and scanner test files: 629 passed.
- `docs/research/probe_rule_coverage.py --verify`: passed.
- Ruff check and format on the changed files, and `mypy --strict src scripts`: clean.

Not run here: the full pytest and selftest suites and the Windows and macOS jobs. Those are
left to hosted CI.
