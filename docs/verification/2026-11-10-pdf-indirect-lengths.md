# PDF stream lengths kept in another object: one pass, not one per stream — November 10, 2026

Measured on `main` at `2b6eda8` and on this change. Linux 6.18 x86_64 container (4 vCPU),
Python 3.12.3, YARA-X 1.23.0, 85 bundled local rules, zero skips, no vendor download. Every
scan used `scan_bytes` with a disposable copy of `rules/local`. Nothing was executed,
unpacked to disk, or fetched by the scanner. Each number is one run, not a benchmark.

## Defect

The annotation reader steps over a stream body by its `/Length`. When the length is a
reference (`/Length 12 0 R`), `_tokens` in `pdfannotations.py` asks `PdfObjects` for object
12, and a lookup that was not primed runs `PdfRawObjects.prime([key])`: one
`_PDF_HEADER.finditer` pass over the whole file. A file whose writer keeps every length in
its own object therefore costs a pass per stream. qpdf's QDF mode writes every stream that
way, and so does any writer that emits a body before it knows the size.

cProfile on the 300-stream file below, on `main`: 300 calls to `heuristics.py` `prime`,
8.06 s of 8.56 s, all from `pdfannotations._tokens`.

## Change

`prime_stream_lengths` in `pdfannotations.py` finds every `/Length N G R` with one regular
expression pass and hands the objects to `objects.prime` together, before the token pass.
Priming records where the definitions are and nothing else, so each lookup returns what it
returned before. The same file after the change: one pass in `prime`, 0.025 s of 0.55 s.

The pattern reads the four tokens as the lexer does: any letter of the name as a `#xx`
escape, whitespace or comments between the tokens, digit runs of any length. It reads bytes,
not tokens, so a match inside a string or a stream body is taken too and costs one unused
entry.

The object-stream members get the same pass before they are read, because a member can
hold a stream whose length is another member. Only inflated members are read there. A
member of an unfiltered object stream is a view of the file, which the first pass has
read.

## Result

Synthetic files of content streams with 4,000 bytes of padding each and no annotation. The
verdict is `clean` with no findings in every row except the two timeouts.

| Streams | File size | `/Length` direct, `main` | direct, change | `/Length N 0 R`, `main` | `N 0 R`, change |
| --- | --- | --- | --- | --- | --- |
| 150 | 0.6 MB | 0.20 s | 0.20 s | 2.00 s | 0.22 s |
| 300 | 1.2 MB | 0.42 s | 0.36 s | 7.64 s | 0.40 s |
| 900 | 3.6 MB direct, 3.7 MB indirect | 1.25 s | 1.32 s | 30.06 s, `incomplete` (`timeout`) | 1.37 s |
| 900 | padded to 4 MiB | | | 30.05 s, `incomplete` (`timeout`) | 1.55 s |

A file written by a real writer: 20 sources of 27 pages each, merged and saved by libqpdf
12.4.2 (through pikepdf 10.18.0, run as an overlay with `uv run --with pikepdf`; the locked
environment and `uv.lock` are unchanged). The QDF save has 540 streams, each with
`/Length N 0 R`. The plain save of the same merge has 540 direct lengths. Both carry 20
annotations.

| File | Size | `main` | Change | Result on both |
| --- | --- | --- | --- | --- |
| QDF save | 2,210,048 bytes | 28.68 s | 1.55 s | `clean`, `pdf-annotation` 20, `pdf-text` 540 |
| Plain save | 2,091,339 bytes | 1.53 s | 1.56 s | `clean`, `pdf-annotation` 20, `pdf-text` 540 |

On `main` the QDF save is 1.3 s from the scanner's 30 s deadline.

The tripwire has a new input, `pdf-indirect-lengths.pdf`: 1,029 such streams in exactly
4 MiB, then one annotation. It requires the `pdf-annotation` view, which is read only when
every length before it landed.

| Source | `pdf-indirect-lengths.pdf` |
| --- | --- |
| `main` | 30.028 s, fails (`exceeds 10s`) |
| Change | 1.49 s, `clean`, `pdf-annotation` 1 |

The whole tripwire passed on the change: 30 inputs, each exactly 4 MiB.

## The answer is the same

**Reader, 23 inputs.** `pdf_annotation_texts` was run on each with the priming and with it
replaced by a no-op, and the text or the `ContentLimit` reason was compared. All 23 agree.
With 40 streams per input, the passes over the file went from 40 to 1 for 13 of them: the
plain form, the name with lower-case and upper-case `#xx` escapes, comments between the
tokens, NUL and form-feed gaps, 36 leading zeros, no space before `>>`, generation 1, a
duplicated `/Length` key, a nested `/Length`, the length held in an inflated object stream
and in a stored one, and streams inside inflated members. Eight took one pass both ways:
every stream naming one shared length object, references that only appear inside a stream
body, and six that end `pdf annotation stream length unaligned` on the first stream (no
object holds the length, two hold it, 70 hold it, it does not land, the object is itself a
reference, its number has 40 significant digits). Two took none either way: a direct
length, and a 5,000-digit number, which is not a dictionary value to either.

**Scanner, 53 inputs.** The same files, the six table files, the two libqpdf files, and
every PDF in `showcase.py` and `samples.py` were scanned on `main` and on the change, and
every field of the result except the timings and `detector_sha256` was compared. Two
results changed: the 900-stream files that timed out are now `clean`. The other 51 are
identical, including every finding, `incomplete_reason`, and `views_scanned`.

**Tests.** `tests/test_pdfannotations.py` and `tests/test_pdfxref.py`: 76 passed, 9 of
them new. The new tests count passes over the file rather than seconds: one pass with the
priming and twelve without, with the same text, for five spellings and for member streams;
and the same reason primed and unprimed when no object, two objects, or 65 objects hold
the length.

## Cost of the pass itself

Each 4 MiB input below was given to the pattern alone, then to `prime_stream_lengths`
(which includes the one `prime` pass when a reference was found).

| 4 MiB input | Matches | Pattern | With priming | Keys |
| --- | --- | --- | --- | --- |
| 900 direct-length streams (ordinary) | 0 | 0.002 s | 0.002 s | 0 |
| `/` repeated | 0 | 0.029 s | 0.030 s | 0 |
| `/Length ` repeated | 0 | 0.059 s | 0.059 s | 0 |
| `/Length %` repeated, no newline | 0 | 0.064 s | 0.064 s | 0 |
| `/Length 1 %` repeated, no newline | 0 | 0.073 s | 0.069 s | 0 |
| `/#4c#65#6e#67#74#68 ` repeated | 0 | 0.025 s | 0.025 s | 0 |
| one name, then 4 MiB of digits | 0 | 0.006 s | 0.005 s | 0 |
| one name, then 4 MiB of spaces | 0 | 0.066 s | 0.064 s | 0 |
| `/Length 1 0 R ` repeated | 299,592 | 0.092 s | 0.665 s | 1 |
| a different reference each time | 226,599 | 0.072 s | 1.239 s | 100,000 |

The first draft of the pattern let a comment between the tokens hold any byte. A comment
can then hold the name, so in `/Length %/Length %...` with no newline every attempt reads
the same comment to its end. The pattern now leaves out a comment that holds a `/`.
Every attempt starts at a `/`, nothing it reads after that can be one, and the gaps and
digit runs are possessive, so no byte is read by two attempts. Rows four and five are that
input.

Two object-stream inputs at 4 MiB, through `pdf_annotation_texts`:

| Input | `main` | Change |
| --- | --- | --- |
| 900 streams inside the members of one inflated object stream, each length another member | 30.01 s, `timeout` | 0.44 s, annotation read |
| The same members, unfiltered | 0.00 s, `stream length unaligned` | 0.08 s, same reason |

## Boundaries

- A comment that holds a `/` between the name and its value is not found by the pattern.
  Those lengths are looked up one at a time as before, and the 30 s deadline ends that scan
  as `incomplete`. No writer was found that puts a comment there.
- The pass stops at 100,000 distinct references (`MAX_TEXT_PIECES`), which bounds its
  memory: 37 MB at the peak (tracemalloc) for the last row above. References past that are looked up one
  at a time. A file that defines more than 100,000 objects is already
  `pdf annotation objects exceed 100000`, and more than 2,000 streams is already
  `pdf streams exceed 2000`.
- The priming is the annotation reader's own. Another reader that steps over streams by
  their length has to prime before its own pass, or call `prime_stream_lengths`.
- Found and left as it is: many unfiltered `/ObjStm` declarations before one `endstream`
  make `PdfObjects._index` search to that `endstream` once per declaration. 60 of them in
  4 MiB take 10.8 s on `main` and 1,900 reach the timeout, before and after this change.
  With the member pass limited to inflated members, this change adds nothing to that input
  (11.78 s on `main`, 11.75 s here). Read unfiltered members too and it would add 3.6 s.

## Open pull requests

Listed on November 10 at these heads; each was trial-merged with this change. All three
merges are clean. On each merged tree Ruff, `mypy --strict src scripts`, the link check,
the PDF and tripwire tests, the new input, and that pull request's own tripwire inputs
passed.

| Pull request | Head | Shared files | Merged tree |
| --- | --- | --- | --- |
| #205 page fonts | `f83c738` | `pdfannotations.py`, `check_worst_case_timing.py` | 152 tests passed; new input 1.51 s; its two inputs 6.01 s and 2.53 s |
| #206 font definitions | `3707639` | `check_worst_case_timing.py`, `worst-case-timing.md` | 124 tests passed; new input 1.55 s; its input 5.35 s |
| #207 hidden HTML | `3f44e7d` | `check_worst_case_timing.py` | 106 tests passed; new input 1.62 s; its four inputs 1.45 s to 3.58 s |

Two things to settle when they merge:

- **The input count.** `worst-case-timing.md` says 30 here. #206 also changes 29 to 30, so
  Git merges the two without a conflict and the number is then one short. #205 adds two
  inputs and #207 adds four without changing it. With all four merged the script has 37.
- **#205 has the same cost in its own pass.** At `f83c738`, `pdfpages._layout` steps over
  streams with `stream_span` before the annotation reader runs, and nothing primes the
  lengths for it. A file with two fonts under one name and 300 indirect-length streams
  takes 8.78 s on #205 alone and 8.33 s merged with this change (302 passes in `prime`).
  One call to `prime_stream_lengths([data], objects, budget)` at the top of `_layout` on the
  merged tree brings it to 0.72 s (5 calls to `prime`). That call is not part of this
  change.

## Commands

```sh
uv sync --frozen --group dev
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src scripts
uv run pytest tests/test_pdfannotations.py tests/test_pdfxref.py -q
uv run python docs/verification/check_worst_case_timing.py
uv run python docs/research/probe_rule_coverage.py --verify
uv run python docs/verification/check_text_controls.py
uv run python docs/verification/check_doc_links.py
```

All passed on the change. The direct probe exited 0. The comparison scripts and the
generated files were kept outside the repository and are not committed. The full pytest
and selftest suites, macOS, and Windows are left to hosted CI.
