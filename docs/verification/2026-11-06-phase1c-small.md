# Phase 1c-small verification (2026-11-06)

Base: `39f5aa6f9cca6c002b195062bbf01c75c149a75a` (Phase 1b merged).
Local macOS arm64, Python 3.12.12, locked YARA-X 1.23.0. Disposable rules
and gate homes, 85 bundled rules, no vendor downloads or skipped files.
Candidate scanner source hashes:

- `src/yara_gate/content.py`: `53c3579fb0edc2fa4bee262d319affceb39753d93ffac6ac4cfb6c4db06a41b4`
- `src/yara_gate/scanner.py`: `7673de815127cc9e8bab1162c621a78cd55b5f4cb3d75592ff9355fc25a86c2d`

## Behavior and scope

The unchanged base reproduced four misses from [#171](https://github.com/cgfixit/yara-gate/issues/171):
SVG tspan text, Excel rich comments, modern PowerPoint rich comments, and Latin
small capitals. Each was clean under all three policies. The candidate reports
the same phrase as a note, advisory under default and agent-document and block
under agent-ingest. No rule severity or policy changed.

Excel `xl/commentsN.xml` and PowerPoint `ppt/comments/*.xml` use a separate
`ooxml-comment` piece per comment, reusing the bounded worksheet tokenizer.
SVG uses `html-text`, with a separate piece for each text element. The fixed
small-capital table feeds the existing spelling fold, including folded piece
views. Plain IPA and small-capital benign headings remain clean. Separate
comments/text elements cannot create one phrase; piece scanning also prevents a
quotation in one comment from suppressing another comment's phrase.

## Local execution

- `uv run python docs/research/probe_detection_gaps.py --verify`: baseline 155 ok,
  10 open; candidate 159 ok, 6 open; no FAIL or STALE. The existing benign SVG,
  separate-comment, rich review-comment, heading, and IPA boundaries stay clean.
- `uv run python docs/research/probe_rule_coverage.py --verify`: passed its real
  library/CLI scans, report and intake checks, and compilation/deadline failures.
- `uv run pytest -q tests/test_phase1c_readers.py`: 8 focused regressions passed.
  These cover policy/severity, member ordinals and view labels, SARIF's lack of
  outer-file byte regions for derived findings, separate pieces, scope exclusions,
  the deadline, and actual 100,001-piece inputs for the shared cap.
- `uv run python docs/verification/check_rule_pairs.py`: 115 pairs passed.
- `uv run python docs/verification/check_added_rules.py`: 180 plus 4 override cases passed.
- `uv run python docs/verification/measure_precision.py --fail-over`: 324 files,
  zero incomplete; exact same finding table as base (only the time line differed).
- Ruff check/format on changed Python and Markdown, `mypy --strict src`,
  `check_text_controls.py`, and `git diff --check`: passed.

A read-only comparison of 500 installed Homebrew documentation/assets under
200,000 bytes each found zero changes in hashes, verdicts, incomplete reasons,
or finding-ID sets. This is a small host sample, not a production false-positive
rate or an Office corpus. Filenames and contents are not published.

## Adversarial timing

One real `scan_bytes` run per input using the Phase 3 tripwire candidate, against
main and then this scanner via `PYTHONPATH`. Each input is exactly 4 MiB. Compilation
is warmed outside the scan timer; each worker has a 20-second watchdog, and each
scan must finish in 10 seconds. The two explicit cap outcomes are incomplete,
not clean. This is a regression check, not a latency guarantee.

| 4 MiB input | Main seconds | Phase 1c-small seconds | Outcome |
| --- | --- | --- | --- |
| `html-comments.html` | 0.328 | 0.330 | clean |
| `html-quotes.html` | 0.426 | 0.419 | clean |
| `html-tags.html` | 0.406 | 0.405 | clean |
| `zip-end-records.zip` | 0.006 | 0.006 | zip end records exceed 64 |
| `json-escapes.json` | 0.581 | 0.580 | clean |
| `notebook-nesting.ipynb` | 0.223 | 0.225 | clean |
| `comment-lines.py` | 0.798 | 0.779 | clean |
| `comment-pieces.py` | 0.290 | 0.280 | text pieces exceed 100000 |
| `markdown-brackets.md` | 0.388 | 0.393 | clean |
| `rtf-controls.rtf` | 0.273 | 0.273 | clean |
| `svg-spans.svg` | 0.236 | 0.465 | clean |
| `small-capitals.txt` | 0.548 | 0.986 | clean |
| `ooxml-comment.zip` | 0.298 | 0.428 | clean |

## Remaining scope

RTF reading, PDF strings outside streams, OOXML drawings/glossary parts, Excel
threaded comments, and hidden-text policy (#110) remain outside this draft. SVG
coordinates/CSS and visibility are not computed; positioned tspans within one
text element can still combine. The small-capital table is not general IPA
transliteration. No Office viewer, native application, vendor-pack run, full local
suite, or production recall study was performed. Hosted checks are separate.

Format references: [SVG 2 text](https://www.w3.org/TR/SVG2/text.html) and
[Microsoft's modern-comment example](https://learn.microsoft.com/en-us/office/open-xml/presentation/how-to-reply-to-a-comment-in-a-presentation)
(consulted 2026-11-06). Neither substitutes for viewer acceptance.

## PR review follow-up

Review of `5d0c55b` reproduced a missed directive split between an SVG CDATA
section and a following tspan: `clean` instead of the ordinary phrase note. The
reader now consumes CDATA as literal text while inside SVG. Entity-looking text
inside CDATA stays literal, and ordinary HTML CDATA handling is unchanged. The
focused file now has 10 passing cases; the detection-gap probe and 324-file
precision results are unchanged. Ruff, format, strict mypy, and text-control
checks passed. The earlier source hashes and timings above describe the original
candidate; the follow-up commit is the reviewed source for this correction.
