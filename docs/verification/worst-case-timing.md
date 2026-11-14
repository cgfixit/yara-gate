# Worst-case scan timing tripwire

[`check_worst_case_timing.py`](check_worst_case_timing.py) scans 78 deterministic
inert inputs of exactly 4 MiB with the real `scan_bytes` API and a disposable copy
of bundled local rules. The CI step runs on Ubuntu 24.04 and macOS 15, after the
detection-gap probe. It has a five-minute job-step limit.

```sh
uv run python docs/verification/check_worst_case_timing.py
```

Each scan must finish within **10 seconds**. Each separate worker must exit within
**20 seconds**, including imports, fixture construction, and a rule warmup. The
parent kills and waits for a worker that exceeds that deadline; this also catches
regex/parser work that cannot observe the scanner's cooperative deadline. Rule
warmup stays outside the measured scan, and a failed/incomplete warmup fails the
check. The scanner's production 30-second default is unchanged.

Inputs cover unclosed HTML comments, quoted attributes and tags; ZIP end-record
floods; JSON escapes and nested notebook arrays; bare source-comment lines and
many comment blocks; unmatched Markdown brackets; unclosed RTF groups/control
words; SVG tspans; Latin small capitals; and stored OOXML comments. No input is
executed, fetched, or extracted to disk. The ZIP input size includes its metadata.
The ZIP end-record, comment-piece, and RTF group-depth floods must return their
explicit incomplete cap reasons. Two added PDF annotation floods require the
100,000-token dictionary cap and 1 MiB encoded-string cap. Four synthetic PDFs
use a `/Length` that lands on `endstream`, so the tripwire measures page-text
cost. Three ToUnicode CMap PDFs cover 200 fonts that each have their own
65,536-entry map, which must end `pdf cmap entries exceed 524288`; one map of
unclosed `beginbfchar` markers; and one `bfrange` section of `[` tokens, which
must end `pdf cmap tokens exceed 1572864`
([record](2026-11-07-cmap-entry-budget.md)). An HTML page just under the SVG scope
test's 1,024-match cap runs every scope loop to its end, and a PDF of 64 fonts
under one resource name covers the per-string font readings. A PDF that defines one
font object until the file is full, over a ToUnicode map defined 1,900 times, covers the
font-definition caps ([record](2026-11-10-pdf-font-definitions.md)). Six inputs cover the
Office XML and OpenDocument readers ([record](2026-11-11-office-xml-readers.md)): a comment
inside one Word run until the part is full, a run tag whose quoted value never closes (which
ran past 100 s before the run pattern was bounded), an internal entity referenced until it
must end `xml entity expansion exceeds 1MB`, OpenDocument paragraphs each joined across a
span, one paragraph of elements readers treat differently, and paragraphs that never close,
which must end `odf paragraph nesting exceeds 64`. The RTF reader now rejects the unclosed nesting
at depth 128; the historical table below predates that reader. Any other incomplete result, worker failure, timeout, or over-ceiling
scan fails. Reaching a safe incomplete limit is not detection clearance.

Output records revision, Python/engine version, input hash/size, scan seconds,
verdict/reason, rule count/skips, ruleset digest, and view coverage. This is one run
per synthetic case with bundled rules, not a benchmark, production latency SLO,
memory limit, vendor-pack measurement, or exhaustive worst-case proof. A future
reader may expose another regression; extend the cases with its triggering shape.
Do not raise the ceiling without diagnosing the same input on base and candidate.

## Local verification, 2026-11-06

Base `39f5aa6f9cca6c002b195062bbf01c75c149a75a`, macOS arm64, Python 3.12.12,
YARA-X 1.23.0, 85 compiled local rules and zero skips. The independent timing
branch and the Phase 1c-small scanner candidate both passed all 13 cases:

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

`tests/test_worst_case_timing.py` has two focused failure checks: a zero scan
ceiling rejects an actual completed scan, and a 1 ms worker deadline exercises
real subprocess termination with a nonzero parent exit. Both passed. Ruff and
format checks, actionlint 1.7.12, text-control checking, and diff whitespace
checks passed. Full pytest/selftest and other platforms are left to hosted CI.

## PR review follow-up

The original notebook inputs exercised malformed/escaped JSON, but neither
produced a `notebook-text` view. Added a valid notebook with a long line array,
a long source-comment block, and a Markdown paragraph with many short marked-up
lines. All 16 inputs remain exactly 4 MiB. These three cases now require their
respective reader-view counters, so bypassing a reader cannot produce a passing
fast scan. All 16 completed under the same ceilings locally. Three focused
regressions cover the scan ceiling, actual worker termination, and rejection of
a missing required reader. The 13-row table above preserves the original run.

## Reader boundaries, 2026-11-12

Thirty inputs were added with the [reader boundaries](2026-11-12-reader-boundaries.md)
change, each a shape a reviewer used to reach the 30 s deadline or the nearest one to it:
six for a PDF font's own dictionary (thousands of fonts with repeated `/ToUnicode` keys, a
font defined 64 times with keys of its own, `/Subtype` and `/Encoding` 24,000 times each,
dictionaries that fill the 4 KB window, ones only the lenient lexer reads, and a name that
means 64 fonts), thirteen for the Office readers (an unusual part name whose root tag never
closes, a long name run in a root tag, every element under another prefix, a namespace
declared on every run, DOCTYPE namespace defaults, two vocabularies in one part, nothing but
`<a:br/>`, padded end tags, megabytes of attribute), and eleven for mail (a header block
with no blank line, folded lines, a comment that never closes, nested one-body messages, a
quoted parameter, and a body or part declared `charset=punycode`). All 72 passed on Linux
x86_64, Python 3.12.3; the slowest new input took 5.9 s (`mail-nested-charset.eml`,
`pdf-font-readings-winansi.pdf`) and the slowest overall 6.3 s (`pdf-page-fonts.pdf`).
`mail-punycode-part.eml` must end `archive unreadable or encrypted`; on the base revision
the same bytes ran 136 s.

## November 13, 2026: PDF page content as one stream, and JSON with comments

Four inputs were added with the [PDF streams and JSON with comments](2026-11-13-pdf-streams-and-jsonc.md)
change: a `.json` file of unclosed `/*` (0.44 s), a page whose `/Contents` array names 400
streams joined into one (3.4 s), a binary page content stream named by a page (0.44 s), and
4 MiB of `/Contents[` after a binary content stream (2.8 s), which drives the pattern that
collects `/Contents` references. The first form of that pattern made the existing
`pdf-contents-arrays.pdf` take 10.2 s; it now takes 2.9 s. All 76 passed on Linux x86_64,
Python 3.12.3; the slowest overall took 5.0 s (`pdf-page-fonts.pdf`).

## November 14, 2026: escapes in YAML and TOML strings

Two inputs were added with the [CJK CMaps and config escapes](2026-11-14-cjk-cmaps-and-config-escapes.md)
change: 4 MiB of short escaped YAML strings, one piece each, which ends at the piece cap
(`text pieces exceed 100000`, 1.1 s), and 4 MiB of apostrophes and `#` signs that open
nothing (0.89 s). The first form of the reader looked for a line feed past each apostrophe
to the end of the file and took 28 s on the second; it now looks only up to the closing
quote. All 78 passed on Linux x86_64, Python 3.12.3; the slowest took 6.5 s
(`pdf-page-fonts.pdf`, 6.3 to 6.5 s on `main` as well).

The scalar-boundary follow-up uses a valid YAML sequence for the first input. On macOS
arm64, Python 3.12.13, and PyYAML 6.0.3, that input hit the piece cap in 0.61 s. The
plain-scalar input stayed clean in 0.30 s.
