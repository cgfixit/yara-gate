# Detection scope and budgets — November 7, 2026

Phase 1 of the follow-up to [#183](https://github.com/cgfixit/yara-gate/issues/183) and the
[November 7 detection review](../reviews/2026-11-07-detection-review.md): one block-tier false
positive, two silent coverage limits, and a deadline overrun, each reproduced on
`origin/main` at `7d505f911a6f7ab34dc0a8a150c2059869eafef9` before the change. Source revision
of the change: `7fec32be03e65b0b60c1ff3ea5b0d127a9e52c60`. Python 3.12, YARA-X 1.23.0, 85 bundled
rules, zero skips, no vendor bodies, disposable rule copies. No input was executed or fetched.

## Changes

| Change | Before (main) | After |
| --- | --- | --- |
| `doc_svg_active` scope | Any `<svg` anywhere plus any `<script` or `onload=` anywhere blocks | In an SVG document (`.svg`/`.svgz` name, or an `<svg>` root after an optional BOM, XML declaration, comments, doctype) unchanged; elsewhere the script or handler must sit inside an `<svg>` element |
| `doc_svg_event_handler` scope | An HTML `<image onerror>` outside SVG is advisory | Same scope test; an HTML parser reads that tag as `<img>` |
| MCP walk | Silently stops at list item 50 and depth 8; clean | Every element up to 2,000,000 nodes and 64 levels; past that, or past `json.loads` nesting, incomplete (`mcp json exceeds walk limit`) when the JSON names `command`, `args`, or `description` or escapes a key |
| CMap parse | Lazy `begin…end` search per section; budget checked between sections only | One linear pass, deadline checked every 4,096 lexemes; over 1,048,576 tokens is incomplete (`pdf cmap exceeds token limit`) |
| `scan_bytes` name | `C:\Users\…\notes.txt` kept whole on POSIX | Last component of either separator (`notes.txt`) |

The scope test counts `<svg` start tags against `</svg>` end tags plus self-closing
`<svg …/>` tags before each match (YARA-X `#a in (0..@b[i])`). Those counts are linear in the
match list, so the loop is quadratic: unbounded, 4 MiB floods took 30–60 s and some ended
incomplete. More than 1,024 matches of any scope pattern therefore keeps the strict test, which
is the old condition: a flood can neither hide a script nor slow the rule.

## Reproductions

SVG, 18 synthetic inputs (library, `default` policy):

| Input | Main | Change |
| --- | --- | --- |
| HTML: inline icon + unrelated `<script>` | block | clean |
| HTML: `<body onload>` + inline icon | block | clean |
| Markdown: inline icon + fenced `<script>` sample | block | clean |
| HTML: `<svg/>` + unrelated `<script>` | block | clean |
| HTML: icon + `<image onerror>` outside SVG | advisory | clean |
| HTML `<img onerror>` | clean | clean |
| HTML: script in SVG, nested SVG then script, `<svg onload>`, `<svg/onload=…>`, `<image onload>` in SVG | block | block |
| HTML: `<image onerror>`, `<svg onerror/>`, `<animate onbegin>` in SVG | advisory | advisory |
| `.svg` with script, with trailing script, with `onload`; `.bin` with an `<svg>` root and trailing script | block | block |

Flood timing at 4 MiB (`p.html`), main rules → changed rules: SVG then scripts 1.50 → 1.55 s;
`</svg>` then scripts 5.91 → 5.79 s; interleaved 0.98 → 1.22 s; `onload` flood 1.29 → 1.59 s;
self-closing, `onerror`, and `onbegin` floods 1.45/0.99/0.94 → 2.01/1.33/0.98 s. Verdicts are
identical; the last three stop at the existing `text pieces exceed 100000` limit on both. Just
under the cap, with every loop running to its end, a 4 MiB page takes 0.65 s and is clean.

MCP, an inert `{"command":"bash","args":["-c","echo inert"]}` entry, both agent policies:

| Placement | Main | Change |
| --- | --- | --- |
| List item 50 | advisory / block | advisory / block |
| List item 51, item 5,001 | clean / clean | advisory / block |
| Depth 7 | advisory / block | advisory / block |
| Depth 9; hidden description at depth 40 | clean / clean | advisory / block |
| Depth 80 (past 64) | clean | incomplete |
| 20,000-row ordinary list; 60-deep ordinary object | clean | clean |
| `[` × 100,000 (no MCP key) | incomplete (`content scan failed`, uncaught `RecursionError`) | clean |

A 17 MB ordinary JSON file of 2.2 million nodes took 3.28 s on main and 3.82 s here, clean on both.

CMap, a one-page PDF whose ToUnicode stream decodes to 4 MiB (`timeout_s=5`):

| Stream | Main | Change |
| --- | --- | --- |
| `beginbfchar ` repeated, never ended | killed at 300 s | 0.36 s, advisory (`heuristic_pdf_text_unmapped`) |
| One section of `<0>` tokens | 1.83 s, clean, 94 MiB RSS | 1.04 s, incomplete, 81 MiB RSS |
| One `bfrange` of `<00><FF>[` triples | 1.07 s, clean | 0.89 s, incomplete |
| A valid map | 0.05 s | 0.05 s |

The new tripwire case `pdf-cmap-sections.pdf` (4 MiB, unfiltered stream) ran past 120 s on main's
code and takes 0.60 s here. Equivalence: 50,000 random CMaps built from keywords, tokens,
brackets, and fragments produced identical mappings and code lengths from the old and new
parsers; in 1,063 of them both raised the same exception.

## Checks

- `probe_detection_gaps.py --verify`: 210 ok, no FAIL, STALE, or open (204 on main, plus six cases
  added here: two `#183.1` SVG and four `#183.6` MCP).
- `check_rule_pairs.py`: passed (115 rules; two scoped-SVG pairs added).
  `check_added_rules.py`: passed (192 plus 4 vendor-override cases; twelve scope cases added).
- `measure_precision.py --fail-over`: 324 files, 0 incomplete, identical to main; both SVG rules 0.
- Host sweep, main code and rules against this change: 15,140 files under `/usr`, `/opt`, `/root`,
  and `/home` (381 HTML, 5,633 SVG, 1,721 Markdown, 5,187 JSON, 2,216 XML, 2 PDF, ≤ 2 MiB):
  0 changed verdicts or findings (14,903 clean, 235 advisory, 2 block on both).
- `check_worst_case_timing.py`: 26 inputs of exactly 4 MiB passed (two added:
  `svg-scope-cap.html` 0.65 s, `pdf-cmap-sections.pdf` 0.60 s); slowest 6.0 s.
- `record_pages_demo.py --baseline web-demo/recordings.json`: 49 scenarios × 3 policies match the
  reviewed outcomes; only provenance refreshed.
- `probe_rule_coverage.py --verify`: passed. Focused tests for MCP position, depth, and limits; CMap
  sections, linear time, and the token cap; and `scan_bytes` names: passed.
- Ruff check and format, `mypy --strict src`, `check_text_controls.py`, `lint_rules.py`: passed.

## Boundaries

- A lexical scope test cannot tell a tag in prose from markup. This repository's own
  `docs/verification/2026-11-06-detection-gaps.md` names an unclosed `<svg>` and later a
  `<script>` in prose, and blocks on main and here alike.
- Comments or CDATA holding `</svg>` inside an SVG close it early for the scope test. This only
  matters outside an SVG document, where a page can run the same script outside the SVG and no
  rule blocks it; inside an SVG document every script still blocks.
- A `bfrange` whose target overflows its byte width raises inside `_cmap_ranges`, before and
  after this change, so the PDF is incomplete (`content scan failed`). That holds rather than
  passes, but holds a malformed font for an avoidable reason; it is left for a separate change.
- The SVG false positives are measured on synthetic pages; the host sweep had no page with the
  pattern. Production false-positive rates were not measured.
