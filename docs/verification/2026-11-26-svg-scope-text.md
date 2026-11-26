# Text a browser reads as text, and the SVG scope proof (2026-11-26)

Source: `main` at `5b8ad4d`, branch `claude/serene-brown-qb93an`. Linux x86_64 (4 cores),
Python 3.12, YARA-X 1.24.0, 89 compiled local rules, no vendor packs, Chromium from the
preinstalled Playwright. One function changes: `svg_scope_proven` in `content.py`. No rule
file, rule id, severity, policy, or view changes.

## The false positive

**Verified** with `probe_candidate.py` on `5b8ad4d`. Vim's `syntax/html.vim` (19,493 bytes) is
a block under every policy, `doc_svg_active` on `raw`, `html-unescaped`, and `text-folded`. The
control, `<html><body><p>x</p><svg><script>void 0</script></svg></body></html>`, is a block too.

The file names `start="<svg>"  end="</svg>"` in one syntax region and `<script` in others.
`doc_svg_active` blocks a script inside an svg element, and outside an SVG document it reads
"inside" from counts of svg start and end tags before the script, but only when
`svg_scope_proven` says the file's tags can be read that way. For this file the proof gave up
at the first `<`, which opens a maintainer's address (`<dougkearns@gmail.com>`), so the rule
kept its strict test: any `<svg` and any `<script` block.

Before its `<svg>` the file holds 13 `<` bytes that the proof did not read:

| Bytes | How the WHATWG tokenizer reads them |
| --- | --- |
| Three mail addresses, `<name@host>` | A start tag: the tag name runs to white space, `/`, or `>`, so `@` and `.` are part of it |
| `<>`, `<[`, `<\s`, `<"`, `<\%(` | Text: `<` before anything but a letter, `/`, `!`, or `?` is emitted as a character |
| `</+ … >`, `</\s* … >` | A bogus comment: `</` before anything but a letter or `>` opens one, and the next `>` closes it |
| `<math>" end="</math>` | A MathML element holding only text, closed by its end tag |

**Sourced, read** (`html.spec.whatwg.org/multipage/parsing.html`, fetched November 26): the
bogus comment state ends at `>` or the end of the input. **Sourced, located** on the same
page, read only as a summary: the tag open state (a letter opens a tag, `/` an end tag, `!` a
markup declaration, `?` a processing instruction, anything else is text), the end tag open
state (a letter opens a tag, `>` is dropped, anything else opens a bogus comment), the tag name
state (white space, `/`, or `>` ends the name; any other byte is part of it), and the foreign
content rules. The browser runs below are what checks those readings. **Verified** in
Chromium: with `DOMParser` the file's svg element holds only text, and its script elements lie
outside it.

## The change

The proof follows the tokenizer for those four shapes and still declines everything else:

- A `<` before any byte other than an ASCII letter, `/`, `!`, or `?` is text.
- `</` before any byte other than a letter or `>` is a bogus comment to the next `>`. If an
  svg tag lies inside it the proof declines, since the rules would count that tag.
- A tag name is any run of bytes other than white space, `/`, `>`, `<`, and NUL, up to 64. A
  name holding `<` or NUL still declines. A name that only starts with `svg` (`<svg@x>`)
  declines too, as before: the rules count it as an svg tag and a browser does not.
- `<math>` outside an svg, whose next `<` opens `</math>`, is skipped to its end tag. A math
  element that holds a tag, sits inside an svg, closes itself, or holds an svg tag declines.

Everything the base proof accepted, it accepts the same way: on 4.2 million generated
documents no document went from proven to not proven.

## Browser comparison

**Verified.** Documents were generated from 33 of the new shapes, 17 svg pieces (handlers,
`foreignObject`, `javascript:` links, animations), and 28 page pieces (raw-text elements,
comments, breakout tags, quotes, line breaks); 60% of them as a prefix, an svg holding a mix,
its end tag, and a tail. Each document the new proof accepts was parsed in Chromium with
`DOMParser` and scanned with `doc_svg_active.yar` and `doc_svg_event_handler.yar` compiled
alone, with the scope global true. A miss is a document where the browser puts a script or
`onload`, an `onbegin` or `onerror` on the elements the rules name, a `javascript:` link that is
not a no-op, a `javascript:` animation value, or a frame, object, embed, or form inside a
`foreignObject` under an svg element, and the rule for it does not fire.

| Run | Unique documents | Proven, base | Proven, new | Newly proven | Misses |
| --- | ---: | ---: | ---: | ---: | ---: |
| Flat mix, seed 1 | 367,623 | 7,346 | 16,930 | 9,584 | 0 |
| Structured, seed 11 | 1,415,053 | 48,067 | 127,070 | 79,003 | 0 |
| Structured, seed 12 | 1,415,124 | 47,804 | 126,838 | 79,034 | 0 |
| Structured, seed 13 | 1,415,144 | 48,032 | 126,794 | 78,762 | 0 |

Across the three structured runs the browser put a script or `onload` inside an svg in 83,752
proven documents, a handler the event rule names in 17,559, and a link or frame in 9,200, and
the rule for each fired every time. In the newly proven documents the narrow test cleared
29,257 `doc_svg_active` findings, 30,624 `doc_svg_event_handler` findings, and 31,434
`doc_svg_active_link` findings that the strict test gave, and in each the browser put nothing
of that kind inside an svg.

The harness was checked against planted faults in the proof. A math element skipped to any
later end tag, without the marker check, gave two misses on the flat seed. A bogus comment
read without its marker check gave none on the flat seed and eight on a structured one, for
example `</+ x><g><svg></+</+</svg><script>f()</script></svg><g>`: the browser keeps the
script inside the svg, and the counts read the commented `</svg>` as its end. Allowing
math inside an svg gave no miss; in an svg a `math` tag is an svg-namespace element, so a
script after it is still inside.

## Rule pairs

Four pairs are in [`check_rule_pairs.py`](check_rule_pairs.py): the address, text `<`, and
math shapes with a script inside the svg (fires) beside the `html.vim` shapes (near-miss); a
bogus comment before an svg whose group holds a script, beside the same svg with the script
after it; an svg end tag inside a bogus comment (fires, because the proof declines), beside
one after the svg has closed; and an `image` with `onerror` inside an svg after an address
element, beside an `img`-style tag outside it. Three of the four near-misses fired on
`5b8ad4d`; the fourth was already proven there, because the base proof stops at the last svg
tag and never reads the comment after it.

## Installed text

**Verified.** The sweep's `collect` over `/usr/share/doc`, `/usr/lib/python3.12`,
`/usr/lib/python3/dist-packages`, `/usr/share/man`, `/usr/share/perl`, `/usr/share/vim`,
`/usr/include`, `/usr/share/javascript`, `/usr/share/icons`, the locked site-packages, `docs`,
and `web-demo` gave 14,334 files, 4,140 of them `.svg`. Each was scanned in memory with the
bundled rules under the default policy, once with `src` at `5b8ad4d` (a `git worktree`) and once
with the working tree. `sweep_rule_changes.py` itself compares two rule trees under one source
tree, so it cannot see this change; the same collection was scanned through each tree instead.

One file changed findings: `/usr/share/vim/vim91/syntax/html.vim`, block to clean. 77 files
had a finding on the base and 76 now, and no scan was incomplete in either.

## Timing

One run each, the proof alone, on inputs of up to 1 MiB (it declines anything larger, or
more than 4,096 `<`):

| Input | Proven | Time |
| --- | --- | ---: |
| 4,000 `< ` then an svg | yes | 0.003 s |
| 4,000 `</ x>` then an svg | yes | 0.004 s |
| `</ `, 1 MiB of text, `>`, an svg | yes | 0.001 s |
| 2,000 text-only math elements | yes | 0.003 s |
| 4,000 address elements | yes | 0.006 s |
| An unclosed math element over 1 MiB | no | 0.001 s |
| 1 MiB of prose then an svg | yes | 0.001 s |

Each bogus comment and math element is read once to its end, so the walk stays linear.

## Checks

On `e5ca3f9` (the change) and `a2153b9` (with this record), which hold the same `src` and
rules:

| Check | Result |
| --- | --- |
| `check_rule_pairs.py` | 120 rules passed, with the four pairs above |
| `probe_match_cap.py` | 3,331 flooded texts over 84 rules, 0 blind spots, 0 fail |
| `check_added_rules.py` | 271 plus 4 vendor-override cases |
| `measure_precision.py --fail-over` (328 files) | exit 0, 0 incomplete |
| `probe_rule_coverage.py --verify` | passed |
| `probe_detection_gaps.py --verify` | exit 0 |
| `check_worst_case_timing.py` | 106 adversarial inputs of 4 MiB, pass |
| `check_scan_only.py`, `check_intake.py` | passed |
| `check_rule_generator.py`, `check_rules_lock.py`, `uv lock --check` | passed |
| `yara-gate selftest` | pass |
| `yara-gate conform`, `build_conformance.py --check` | 98 fixtures, 294 checks, 0 changes; manifest current |
| `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | 97 scenarios x 3 policies, outcomes match the baseline |
| `check_text_controls.py`, `check_doc_links.py`, `zizmor --offline --pedantic` | passed |
| Ruff, `ruff format --check`, `mypy --strict src scripts` | passed |

No catalog fixture moves, so neither the conformance manifest nor the demo recordings change.

## Independent attempt to break it

REVIEW

## What this does not show

- Of the specification, only the bogus comment state was read word for word; the other
  states were located in a summary. The browser runs are the check, and they cover Chromium's
  parser only: Firefox and WebKit were not run.
- `DOMParser` parses with scripting off. The proof already declines `noscript`, the one
  element whose parsing that flag changes.
- A file served as XML (`.xhtml`) is parsed by an XML parser, which stops at the first of
  these shapes; nothing after that point is shown or run.
- `textprop.txt`, `dpkg-scansources`, and `CORE.pod` (`agent_role_spoof_action`) and
  `oletools/msodde.py` (`heuristic_ooxml_dde`) are untouched.
- One file on one machine is not a false-positive rate.
