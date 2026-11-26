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

The independent review below found that the first version of this change opened a hole, and
that `main` already had two. Two declines close them:

- A raw-text start tag (`script`, `style`, `textarea`, `title`, `xmp`, `iframe`, `noembed`,
  `noframes`) inside an svg `desc`. A `desc` is an HTML integration point, like the `title` and
  `foreignObject` the proof already declined, so a browser reads on from such a tag as text to
  its end tag, and the walk does not follow that.
- An svg start tag in which the rules' self-closing pattern (`<svg` up to the first `/>`) ends
  before the tag does, as in `<svg a="/>">`. The rules would count a self-closing svg that a
  browser keeps open.

Both only make the proof decline, which gives the rules their strict test. On 7,980,274
generated documents the final proof declined 41,309 that `5b8ad4d` proved; in 22 of them the
base's narrow test missed what the browser put inside an svg, and the rest are the strict
test's cost. Every other document the base proved is proven the same way.

## Browser comparison

**Verified.** Documents were generated from 33 of the new shapes, 30 svg pieces (handlers,
`foreignObject`, `desc`, `javascript:` links, animations, raw-text tags and their end tags
with a quoted value, `<svg a="/>">`), and 28 page pieces (raw-text elements, comments,
breakout tags, quotes, line breaks). Five runs mix them: 60% of each as a prefix, an svg holding
a mix, its end tag, and a tail, and the rest as a flat run of pieces. A sixth starts every
document with `<p><svg><desc>` and a run of raw-text tags, bogus comments, and quotes. Each
document the new proof accepts, and each the base accepted and the new one declines, was
parsed in Chromium with `DOMParser` and scanned with `doc_svg_active.yar` and
`doc_svg_event_handler.yar` compiled alone, with the scope global true. A miss is a document
where the browser puts a script or `onload`, an `onbegin` or `onerror` on the elements the
rules name, a `javascript:` link that is not a no-op, a `javascript:` animation value, or a
frame, object, embed, or form inside a `foreignObject` under an svg element, and the rule for
it does not fire.

| Run | Unique documents | Proven, base | Proven, new | Newly proven | Declined now | Misses |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Mixed, seed 11 | 1,421,522 | 49,903 | 108,033 | 66,386 | 8,256 | 0 |
| Mixed, seed 12 | 1,422,078 | 49,425 | 107,775 | 66,549 | 8,199 | 0 |
| Mixed, seed 13 | 1,422,171 | 49,775 | 107,881 | 66,413 | 8,307 | 0 |
| Mixed, seed 21 | 1,422,331 | 49,981 | 108,187 | 66,479 | 8,273 | 0 |
| Mixed, seed 22 | 1,422,189 | 49,864 | 107,766 | 66,077 | 8,175 | 0 |
| `desc` prefix, seed 31 | 869,983 | 2,254 | 3,156 | 1,001 | 99 | 0 |
| Total | 7,980,274 | 251,202 | 542,798 | 332,905 | 41,309 | 0 |

In the proven documents the browser put a script or `onload` inside an svg in 125,218, a
handler the event rule names in 14,736, and a link or frame in 7,758, and the rule for each
fired every time. In the newly proven documents the narrow test cleared 39,117
`doc_svg_active` findings, 23,892 `doc_svg_event_handler` findings, and 24,254
`doc_svg_active_link` findings that the strict test gave, and in each the browser put nothing
of that kind inside an svg.

The harness was checked against planted faults in the proof:

| Planted fault | Result |
| --- | --- |
| A math element skipped to any later end tag, with no marker check | 2 misses on a flat run |
| A bogus comment read with no marker check | 0 on a flat run, 8 on a mixed one, such as `</+ x><g><svg></+</+</svg><script>f()</script></svg><g>`: the browser keeps the script inside the svg, and the counts read the commented `</svg>` as its end |
| No decline for a `/>` inside the svg start tag | 14 misses on seed 21 |
| No decline for raw text in `desc` | 0 misses in either generator; the review's documents below are proven and clean with it, and declined with it in place |
| Math allowed inside an svg | 0 misses: in an svg a `math` tag is an svg-namespace element, so a script after it is still inside |

The `desc` fault needs a run of about eight particular pieces, which random choice does not
reach, so its check is the seven documents from the review, kept as rule pairs.

## Rule pairs

Seven pairs are in [`check_rule_pairs.py`](check_rule_pairs.py):

- `doc_svg_active`: the address, text `<`, and math shapes with a script inside the svg
  (fires), beside the `html.vim` shapes (near-miss).
- `doc_svg_active`: a bogus comment before an svg whose group holds a script, beside the same
  svg with the script after it.
- `doc_svg_active`: an svg end tag inside a bogus comment (fires, because the proof declines),
  beside one after the svg has closed.
- `doc_svg_active`: review finding A, a bogus comment inside `<xmp>` inside `desc`, beside a
  `desc` of plain words.
- `doc_svg_active`: review finding B, `<!--` inside `<xmp>` inside `desc`, beside a `desc`
  holding a `b` element.
- `doc_svg_active`: review finding C, `<svg a="/>">`, beside a self-closing `<svg a="x"/>`.
- `doc_svg_event_handler`: an `image` with `onerror` inside an svg after an address element,
  beside an `img`-style tag outside it.

On `5b8ad4d`, three near-misses fired (the two `html.vim`-shaped ones and the `image` one): those
are the false positive. The other four were already clean, because the base proof stops at the
last svg tag or proves them. The fires halves of B and C were clean there: the bypasses on
`main`.

## Installed text

**Verified.** The sweep's `collect` over `/usr/share/doc`, `/usr/lib/python3.12`,
`/usr/lib/python3/dist-packages`, `/usr/share/man`, `/usr/share/perl`, `/usr/share/vim`,
`/usr/include`, `/usr/share/javascript`, `/usr/share/icons`, the locked site-packages, `docs`,
and `web-demo` gave 14,334 files, 4,140 of them `.svg`. Each was scanned in memory with the
bundled rules under the default policy, once with `src` at `5b8ad4d` (a `git worktree`) and once
with the working tree. `sweep_rule_changes.py` itself compares two rule trees under one source
tree, so it cannot see this change; the same collection was scanned through each tree instead.

One file changed findings: `/usr/share/vim/vim91/syntax/html.vim`, block to clean. 77 files
had a finding on the base and 76 now, and no scan was incomplete in either. The sweep was run
again with the two declines in place (`5b579f3`), with the same result: no installed file is
newly held by them. `docs` and `web-demo` were scanned once more through both trees after this
record was written, and none of their 231 files changed findings.

## Timing

The final proof alone, best of three runs, on inputs of up to 1 MiB (it declines anything
larger, or more than 4,096 `<`):

| Input | Proven | Time |
| --- | --- | ---: |
| 4,000 `< ` then an svg | yes | 0.003 s |
| 4,000 `</ x>` then an svg | yes | 0.004 s |
| `</ `, 1 MiB of text, `>`, an svg | yes | 0.001 s |
| 2,000 text-only math elements | yes | 0.003 s |
| 4,000 address elements | yes | 0.006 s |
| An unclosed math element over 1 MiB | no | 0.001 s |
| 1 MiB of prose then an svg | yes | 0.001 s |
| One svg start tag holding 1 MiB of `a="/"` attributes | yes | 0.016 s |
| 1,000 `desc` elements in one svg | yes | 0.002 s |

Each bogus comment and math element is read once to its end, so the walk stays linear.

## Checks

On `5b579f3` (the final code) and `0a86bc6` (with this record), which hold the same `src` and
rules; the same battery passed on the first version, `e5ca3f9`, before the review:

| Check | Result |
| --- | --- |
| `check_rule_pairs.py` | 120 rules passed, with the seven pairs above |
| `probe_match_cap.py` | 3,399 flooded texts over 84 rules, 0 blind spots, 0 fail |
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

A subagent with a fresh context was given the first version's diff, the base checkout, and
Chromium, and asked to make the change wrong. It reported three documents. Each was
reproduced here: scanned with the base and new trees, and parsed in Chromium.

| Finding | On `5b8ad4d` | First version (`e5ca3f9`) | Chromium | Now |
| --- | --- | --- | --- | --- |
| A: `<p><svg><desc><xmp></+</xmp a="></xmp></desc></svg>"><script>void 0</script>`, and two variants with an svg `g` and an `image` `onerror` | Block, advisory: not proven, strict test | Clean: proven | A script, or the handler, inside the svg | Declined, held as on the base |
| B: `<p><svg><desc><xmp><!--</xmp><textarea>--></xmp></desc></svg></textarea><script>void 0</script>` | Clean: proven | Clean | A script inside `svg > desc` | Declined, block |
| C: `<p>x</p><svg a="/>"><script>void 0</script></svg>`, with `image` `onerror` and `javascript:` link variants | Clean: proven | Clean | The svg open, its content inside | Declined, block or advisory |

A was opened by this change: inside `desc` a browser reads `</+` as raw text and the quoted end
tag hides `</svg>`, where the first version read a bogus comment. B and C were open on `main`.
The reviewer also reported that the new shapes agree with the specification in the data state,
that an ISO-2022-JP spelling it tried is caught through the `decoded-charset` view, that no
input of 1 MiB took the proof over 48 ms (an svg start tag of 1 MiB of attributes, 47 ms on the
base), and that it found no document the base proves that the first version did not. Those
reports were not re-run here, apart from the timing table above.

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
- The two declines make the strict test apply to documents `main` read narrowly. On generated
  documents that is 41,309 of 251,202 that the base proved; no installed file is among them,
  which is a count on one machine, not a rate.
- A `desc` that holds a raw-text tag, and any quoted `/>` on an svg start tag, now keeps the
  strict test even when nothing hides an svg tag; those are rare in exported SVG (assessment,
  not measured on a corpus of real pages).
- One file on one machine is not a false-positive rate.
