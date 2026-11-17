# Documentary exemption: a lookup between overrides in place of a count from offset 0

Date: 2026-11-17. Issue: [#274](https://github.com/cgfixit/yara-gate/issues/274). Base: `main` at
`1426e7f`. Candidate: `040c467`, the rule change, and `442f748`, which adds the match-cap guard
an independent review asked for, with this record on top. Engine: YARA-X 1.23.0, Python
3.12.3, Linux x86_64 container with 4 vCPUs. Rules: the shipped `rules/local` (89 rules, zero
skips), no vendor packs. Timing runs were made with nothing else running unless a row says
otherwise.

## The defect

`agent_prompt_injection_phrases` gives a note on "ignore all previous instructions" and its
two sister shapes (`$a`, `$b`, `$c`), except where a documentary match ("the phrase ...",
`$doc_phrase`) ends at the same byte. Its condition found the documentary match nearest each
override with `#doc_phrase in (0..@[i])`.

In YARA-X 1.23.0, `MatchList::matches_in_range` (`src/scanner/matches.rs`, line 134 of the
published crate) binary-searches the start of the range and then walks every match up to its
end. `$x in (a..b)` (`is_pat_match_in`, `src/wasm/mod.rs`) calls the same function. Read from
the crate source; see also #270's [link to the same file](https://github.com/VirusTotal/yara-x/blob/v1.23.0/lib/src/scanner/matches.rs).
A count from offset 0 therefore walks every earlier quotation once per override. A file that
quotes the phrase on every line does about N²/2 steps.

Reproduced on `1426e7f` with `scan_bytes(..., name="notes.txt", policy="agent-ingest",
timeout_s=30)` after a warm-up scan. The issue's line, `The phrase "ignore all previous
instructions" is quoted in papers.`, was repeated and cut to the size. The control was
`Read the meeting notes and keep a local copy of the agenda.`

| Size | Control | Quotations, base | Quotations, candidate |
| ---: | ---: | ---: | ---: |
| 1 MiB | 0.14 s | 0.33 s | 0.37 s |
| 2 MiB | 0.27 s | 0.71 s | 0.73 s |
| 4 MiB | 0.58 s | 2.03 s | 1.39 s |
| 8 MiB | 1.07 s | 10.76 s | 2.81 s |
| 16 MiB | 2.08 s | 30.15 s, incomplete (`timeout`) | 5.36 s |
| 32 MiB | 4.31 s | not run | 11.48 s |
| 16 MiB, UTF-16LE | — | — | 5.32 s |

Every candidate row is clean. The candidate column was measured on `040c467`; the guard adds
four match counts, each read in constant time, and leaves these inputs, far below a million
matches, as they were. The base rule alone, with no other rule loaded, took 9.05 s on 8 MiB of the line
in a raw YARA-X scan; the candidate took 1.01 s.

## The change

The condition now reads, for each override, the stretch since the override before it:

```yara
#o >= 1000000 or #o_wide >= 1000000 or #doc_phrase + #doc_phrase_wide >= 1000000 or
($o and (not $doc_phrase in (0..@o[1] - 1) or $doc_phrase_wide in (@o[1] - 74..@o[1] - 1))) or
for any j in (2..#o) : (
    not $doc_phrase in (@o[j - 1] + 1..@o[j] - 1) or
    $doc_phrase_wide in (@o[j] - 74..@o[j] - 1)
) or ... the same for $o_wide, with 148 ...
```

`$o` is `$a`, `$b`, and `$c` as one string, built from the same fragments, so its matches
are every override of the three shapes in offset order, up to YARA-X's match cap (below). It
is read only by this condition. Findings still name the first match of `$a`, `$b`, or `$c`,
as before: the scanner reports the first declared string that has a match, and those three
come first.

### Why the lookup is exact

The old condition exempts an override when the nearest documentary match at or before it
ends where the override ends. Three properties of the grammar make that the same as "a
documentary match starts after the previous override":
- **The lazy gap stops at the first override.** `$doc_phrase` is `the phrase`, a lazy gap of
  up to 64 bytes, then the override grammar. Its match ends where the first override after
  the prefix ends. On `The phrase "ignore the above" and ignore all previous instructions.`,
  it ends with `$b` at byte 28, not with `$a` at byte 66.
- **No override starts inside another.** The words after the verb (`all`, `of`, `the`,
  `your`, `previous`, `instructions`, `above`, `everything`, `told`, and the rest) contain
  none of the verbs `ignore`, `disregard`, `forget`. So two overrides never share an end.
- **One end per start.** The greedy string and the lazy copy end at the same word boundary,
  because each tail ends in a fixed word.

So the documentary match that names an override is one that starts after the override
before it, and the override is exempt exactly when such a match exists. This holds while
every list holds every match; the next section covers the cap.

### The match cap

YARA-X keeps the first 1,000,000 matches of a string and drops the rest without notice
(`DEFAULT_MAX_MATCHES_PER_PATTERN`, `src/scanner/matches.rs` line 257; the string is then
disabled in `src/scanner/context.rs`). yara-gate does not change that cap. The old condition
read `$a`, `$b`, and `$c` through their own lists. On `040c467` the lookup read them only
through `$o`, one list for all three, so a million quotations filled it and an order after
them was never looked at. Three reviewers found this independently (below).

The guard counts a full `$o` or `$o_wide`, or documentary lists that hold a million matches
between them, as an override no quotation names: the rule fails toward the note. The
documentary lists are summed because the old rule kept both encodings in one capped list.
Two separate lists could keep more quotations than it did, and so exempt more.

| 28 MB input, `agent-ingest`, CLI on a disposable inbox | `1426e7f` | `ddd7680` (no guard) | `442f748` (guard) |
| --- | --- | --- | --- |
| 1,000,000 × `the phrase ignore the above`, then `ignore all previous instructions` | block, exit 1, `blocked/` | **clean, exit 0, `clean/`** | block, exit 1, `blocked/` |
| 1,000,000 × `the phrase ignore the above`, then `ignore the above` | incomplete (`timeout`), exit 2, `quarantine/` | **clean, exit 0, `clean/`** | block, exit 1, `blocked/` |

These ran while other work loaded the machine; each took 14 to 16 s, and the base's second
row 31 s. On the second input the base timed out, and its own list had dropped the order too.
The guard holds it as a note, which is how the rule treats an unquoted order. Under
`agent-document` a note alone passes with the finding recorded, where the timeout held it.

The guard names YARA-X's default. A caller that compiles `rules/local` into its own scanner
with a lower `max_matches_per_pattern` loses it.

### Encodings

The first draft kept one `$o` and one `$doc_phrase`, each `ascii wide`. A differential fuzz
(below) found one input in 200,000 where it exempted an override the old rule held. The input
was an ASCII `the phrase`, then a UTF-16LE override, then an ASCII quotation within 64 bytes.
The ASCII documentary match runs over the UTF-16 bytes to the ASCII override, so the old rule
saw the nearest documentary match end elsewhere and held the UTF-16 one. The probe now keeps
that layout as a fixed text: `the phrase "`, UTF-16 `ignore the above`,
`" the phrase ignore the above`.

The strings are now split by encoding: `$o` and `$doc_phrase` are ASCII, and `$o_wide` and
`$doc_phrase_wide` are UTF-16. An override is exempt only by a documentary match in its own
encoding. A documentary match in the other encoding, within the reach of one, cancels the
exemption.

The reach was measured: the ASCII gap takes up to 64 bytes, and the UTF-16 gap takes up to
64 characters of two bytes with a zero high byte. A CJK character does not fill it. So a
documentary match starts at most 74 bytes, or 148 in UTF-16, before the override it names.

The cancel is stricter than the old rule, never looser. The probe checks each side's cancel
alone and finds it enough. The ASCII side's is also implied by the UTF-16 side's: a UTF-16
documentary match spans only UTF-16 characters, so a nearer UTF-16 quotation always has its own
override before the ASCII one, and that override's check fires. Both are kept, so neither
side's safety rests on that property. Two fixed texts pin the reach each side needs: an ASCII
order at the 64-byte end of a quotation's gap, and a UTF-16 override 40 bytes after the ASCII
prefix.

"One encoding" means where the matches fall, not how a file decodes. Valid UTF-16LE can hold
code units whose bytes spell ASCII: `the phrase ignore the above.  ` read as UTF-16 is CJK
text. An ASCII quotation found there cancels a UTF-16 one within 148 bytes, so the candidate
holds the text and the old rule does not. The probe keeps it as a fixed text.

### Cost of the new strings

| 4 MiB input, this rule alone | Base | Candidate |
| --- | ---: | ---: |
| Meeting notes (no verb) | 0.003 s | 0.003 s |
| Prose with the verbs and no override | 0.281 s | 0.386 s |
| The issue's quotation | 1.821 s | 0.489 s |

The strings without either condition cost 0.94 s and 0.90 s on 8 MiB of quotations. On verb-dense prose the
candidate verifies `$o` and `$o_wide` at every verb; a full `scan_bytes` of that prose took
1.060 s on the base and 1.062 s on the candidate.

## Exactness, checked

[`probe_documentary_exemption.py`](../research/probe_documentary_exemption.py) compiles the
shipped strings with the shipped condition and with the replaced one, keeping the three
exempted strings and the documentary ones. It scans ten fixed texts and then random inert
text built from quotations, orders, their words, padding, and separators (spaces, tabs, line
breaks, CRLF, a blank line, none). Each text is ASCII, UTF-16LE, or chunks of 1 to 30
characters in either encoding, named mixed only when it holds both. Beside the shipped
condition it runs four variants: each cross-encoding cancel removed, and caps of 2 and 3 on
both conditions with the guard rewritten for the cap. It fails on any text in one encoding
where a variant and the old condition differ, and on any text the old condition holds and a
variant does not. CI runs it.

| Run | Texts | Single-encoding texts that differ | Texts the old rule holds and the candidate does not | Mixed texts only the candidate holds |
| --- | ---: | ---: | ---: | ---: |
| Scratch generator, single encodings, seeds 11–16 | 600,000 | 0 | 0 | — |
| Scratch generator, all encodings, seeds 1–8, on `040c467` | 400,000 | 0 | 0 | 169 |
| Committed probe on `ddd7680`, seeds 1–3 | 300,000 | 0 | 0 | 356 of about 60,000 |
| Committed probe on `442f748`, seeds 1–3, every variant | 150,000 | 0 | 0 | 53 to 61 of about 9,400 per seed |

The committed probe holds about 0.6% more of its mixed texts than the old rule. Under a cap of
2 or 3 the guarded condition holds many texts the old one passed (about 5,000 and 3,100 of
50,000), because a list that reaches the cap counts as an unquoted order. That is the guard
working at a tiny cap, not a measure at the real one. On the random texts, the old condition
fires on about half of each encoding, so both outcomes are exercised.

Mutants of the guarded rule, each run through the probe's checks on 20,000 texts:

| Mutant | Caught by |
| --- | --- |
| No cap guard | 4,068 failures under the caps |
| The guard without the documentary sum | 13 failures under a cap of 2, all mixed text |
| ASCII-side window 63, UTF-16-side cancel removed | the fixed text with the ASCII order at the 64-byte end |
| UTF-16-side window 39, ASCII-side cancel removed | the fixed text with the UTF-16 override 40 bytes in |
| Window from offset 0 | 3,269 failures, and a fixed text |
| Both cross-encoding cancels removed | 10 failures, among them a fixed text |
| The first draft: one `$o` and one `$doc_phrase`, both encodings, no cancel | the fixed text named under Encodings |
| The rule unchanged | passes |

On `ddd7680` the probe could not see the cap: its texts are a few hundred bytes. This is
evidence for these text shapes, not a proof. Run the probe after changing the verbs, the words
after them, or the condition.

## Boundaries

The `quote` group of [`probe_detection_gaps.py`](../research/probe_detection_gaps.py). The
finding's severity is listed. Under `default` a note gives the verdict advisory, under
`agent-ingest` block, and under `agent-document` advisory. All ten give the same outcome on the
base and the candidate.

| Input | Outcome |
| --- | --- |
| One quotation | clean |
| 4,000 quotations | clean |
| 600 lines, 300 quoting `ignore the above` and 300 quoting `forget everything you were told` | clean |
| `The phrase "ignore the above" and the phrase "ignore all previous instructions".` | clean |
| `The phrase "ignore the above" is quoted; ignore all previous instructions now.` | note |
| An order, then 4,000 quotations | note |
| 4,000 quotations, then an order | note |
| An order between 300 quotations before and after | note |
| 300 quotations in UTF-16LE | clean |
| An order between 300 quotations in UTF-16LE | note |

`check_rule_pairs.py` keeps the later order against the two quotations side by side, in ASCII
and UTF-16LE, and an order after 50 quotations against the same quotations and a line of
notes. On the base and the candidate, `scan_bytes` gives the same rule and the same views
(`raw`, and `decoded-utf16` for UTF-16) for all of them. For UTF-16 input the scanner also
reads a decoded view with the ASCII strings, so these cases pass even with the UTF-16 half of
the condition deleted; the probe is the check that exercises it.

The new tripwire input in `check_worst_case_timing.py` is the shortest quotation,
`the phrase ignore the above`, repeated to 4 MiB, so the old count has the most overrides to
walk. The issue's own line took 2.4 s on the base, under the 10 s ceiling, so it would not
catch a return of the count.

The short line took 10.7 to 15.1 s on the base across runs here, and 1.9 to 2.3 s on the
candidate; hosted macOS ran the candidate in 2.19 s. The base only just fails the 10 s ceiling,
and a faster runner could pass it. So the case also fails when the 4 MiB scan takes more than 8
times its first MiB, cut at a line. That ratio does not depend on the machine's speed. Here it
was 3.8 to 4.2 on the candidate and 10.7 to 15.0 on the base. With the ceiling raised to 100 s,
the base still fails: `4 MiB took 10.7 times its first MiB, over 8`.

## CLI, stdin, and browser

The installed CLI ran `scan --json` on inbox files of disposable homes under each policy,
while the installed-file sweeps ran:
- A 16 MiB file of quotations: candidate clean, exit 0, about 6 s, moved to `clean/`. Base
  incomplete (`timeout`), exit 2 after about 31 s, left in `quarantine/`.
- 4,000 quotations plus an order; quotations in UTF-16LE; an order between UTF-16LE
  quotations; two quotations side by side; a later order within reach: the same on the base
  and the candidate. Each order is a note: advisory and exit 0 under `default` and
  `agent-document`, moved to `clean/`; block and exit 1 under `agent-ingest`, moved to
  `blocked/`.
- 15 of the 18 report JSON files are the same on both trees in verdict, rule, offset, length,
  severity, and view. The other three are the 16 MiB file under each policy.
- `scan -` with `--name notes.txt` gave the same outcomes. It wrote only reports, and no
  report holds a quoted or matched phrase.

`yara-gate demo --rules <disposable copy>` ran in headless Chromium through Playwright at
1280×900, once with the candidate rules and once with the base rules:
- **Run every pair:** 83 of 83 results matched the reviewed expectation under each of
  `agent-ingest`, `agent-document`, and `default`, on both trees.
- **Pasted text:** 977 quotation lines (65,459 bytes) were clean. 917 quotation lines then
  an order, and an order between 458 quotation lines either side, were held under
  `agent-ingest` with the note. The two quotations side by side were clean, and the later
  order within reach was held. The page and the `/api/scan` response agreed for every paste,
  on both trees, with no page errors.

The CLI and browser runs above used `040c467`. The guard changes only inputs with a million
matches, and the 28 MB rows under "The match cap" ran through the same CLI on `442f748`.

## Independent review

Five reviewers, each with one lens, read `ddd7680`, and a skeptic re-runs each one's findings.
Each finding acted on here was reproduced before it was fixed. The lenses were rule
correctness, YARA-X semantics, the checks and the probe, the claims in this record, and
performance. What came of it:
- **The match cap:** found by the correctness, semantics, and claims reviewers. Confirmed, and
  fixed by the guard.
- **The checks:** the UTF-16 half untested by CI (with it deleted, the rule pairs and the
  `quote` cases still passed), cross-encoding windows that could narrow
  unseen, the first draft caught by one random text, the timing case's thin margin, and texts
  called mixed that held one encoding. Each is fixed above.
- **The wording:** a "64 characters" claim where the gap is 64 bytes, miscounted table rows,
  and an overstated share. Each is corrected here and in `docs/rules.md`.

The run was cut short by a container restart. The skeptics had confirmed every finding of the
correctness, semantics, and checks lenses. The claims reviewer's findings were reproduced here
instead, and the performance reviewer did not report. In its place, these 4 MiB shapes were
timed with this rule alone on `442f748` against `1426e7f`, on an idle machine:

| 4 MiB shape | `1426e7f` | `442f748` |
| --- | ---: | ---: |
| `the phrase ` repeated, with no order | 0.64 s, clean | 0.66 s, clean |
| Five prefixes per quotation line | 12.74 s, clean | 0.83 s, clean |
| ASCII and UTF-16 quotation lines in turn | 5.10 s, clean | 0.59 s, note |
| Orders only | 0.73 s, note | 1.02 s, note |
| 200 spaces before the line break inside each quotation | 2.18 s, clean | 2.92 s, clean |

The third row is the cross-encoding cancel described under Encodings: each UTF-16 quotation
sits within 148 bytes of an ASCII one. The last two rows are the cost of `$o` and `$o_wide`.

## Installed files and precision

`sweep_rule_changes.py`, base rules against the candidate's:

| Roots | Files | Changed | Hits before and after |
| --- | ---: | ---: | ---: |
| This checkout: `docs`, `src`, `tests`, `web-demo`, `rules`, `scripts`, against `HEAD` | 251 | 0 | 322 (53 of this rule) |
| The same with the root Markdown files, against `1426e7f`, on `ddd7680` and on `442f748` | 257 | 0 | 329 (57 of this rule) |
| `/usr/lib/python3.12`, `/usr/share/doc`, against `1426e7f`, on `442f748` | 573 | 0 | 0 |
| `/opt/node-tools`, `/opt/google-cloud-sdk`, the locked `.venv` (thinned to the cap) | 20,000 | 0 | 41 |

The sweep reads files of at most 512 KiB, which cannot hold a million matches, so the guard
cannot change these rows. The checkout's own documentation quotes these phrases on purpose:
67 of its 257 files contain "the phrase", and this rule fires on 57. `measure_precision.py
--fail-over` gave the same result on `040c467` and on `442f748`: 328 files, none incomplete, 85
of 89 rules with no hit, and the same four Windows shortcut-family collisions. This rule hit
nothing.

## What was run

On `442f748` unless a row says otherwise:

| Check | Result |
| --- | --- |
| `generate_rules.py --check`, `lint_rules.py`, `check_rule_generator.py` | 4 generated files current; 89 rules; 22 generator checks |
| `check_rule_pairs.py`, `check_added_rules.py` | 120 rules; 246 plus 4 vendor-override cases |
| `probe_detection_gaps.py --verify` | 748 ok, with the ten `quote` cases; B3 and B5 open, as on `main` |
| `probe_rule_coverage.py --verify` | Passed: 617 library, 55 CLI, and 9 benign observations |
| `check_worst_case_timing.py` | PASS, 96 inputs |
| `record_pages_demo.py --baseline` | Outcomes match for 84 scenarios × 3 policies; only provenance changed |
| `probe_documentary_exemption.py` | 0 fail, as above |
| actionlint 1.7.12 and `zizmor --offline --pedantic` on the CI change | Clean |
| `ruff check .`, `ruff format --check .`, `check_text_controls.py`, `check_doc_links.py` | Clean |

Hosted CI is recorded on the pull request.

## Not established

- **Dense matches still cost.** 99 MiB of the issue's line, under the 100 MiB intake limit, was
  incomplete (`timeout`) after 31.0 s on an idle machine, while 99 MiB of the control was clean
  in 13.1 s. Under load, a reviewer measured 80 MiB clean in 28.2 s. The limit is somewhere
  between those sizes and moves with load. What remains is the cost of matching. This rule's
  strings alone take about 0.12 s per MiB of the line, and a full scan pays about 0.2 s per
  MiB more than the control. Any text dense with these phrases pays it, quoted or not, and
  this change did not alter it. Such a file is held as incomplete, which fails closed. Past a
  million overrides the guard decides first, if the scan finishes.
- **Mixed encodings are held more often.** About 0.6% of the probe's mixed texts are held by
  the candidate and not by the old rule. So is UTF-16 text whose code units also spell an ASCII
  quotation. Real files rarely place ASCII and UTF-16 matches within 148 bytes of each other.
- **The reported offset can name a quotation.** A finding names the first `$a` match, which may
  be a quotation the exemption covers, while the order that made the rule fire sits later.
  For 917 quotation lines then an order, both trees report offset 12. This change does not
  alter it.
- **Other rules and the cap.** Any rule whose condition reads a list that can fill silently
  may lose a match past a million, as `$o` did. This change guards only this rule.
- **macOS was not run here.** The issue's numbers came from a Mac under shared load; this
  record's came from Linux. Hosted macOS runs the tripwire and the probe.
