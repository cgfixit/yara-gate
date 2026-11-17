# Documentary exemption: a lookup between overrides in place of a count from offset 0

Date: 2026-11-17. Issue: [#274](https://github.com/cgfixit/yara-gate/issues/274). Base: `main` at
`1426e7f`. Candidate: `040c467`, the rule change, with this record on top. Engine: YARA-X
1.23.0, Python 3.12.3, Linux x86_64 container with 4 vCPUs. Rules: the shipped `rules/local`
(89 rules, zero skips), no vendor packs. Timing runs were made with nothing else running
unless a row says otherwise.

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

Every candidate row is clean. The base rule alone, with no other rule loaded, took 9.05 s on
8 MiB of the line in a raw YARA-X scan; the candidate took 1.01 s.

## The change

The condition now reads, for each override, the stretch since the override before it:

```yara
($o and (not $doc_phrase in (0..@o[1] - 1) or $doc_phrase_wide in (@o[1] - 74..@o[1] - 1))) or
for any j in (2..#o) : (
    not $doc_phrase in (@o[j - 1] + 1..@o[j] - 1) or
    $doc_phrase_wide in (@o[j] - 74..@o[j] - 1)
) or ... the same for $o_wide, with 148 ...
```

`$o` is `$a`, `$b`, and `$c` as one string, built from the same fragments, so its matches
are every override of the three shapes in offset order. It is read only by this condition.
Findings still name the first match of `$a`, `$b`, or `$c`, as before: the scanner reports
the first declared string that has a match, and those three come first.

### Why the lookup is exact

The old condition exempts an override when the nearest documentary match at or before it
ends where the override ends. Three properties of the grammar make that the same as "a
documentary match starts after the previous override":
- **The lazy gap stops at the first override.** `$doc_phrase` is `the phrase`, a lazy gap of
  up to 64 characters, then the override grammar. Its match ends where the first override
  after the prefix ends. On `The phrase "ignore the above" and ignore all previous
  instructions.`, it ends with `$b` at byte 28, not with `$a` at byte 66.
- **No override starts inside another.** The words after the verb (`all`, `of`, `the`,
  `your`, `previous`, `instructions`, `above`, `everything`, `told`, and the rest) contain
  none of the verbs `ignore`, `disregard`, `forget`. So two overrides never share an end.
- **One end per start.** The greedy string and the lazy copy end at the same word boundary,
  because each tail ends in a fixed word.

So the documentary match that names an override is one that starts after the override
before it, and the override is exempt exactly when such a match exists.

### Encodings

The first draft kept one `$o` and one `$doc_phrase`, each `ascii wide`. A differential fuzz
(below) found one input in 200,000 where it exempted an override the old rule held: an ASCII
`the phrase`, then a UTF-16LE override, then an ASCII quotation within 64 bytes. The ASCII
documentary match runs over the UTF-16 bytes to the ASCII override, so the old rule saw the
nearest documentary match end elsewhere and held the UTF-16 one.

The strings are now split by encoding: `$o` and `$doc_phrase` are ASCII, and `$o_wide` and
`$doc_phrase_wide` are UTF-16. An override is exempt only by a documentary match in its own
encoding. A documentary match in the other encoding, within the reach of one, cancels the
exemption.

The reach was measured: the ASCII gap takes up to 64 bytes, and the UTF-16 gap takes up to
64 characters of two bytes with a zero high byte. A CJK character does not fill it. So a
documentary match starts at most 74 bytes, or 148 in UTF-16, before the override it names.

The cancel is stricter than the old rule, never looser. Each side's check alone is enough for
that. The ASCII side's is also implied by the UTF-16 side's: a UTF-16 documentary match
spans only UTF-16 characters, so a nearer UTF-16 quotation always has its own override before
the ASCII one, and that override's check fires. Both are kept, so neither side's safety rests
on that property.

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
exempted strings and the documentary ones. It scans six fixed texts and then random inert
text built from quotations, orders, their words, padding, and separators (spaces, tabs, line
breaks, CRLF, a blank line, none). Each text is ASCII, UTF-16LE, or chunks of 1 to 30
characters in either encoding.

| Run | Texts | Single-encoding texts that differ | Mixed texts the old rule holds and the candidate does not | Mixed texts only the candidate holds |
| --- | ---: | ---: | ---: | ---: |
| Scratch generator, single encodings, seeds 11–16 | 600,000 | 0 | — | — |
| Scratch generator, all encodings, seeds 1–8 | 400,000 | 0 | 0 | 169 |
| Committed probe, seeds 1–3, before the fixed texts | 300,000 | 0 | 0 | 356 |
| Committed probe, default | 6 + 50,000 | 0 | 0 | 59 |

On the random texts, the old condition fires on about half of each encoding, so both outcomes
are exercised.

Mutants, each run through the committed probe:
- **Window from offset 0** in place of the previous override: caught, 2,876 failures in 20,000
  texts and on a fixed text.
- **Both cross-encoding checks removed**, the unsafe first draft: caught on the fixed mixed
  text.
- **The ASCII-side check alone removed**: not caught, as the property above predicts.

This is evidence for these text shapes, not a proof. Run the probe after changing the verbs,
the words after them, or the condition.

## Boundaries

The `quote` group of [`probe_detection_gaps.py`](../research/probe_detection_gaps.py). The
`default` outcome is listed; each order is block under `agent-ingest` and advisory under
`agent-document`. All ten give the same outcome on the base and the candidate.

| Input | Outcome |
| --- | --- |
| One quotation | clean |
| 4,000 quotations | clean |
| 300 lines quoting `ignore the above` and `forget everything you were told` | clean |
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
(`raw`, and `decoded-utf16` for UTF-16) for all of them.

The new tripwire input in `check_worst_case_timing.py` is the shortest quotation,
`the phrase ignore the above`, repeated to 4 MiB, so the old count has the most overrides to
walk. The issue's own line took 2.4 s on the base, under the 10 s ceiling, so it would not
catch a return of the count. The short line took 15.1 s on the base, failing the check, and
1.9 s on the candidate.

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

## Installed files and precision

`sweep_rule_changes.py` against `HEAD`:

| Roots | Files | Changed | Hits before and after |
| --- | ---: | ---: | ---: |
| This checkout: `docs`, `src`, `tests`, `web-demo`, `rules`, `scripts` | 251 | 0 | 322 (53 of this rule) |
| `/usr/lib/python3.12`, `/usr/share/doc` | 573 | 0 | 0 |
| `/opt/node-tools`, `/opt/google-cloud-sdk`, the locked `.venv` (thinned to the cap) | 20,000 | 0 | 41 |

The checkout's own documentation quotes these phrases on purpose; 57 of its files contain "the
phrase". `measure_precision.py --fail-over`: 328 files, none incomplete, 85 of 89 rules with
no hit, and the same four Windows shortcut-family collisions; this rule hit nothing.

## What was run

| Check | Result |
| --- | --- |
| `generate_rules.py --check`, `lint_rules.py`, `check_rule_generator.py` | 4 generated files current; 89 rules; 22 generator checks |
| `check_rule_pairs.py`, `check_added_rules.py` | 120 rules; 246 plus 4 vendor-override cases |
| `probe_detection_gaps.py --verify` | 748 ok, with the ten `quote` cases; B3 and B5 open, as on `main` |
| `probe_rule_coverage.py --verify` | Passed: 617 library, 55 CLI, and 9 benign observations |
| `check_worst_case_timing.py` | PASS, 96 inputs; `doc-quotations.txt` clean in 2.0 s while the sweeps ran |
| `record_pages_demo.py --baseline` at `040c467` | Outcomes match for 84 scenarios × 3 policies; only provenance changed |
| `probe_documentary_exemption.py` | 0 fail, as above |
| `ruff check .`, `ruff format --check .`, `check_text_controls.py`, `check_doc_links.py` | Clean |

Hosted CI is recorded on the pull request.

## Not established

- **Dense matches still cost.** 99 MiB of the issue's line, under the 100 MiB intake limit, was
  incomplete (`timeout`) after 31.0 s, while 99 MiB of the control was clean in 13.1 s. That
  run used the candidate before a comment-only edit. What remains is the strings themselves,
  about 0.12 s per MiB of this line in this container. Any text dense with these phrases pays
  it, quoted or not, and this change did not alter it. Such a file is held as incomplete,
  which fails closed.
- **Mixed encodings are held more often.** About 0.1 to 0.6% of the probe's mixed texts are
  held by the candidate and not by the old rule. Real files are rarely ASCII and UTF-16 within
  148 bytes of each other.
- **The reported offset can name a quotation.** A finding names the first `$a` match, which may
  be a quotation the exemption covers, while the order that made the rule fire sits later.
  For 917 quotation lines then an order, both trees report offset 12. This change does not
  alter it.
- **macOS was not run here.** The issue's numbers came from a Mac under shared load; this
  record's came from Linux.
