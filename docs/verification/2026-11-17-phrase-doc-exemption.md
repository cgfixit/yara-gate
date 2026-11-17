# Phrase-rule quotations: a linear exemption that keeps the old answer

Date: 2026-11-17. Base: `main` at `1426e7f`. Engine: YARA-X 1.23.0, Python 3.12.3, Linux
container with 4 CPUs. Rules: the shipped `rules/local` (89 rules), no vendor packs. Issue:
[#274](https://github.com/cgfixit/yara-gate/issues/274).

## The defect

`agent_prompt_injection_phrases` lets a quotation ("the phrase 'ignore all previous
instructions'") cover the order it ends with. For every order match, the condition counted
the quotations from the start of the unit to find the nearest one
(`#doc_phrase in (0..@[i])`). That is quadratic in the number of quotations. The issue's line,
repeated, on `1426e7f`, through `scan_bytes` under `agent-ingest` (load average 0.04):

| Size | `main` | This change |
| ---: | --- | --- |
| 1 MiB | clean, 0.40 s | clean, 0.37 s |
| 4 MiB | clean, 2.53 s | clean, 1.36 s |
| 8 MiB | clean, 11.34 s | clean, 2.80 s |
| 16 MiB | incomplete (`timeout`), 29.68 s | clean, 5.41 s |
| 32 MiB | incomplete (`timeout`), 29.96 s | clean, 10.96 s |
| 64 MiB | not run | clean, 22.35 s, before the guard; a note since (below) |

The line is `The phrase "ignore all previous instructions" is quoted in papers.` An unquoted
order repeated to the same sizes (`Ignore all previous instructions.`) blocks at every size on
this change, in 0.44 s at 1 MiB and 27.19 s at 64 MiB. That cost is the matching itself, not
the exemption.

The 64 MiB row was measured before the match-limit guard below. 64 MiB of this 67-byte line
is 1,001,624 quotations, past YARA-X's 1,000,000-match limit, so the guard now reports the
note. Rechecked on `747218d` with `scan_bytes` (load under 0.9, about 19 s each,
[#285](https://github.com/cgfixit/yara-gate/issues/285)):

| Size | Quotations | `default` | `agent-ingest` | `agent-document` |
| ---: | ---: | --- | --- | --- |
| 63 MiB | 985,974 | clean | clean | clean |
| 64 MiB | 1,001,624 | advisory (note) | block (note) | advisory (note) |

Through the CLI, 16 MiB of the line dropped into a disposable inbox under `agent-ingest` was
incomplete with exit 2 on `main` and stayed in `quarantine/` (30.7 s). On this change it is
clean with exit 0 and moves to `clean/` (6.1 s). The same 1,000 quotations followed by one
unquoted order block with exit 1 and move to `blocked/` on both.

## The change

An order now fires when it starts in one of these places:
- before the first quotation;
- after the last quotation ends;
- between where one quotation ends and the next begins.

Each test is a range lookup on the ordered match lists, the same approach
[#270](2026-11-16-code-relay-timing.md) took for code-relay refusals. Only
`rules/templates/agent_prompt_injection_phrases.yar.tmpl` was edited, and
`scripts/generate_rules.py` regenerated the rule file.

This gives the counting condition's answer because of three properties of the strings:
1. An order starts only at `ignore`, `disregard`, or `forget`, and no later word of an order
   is one of those. So no order starts inside another, and each start has one end.
2. A quotation's skip is lazy and stops at the first order within 64 characters. So inside a
   quotation's own span, the only order in the quotation's encoding is the one it quotes,
   and that order ends where the quotation ends.
3. A UTF-16 quotation is two-byte characters throughout, so no ASCII order starts inside it.

The exception is a UTF-16 order inside an ASCII quotation's skip. The counting condition
fired on it, because it does not end where the quotation ends. To keep that answer, the three
order strings were split into ASCII copies and UTF-16 (`wide`) copies. From an ASCII
quotation, recognized because its second byte is not zero, a UTF-16 order anywhere in the
gap counts. This is a crafted case, but without the split the change would have exempted it.

## The answers are the same

[`probe_phrase_doc_exemption.py`](../research/probe_phrase_doc_exemption.py) compiles two
rules that hold only the order strings and the quotation string: the shipped exemption, and
the counting condition over the original `ascii wide` strings. The rule's other strings
would fire alike in both and hide a difference. It scans random inert messages and fails on
any message where the two disagree. A message is built from these parts:
- quotations with up to three filler pieces before the order, including a second
  "the phrase", a NUL, and 40 spaces, so that some orders fall past the 64-character skip;
- every branch of the order grammar, with spaces, tabs, line breaks, `\r\n`, and blank lines
  between the words;
- near-misses such as `ignored`, `instructionsX`, and `do not ignore`;
- ASCII, UTF-16LE, or mixed encodings, with NUL bytes that shift the byte alignment;
- a cross part that stands alone: a quotation in one encoding whose skip holds an order in
  the other, sometimes followed by a second quotation.

| Seed | Messages | Counting fires | Quote an order and stay clean | Differ |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 200,000 | 115,608 | 65,661 | 0 |
| 2 | 200,000 | 115,656 | 65,600 | 0 |
| 3 | 200,000 | 115,533 | 65,539 | 0 |
| 4 | 200,000 | 115,536 | 65,571 | 0 |

The probe was checked against five broken copies of the new exemption, 20,000 messages
each, and it caught every one:

| Mutation | Messages that differ |
| --- | ---: |
| No whole-gap test for a UTF-16 order between two quotations | 165 |
| No whole-gap test after the last quotation | 201 |
| A gap measured from a quotation's start, not its end | 1,105 |
| No test before the first quotation | 1,046 |
| A gap that stops 30 bytes before the next quotation | 48 |

### Independent review

Four reviewers worked separately on this change, in scratch directories, with no access to
each other's results.
- **An exhaustive fuzzer.** It used its own generator, not the probe's. It ran every token
  sequence up to length 5 in ASCII, UTF-16LE, UTF-16BE, and every per-token mix, then every
  one-byte edit of boundary seeds. On 8,555,810 inputs the old and new conditions agreed, and
  it caught each non-equivalent mutant.
- **An engine-semantics refuter.** It wrote about 35 crafted cases:
  - lazy ends, nested and overlapping quotations, and the 64/65-character skip boundary;
  - UTF-16 word boundaries at odd alignment;
  - `\r\n`, bare `\r`, `ſ`, and the Kelvin sign;
  - separators up to 70,000 characters.

  It also ran a 240,000-message fuzzer that checks properties 1 to 3 directly on the
  reported match lists. It found no disagreement and no violation.
- **A performance adversary.** It found no input on which the new condition grows faster than
  the size, and prose is not slower. The new condition adds 0 to 0.15 s over a condition that
  does nothing. Its slowest shape (many "the phrase" before 4,000 spaces) costs the same on
  `main`, and the cost comes from the quotation regex, which is unchanged.
- **An integration reviewer.** It confirmed the generator and lint checks, and it found three
  things:
  - two stale comments, now fixed (`fragments.toml` and a backlog row);
  - the shifted offsets below;
  - PR [#278](https://github.com/cgfixit/yara-gate/pull/278), opened by another session while
    this one was written, which fixes #274 in the same files. The maintainer kept this change
    and closed #278.

Three of the four reviewers found the same problem, and none of them in the logic.

### The match limit

YARA-X 1.23.0 records at most 1,000,000 matches of a string and drops the rest without a
signal. The scanner keeps that default. On `main`, 1,000,000 quoted orders followed by one
real order timed out, so the file was incomplete and held. With the linear condition alone
the scan finished before the deadline. The real order was never recorded, so the file was
**clean**. Both conditions read the same truncated list. The probe cannot see this, because
its messages are short.

The rule now counts a full order list as an order:
`for any of ($a, $b, $c, $a_wide, $b_wide, $c_wide) : (# >= 1000000)`.

| `the phrase ignore the above\n` × n, then `Ignore the above.` | n = 999,999 | n = 1,000,000 |
| --- | --- | --- |
| Engine, linear condition without the guard | fires | **does not fire** |
| Engine, with the guard | fires | fires |
| CLI, `agent-ingest`, disposable inbox, `main` | — | exit 2, incomplete (`timeout`), `quarantine/`, 30.8 s |
| CLI, `agent-ingest`, disposable inbox, this change | — | exit 1, block, `blocked/`, 14.4 s |

The guard fires on 1,000,000 quotations with nothing after them. That is a note where `main`
gave a timeout, and the file is held under `agent-ingest` either way. At 999,999 quotations
alone the rule stays clean. A full quotation list without a full order list is safe already,
because the orders after the last recorded quotation count. One reviewer saw this
over-fire on 16 MiB of six nested quotations per order.

The same limit already lets a request through `agent_message_code_relay` on `main`. 1,000,000
refusals followed by a real request (42 MiB) scan clean, where 999,999 refusals fire. That
rule, and the others whose conditions read offsets, are
[#280](https://github.com/cgfixit/yara-gate/issues/280).

### Reported offsets

A finding reports the first match of the first string that matched, in declaration order.
`$a` used to hold both encodings, so its first match was the earlier of the two. The ASCII
strings are now declared before the UTF-16 copies. In a file that mixes encodings, the
finding can therefore name a later ASCII match. The integration reviewer measured one case:
offset 265, length 42 became 314, 16. The verdict and the view are the same. Single-encoding
files report the same offsets as before.

Each new pair in `check_rule_pairs.py` gives the same answer on `main` and on this change:
- 300 quotations, then an order, then a quotation, against the quotations alone;
- the UTF-16LE form of the same thing;
- a UTF-16 `ignore the above` inside an ASCII quotation's skip, against `see the above`;
- 1,000,000 quotations, then an order (26.7 MiB), against one quotation.

## What was run

| Check | Result |
| --- | --- |
| `generate_rules.py --check`, `lint_rules.py`, `check_rule_generator.py` | 4 generated files current; 89 rules; 22 generator checks |
| `check_rule_pairs.py` | 120 rules; the 12 phrase-rule pairs below the limit agree on `main` |
| `check_added_rules.py` | 246 plus 4 vendor-override cases |
| `measure_precision.py --fail-over` | 328 files, 0 incomplete, the four documented Windows shortcut collisions |
| `probe_detection_gaps.py --verify` | 738 ok; B3 and B5 open, as on `main` |
| `probe_rule_coverage.py --verify` | passed |
| `check_worst_case_timing.py` | PASS, 96 inputs; the new `phrase-quotations.txt` clean in 2.08 s (15.01 s on `main`, past the 10 s ceiling). Load rose from 0.3 to 7.6 during the run, which overlapped the sweep; the slowest input took 7.62 s |
| `sweep_rule_changes.py --jobs 3 --base-ref origin/main` | 0 of 6,027 files changed findings (279 hits before and after), and 0 of 6,028 (280) rerun with the guard, over `/usr/share/doc`, `/usr/lib/python3.12`, `/usr/include`, `/usr/share/man`, the locked site-packages, and `docs` |
| `record_pages_demo.py --baseline` | Outcomes match for 84 scenarios × 3 policies; and for 91 × 3 on a trial merge with [#277](https://github.com/cgfixit/yara-gate/pull/277) |
| `probe_phrase_doc_exemption.py` | 0 differ, as above, and with the guard (seed 9, 200,000 messages) |
| `ruff check`, `ruff format --check`, `check_doc_links.py`, `check_text_controls.py` | Clean |

## Not established

- The equivalence is tested, not proved. The three properties above hold for the current
  word lists. A verb added to a list that can also follow a verb, or a greedy skip, would
  break property 1 or 2. Run the probe after changing the order strings, the quotation
  string, or `fragments.toml`.
- Message shapes outside the generator, and quotations in other languages.
- Hosted CI on `d77c94b`, before the guard: macOS 15 passed the timing check, with
  `phrase-quotations.txt` clean in 2.90 s, and the Windows scan job passed.
- The guard assumes the engine's default limit of 1,000,000. A scanner that changes
  `max_matches_per_pattern` must change the guard with it ([#280](https://github.com/cgfixit/yara-gate/issues/280)).
