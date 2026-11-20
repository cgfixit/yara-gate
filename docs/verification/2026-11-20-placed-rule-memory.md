# Match objects of rules that place one string after another

Date: 2026-11-20. Base: the any-byte-gap change on `main` at `af31328` (`169dc3b`), which holds
[#310](https://github.com/cgfixit/yara-gate/pull/310). Engine: YARA-X 1.23.0, Python 3.12.3,
x86_64 Linux container with 4 cores and 15 GiB. Rules: the shipped `rules/local`, no vendor
packs. Direct runs on this container.

The lead was a security review finding on #310
([thread](https://github.com/cgfixit/yara-gate/pull/310#discussion_r4646718763)): the opener and
verb strings that #310 made standalone can each match a million times in an allowed file, and
the scan's memory grew about four times on a 15 MiB flood. #310's author reproduced it (368 MiB
against 74 MiB on `main`, and 1,382 MiB for 100 MiB with a 120 s timeout) and left the fix to
the maintainer. The [any-byte-gap change](2026-11-20-any-byte-gap-timing.md) makes the same
kind of string in 14 more rules.

## Where the memory went

`agent_role_spoof_action.yar` compiled alone, one `yara_x.Scanner.scan` of 15 MiB of
`<system> ignore `, growth of the peak resident set over the compiled rules:

| Rule file | Growth | Match objects |
| --- | ---: | --- |
| As shipped | 269 to 285 MiB | 983,040 for each of `$header`, `$verb`, `$word` |
| The same rule made private, behind a public rule that names it | 58 to 91 MiB | none |
| The same strings with a condition that cannot hold | 0 MiB | none |

- The growth is inside `scan`, before the caller reads a result. YARA-X's Python binding builds
  an object for every match of every string of a public rule that matched, about two thirds of
  the total here. The engine's own lists are the rest.
- The binding has no option to limit what it reports (`ScanOptions` sets module metadata
  only; `fast_scan` does not apply to a string whose place is read).
- A private rule gets no objects, which the match-cap guards already rely on.

## The change

The guarded ruleset is the one the scanner uses for a view of 1,000,000 bytes or more, the
only views in which a list can hold a million matches. In it, a non-vendor rule that reads
where its matches lie is now compiled as a private rule `<name>__placed`, behind a public rule
of its own name that keeps the metadata and has no strings (`hidden_source` in `rules.py`).
Another rule's reference to the name still resolves. 24 of the 25 bundled files with such a
rule are rewritten, 29 of 30 rules; `agent_invisible_unicode` is left out because the scanner
reads its matches one by one. A file that is not laid out as bundled rules are, or whose
rewritten text does not compile, loads as before. The cache names carry format 3.

A finding from such a rule then arrives without a match, so the scanner scans the rule's file
alone with every condition replaced by `any of them` (`locating_source`) and reads the first
match from that: each string kept to 1,024 matches, or to every match in a view of at most
1 MiB, where the deciding match is still looked for. No rule file changed.

**Considered and not used.** Moving the paired strings into private helper rules in each of
the 15 rule files, as #310's author prototyped. It gives the same saving, but a finding fired
by the pairing then has no offset at any size, the rule count in every report changes, and
each later rule of this kind would need the same split by hand.

## Same findings

`scan_bytes`, before and after, on the first-half-then-second-half flood of each of the 31
rows of the any-byte-gap record plus a system-opener flood and a code-relay flood, each at
1 MiB and at 4 MiB: 66 scans, and the verdict, incomplete reason, rescan limit, and every
finding's rule id, offset, length, and view are equal in all 66. A first draft read 1,024
matches at 1 MiB too and reported the first match there instead of the deciding one in 20 of
them; that is what the 1 MiB rule above fixes.

## Memory

One `scan_bytes` call per fresh process, 30 s timeout, peak resident set (`ru_maxrss`), which
includes the interpreter and the compiled rules:

| Input, 15 MiB | Before | After |
| --- | --- | --- |
| Ordinary sentences | clean, 97 MiB | clean, 98 MiB |
| `<system> ignore ` | advisory, 368 MiB | advisory, 158 MiB |
| `<!-- ignore previous instructions ` (`.html`) | advisory, 292 MiB | advisory, 174 MiB |
| `<foreignObject> <iframe ` (`.svg`) | advisory, 222 MiB | advisory, 145 MiB |
| `display:none ignore previous instructions ` (`.html`) | advisory, 233 MiB | advisory, 213 MiB |
| `<!-- ` alone (`.html`) | clean after the rescan, 327 MiB | clean after the rescan, 328 MiB |
| `<libraryDescription <url>\\h\s ` (`.library-ms`) | not measured | block after the rescan, 188 MiB |
| `<system> ignore `, 100 MiB, 120 s timeout | incomplete (`match cap reached`), 1,382 MiB (measured on #310) | the same verdict, 519 MiB |

- **What is left is the engine's own lists**, and the rescan that reads them again at
  4,000,000. `<!-- ` alone fires no rule, so it never had match objects; its memory is three
  million openers in two lists, read twice. The contract already says the rescan bounds the
  counted lists, not memory ([measured](2026-11-19-rescan-memory.md)); this change does not
  move that.
- The hidden-cue row barely moves. Not profiled: the rules that fire there besides
  `agent_hidden_html` include ones that do not place a string, whose objects are still built.
- A rule that tests a string only for presence, and vendor rules, are as they were.

## Checks

| Check | Result |
| --- | --- |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts` | pass |
| `pytest` (the whole suite) | 1,320 passed, 5 skipped. One expectation changed: the guard cache file names in `tests/test_rules.py` |
| `tests/test_match_cap.py` | 14 passed, 5 of them new: the rewritten source, a file not written as bundled rules are, the locating source, offsets at 990,000 and 1,100,000 bytes for a test rule and at 1.7 MB for `agent_hidden_html`, and no match objects from the guarded ruleset |
| `check_rule_pairs.py`, `check_added_rules.py`, `check_scan_only.py` | passed: 120 rules; 246 cases plus 4 vendor-override cases; 7 cases |
| `probe_rule_coverage.py --verify`, `probe_detection_gaps.py --verify` | exit 0 |
| `check_worst_case_timing.py` | PASS, 101 inputs of 4 MiB, slowest 7.05 s; scan seconds summed 231.9 against 244.1 before, no verdict or reason differs. The four any-byte-gap inputs took 0.2 to 0.6 s longer each, the locating scan |
| `record_pages_demo.py --baseline`, `build_conformance.py --check`, `yara-gate conform` | outcomes match, 91 scenarios under 3 policies; `current: conformance.json`; `CONFORM PASS`, 92 fixtures, 276 checks. `probe_match_cap.py`: 3,031 texts, 0 blind spots |

## What this does not show

- A bound on memory. A file of a few megabytes can still fill lists, and the rescan still
  reads them at four times the limit.
- Memory on macOS or Windows, or under a container limit; nothing here was killed for memory.
- That the first 1,024 matches of a string always include its first by offset. YARA-X keeps
  the first matches it finds, which is by offset except within one occurrence of an atom
  ([November 17 record](2026-11-17-match-cap-rules.md#what-the-engine-does)); the 66 scans
  above agree, and an offset from the locating scan always lies in the view.
