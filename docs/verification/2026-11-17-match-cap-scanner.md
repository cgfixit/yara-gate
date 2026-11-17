# The scanner holds a scan whose match list stays full

Date: 2026-11-17. Base: `523855d` (`main` after #288). Engine: YARA-X 1.23.0 (locked).
Follows the [bundled-rule record](2026-11-17-match-cap-rules.md), which guarded 13 rules one by
one and left the scanner-level option to the maintainer. The maintainer chose it, with this
condition: if any pattern reaches the match-list limit, mark the scan incomplete (exit 2),
hold the file for human review, keep the findings already collected, and do not report the
scan as complete. The incomplete test is the limit of the final scan: a list full at
1,000,000 is read once more at 4,000,000, and only a list full then holds the file.

## What the engine gives the scanner

Read in the published `yara-x` 1.23.0 crate and the Python binding, and run:

- `PatternMatches::add` stops a string at `max_matches_per_pattern` (default 1,000,000) and the
  scan goes on without it. A list keeps one match per start offset, so no list can fill in an
  input shorter than 1,000,000 bytes.
- `ScanResults` has `matching_rules` and `module_outputs` and nothing else. A full list in a
  rule that did not match is invisible to Python.
- An identical string in several rules is searched and stored once. One string in 1 or 20
  private rules, flooded past 1,000,000 matches: +24 MiB and +25 MiB. The same 20 rules public:
  +1,417 MiB and 3.7 s, because the binding builds a Python object for every match of every
  matching rule (about 70 bytes a match there; 107 bytes in the uncapped runs below).
- A private rule's matches are never built into Python objects, and `console.log` in its
  condition reaches the callback set with `Scanner.console_log`.

## What was built

- `guard_source` in `src/yara_gate/rules.py` formats each rule file with YARA-X's own
  `Formatter`, blanks its comments, and writes, for each rule with strings:

  ```
  private rule <name>__match_cap {
    strings:
      <the rule's strings, as formatted>
    condition:
      for all of them : (
        # < yara_gate_match_limit or
        console.log("yara-gate match cap: <name> ", #)
      )
  }
  ```

  Each file's guards go in a namespace of their own (`gate_<i>_cap`), so a global rule of the
  file cannot turn them off. The original rule is not changed: a finding still means its own
  condition held.
- `compile_ruleset` builds a second ruleset, the same files plus their guards, and caches it
  beside the first (`<digest>.guard1.yarc`). A file whose guard does not format, parse, or
  compile loads as before and is listed (`<digest>.unguarded1`); `rules install`, `rules
  update`, and `setup` print `<file>: unguarded`, and the report counts them.
- `_yara_findings` in `src/yara_gate/scanner.py` scans a view of 1,000,000 bytes or more with
  the guarded set. If one to four guard lines are logged, it scans the view again with
  `max_matches_per_pattern(4_000_000)` and `yara_gate_match_limit = 4_000_000`, and the
  report's `match_rescan_limit` records `4000000`. A guard line on that rescan, or more than
  four on the first scan, marks the scan: it goes on through every other view and ends
  `incomplete`, `match cap reached`, with every finding it made. A timeout or another reason
  found later takes precedence, as any incomplete reason does.
- `RESCAN_MAX_FULL = 4` bounds the rescan's memory: four lists of 4,000,000 at the measured
  107 bytes a match is about 1.7 GB in the worst case, where every one is a matching public
  rule's.

## Runs

Each through `uv run yara-gate scan <file> --rules <disposable copy of rules/local plus one
test file> --json`, with a disposable cache and gate home. The test file adds
`zz_cap_letter_then_marker` (block when `MARKER` follows an `a`) and a private rule with five
one-letter strings. The same cases are `tests/test_match_cap.py`.

| Input | `523855d` | This branch |
| --- | --- | --- |
| 900,000 `a`, then `aMARKER` | | block, exit 1, no rescan |
| 1,500,000 `a`, then `aMARKER` | **advisory, exit 0**: the rule never sees the marker | block, exit 1, `match_rescan_limit` 4,000,000 |
| a `regsvr32` scriptlet line, 4,100,000 `a`, then `aMARKER` | | incomplete, exit 2, `match cap reached`; `script_regsvr32_remote_scriptlet` and `agent_base64_blob` kept |
| `bcdef` × 1,100,000 (five full lists) | | incomplete, exit 2, `match cap reached`, no rescan |

The third file dropped in a disposable inbox stayed in `quarantine/<digest>/`, and
`yara-gate held` lists it as `incomplete` with both findings and `release_eligible: false`.
Peak memory of these CLI runs: 194 to 367 MiB.

## Cost

- **Views under a million bytes**: unchanged. They are scanned with the plain ruleset.
- **4 MiB timing tripwire, bundled rules** (`check_worst_case_timing.py`, 96 inputs, this
  container): no verdict or reason changed. Total 245.4 s on `523855d`, 254.5 s here (+4%).
  Slowest input 7.97 s before, 7.86 s after. Largest increase `ooxml-xmlns-every-run.zip`,
  3.74 s to 5.63 s.
- **Vendor packs on 4 MiB of ordinary text** (the repository's own Python and Markdown): the
  plain set scans in 0.14 s, the guarded set in 0.24 s. Loading the same files twice costs
  nothing (0.14 s), and formatted copies are shared too, so the extra time is the guards'
  conditions, about 13,459 of them.
- **Cold compile with the vendor packs**: the plain set 8 s as before, then about 40 s more for
  the guarded set (most of it the formatter). Both are cached, so this is paid once per
  change to the rules.

## Guard coverage

`docs/verification` has no copy of the check; it was run from the scratchpad over the locked
packs installed into a disposable rules root (`rules install --allow-network`; yara-forge-core
`20261004`, signature-base `94a1c48`, elastic `83e2276`; 13,638 rules compiled, 13 skipped as
before). For each of the 1,855 files that compile:

- the guard was built: 13,459 guards, one for each rule with strings;
- the file compiled with an extra rule that names every guard's rule, so no guard stands for
  a rule the file does not have;
- the guard compiled alone.

No file was left unguarded. The first draft read formatter lines without blanking comments
and refused three signature-base files: `apt_hatman.yar` (the words "rule set" in a comment),
`gen_gcti_cobaltstrike.yar` (a comment after a closing brace), and `generic_dumps.yar`, which
keeps whole rules inside `/* */`. Read that way, the last would have guarded rules that do
not exist. `tests/test_match_cap.py` keeps those shapes.

## Vendor sweep of large benign files

SWEEP_RESULTS

## Rejected designs

- **No cap** (`max_matches_per_pattern` above the input length). Measured with the limit
  removed, strings that match at every byte of `a` × N: 10 MiB and one string, 10.5 million
  matches, +1.1 GB, 2.5 s; 20 MiB, +2.2 GB, 4.8 s; 20 MiB and four strings, 84 million
  matches, +7.2 GB, 17.4 s. About 107 bytes a match with the Python objects, so about 11 GB a
  string at the 100 MiB intake limit. The deadline does not bound allocation.
- **Rewrite each condition** as `(...) or for any of them : ( # >= limit )`. A full list would
  then be the rule's own finding, so the report could not tell a finding from a full list, and
  a public match builds Python objects for every rule that shares the string (the 1.4 GB
  above). It also needs a parser for every vendor condition.
- **Guards in the one ruleset every view uses**: about 70% more on every scan (0.14 s to
  0.24 s above) for views where no list can fill.

## Limits

- The guarded set is chosen by view length, `len(data) >= 1_000_000`. A view under a million
  bytes cannot fill a list.
- A rule file with no guard (`unguarded_rule_files`) is exposed as before. None of the locked
  packs or the bundled rules has one.
- More than four full lists hold the scan without a rescan, even when every list would have
  fit under 4,000,000. That trades a held file for a memory bound.
- A rule that writes its own `console.log` line beginning `yara-gate match cap: ` would be read
  as a guard and hold the scan. No locked pack does: one file, signature-base
  `gen_webshells.yar`, imports `console`, and the scanner drops lines without the prefix.
- The bundled rules keep their own guards from the [rules record](2026-11-17-match-cap-rules.md).
  On a full list they still report their finding, and the scan is now also incomplete unless
  the rescan reads every match.
