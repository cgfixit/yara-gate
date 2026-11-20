# Phrase rules rendered from one word list and one separator — November 10, 2026

Measured on this branch at `7f7bab3`: `main` at `838b11d` plus the
[SVG link and zero-width run rules](2026-11-10-svg-links-and-invisible-runs.md), which are
the first commit of the same pull request,
[#211](https://github.com/cgfixit/yara-gate/pull/211). The other open pull request,
[#210](https://github.com/cgfixit/yara-gate/pull/210) (the cost of reading PDF fonts),
shares no file with this change; it merged while this was being written, and the
[last section](#after-main-moved) has the re-run on the merged tree. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0,
87 bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local`. Nothing was executed, unpacked to disk, or fetched.

## Question

The backlog carried one maintenance item ahead of any new phrase: generate the phrase rules
from a word list and one separator grammar
([#171](https://github.com/cgfixit/yara-gate/issues/171)). In
`agent_prompt_injection_phrases.yar` the separator between words was written out 64 times,
and the documentary exemption was a second, hand-made copy of the grammar with every
quantifier turned lazy. Can those files be rendered from one source without changing what
any pattern matches?

## What changed

- [`rules/templates/`](../../rules/templates/) holds the sources.
  [`fragments.toml`](../../rules/templates/fragments.toml) has 17 fragments: 8 word lists
  and 9 sub-patterns, the separator among them. Each of three `.yar.tmpl` files is a rule
  file with `{{name}}` where a fragment goes.
- [`scripts/generate_rules.py`](../../scripts/generate_rules.py) renders them into
  `rules/local`. `{{lazy name}}` gives a fragment with every quantifier made non-greedy, which
  is how the documentary exemption and the HTML comment strings are now derived from the
  strings they follow. `--check` writes nothing and exits 1 on a stale file.
- [`lint_rules.py`](lint_rules.py) runs that check on Ubuntu, macOS, and Windows, so a hand
  edit to a generated file and a template edit that was not rendered both fail CI.
  [`check_rule_generator.py`](check_rule_generator.py) is a new CI step for the generator
  itself.

| Generated file | Separator copies before | Placeholders in the template | Shares with |
| --- | ---: | ---: | --- |
| `agent_prompt_injection_phrases.yar` | 64 (50 greedy, 14 lazy) | 55 | the verbs, adjectives, and nouns of `agent_override_imperative`; the "you are now" tail of `agent_hidden_html` |
| `agent_override_imperative.yar` | 9 | 12 | as above |
| `agent_hidden_html.yar` | 0 | 6 | its hiding cues were written twice, and its seven phrases twice, once made lazy by hand; the "you are now" and DAN tails each had a third copy in the phrases rule |

No rule was added or removed and no severity changed: 87 rules in 58 files, 75 advisory,
6 block, 6 note. The templates are not packaged and nothing reads them at scan time.

## The patterns are the ones that were there

Each generated file is the committed file with three comment lines above it that name its
sources. The rest is the same bytes:

| File | Committed body at `7f7bab3` | Generated file | Lines added | Lines removed |
| --- | ---: | ---: | ---: | ---: |
| `agent_prompt_injection_phrases.yar` | 7,270 bytes | 7,469 bytes | 3 | 0 |
| `agent_override_imperative.yar` | 5,853 bytes | 6,047 bytes | 3 | 0 |
| `agent_hidden_html.yar` | 5,188 bytes | 5,374 bytes | 3 | 0 |

`git show 7f7bab3:rules/local/<file> | cmp - <(tail -n +4 rules/local/<file>)` is silent
for each. The templates were made from the committed files by putting a placeholder where
a fragment's rendered text stood, so the comparison checks the fragments, the templates, and
the lazy rendering at once. A comment is not part of a YARA pattern, so no match can differ;
the checks below were run anyway.

The ruleset digest changes, because it covers file bytes: from
`7f99e59f6ae7ef5490b83cf7c4089b339929e5d6a47ea3bde83d4377f545843f` to
`e96faeaf3d4b7719f1c0ae5a12593a45e6b0a3fe4500a4197900ca16f38e7487`. The compiled cache is keyed by it, so
the first scan after this change compiles once.

## The generator, exercised

[`check_rule_generator.py`](check_rule_generator.py) runs on disposable copies and passed
its 22 checks:

- **Drift.** A hand edit to a generated file is reported with its file and line, with exit
  1; regenerating gives the committed bytes back.
- **Reach.** A made-up noun added to `order_nouns` and not yet rendered is reported.
  Rendered, it rewrites one file and reaches `$a`, `$doc_phrase`, `$a_post`, `$a_above`, and
  `$a_follow`; `$a_replace`, whose list leaves `rules` out on purpose, is untouched. The
  exemption holds the word once, the rules compile with the locked engine, an order with
  the word fires in the changed copy and not in the shipped rules, and the same words after
  "the phrase" stay clean. So the exemption still ends where the order ends.
- **Refusals.** An unknown fragment, a placeholder not written as `{{name}}`, a fragment
  that names itself, a fragment no template uses, a lazy copy of a fragment that is already
  lazy, a fragment that is not text, a file marked as generated with no template, and a
  template that was never rendered: each is refused.

The check was then shown to fail. With the lazy rendering removed from the generator it
exited 1 and `lint_rules.py` failed on two files; with the leftover-placeholder test removed
it exited 1 on that case. Both edits were reverted and the generator compared byte for
byte with its copy.

In the working tree, a word added by hand to `agent_override_imperative.yar` made
`lint_rules.py` exit 1 naming line 16; `generate_rules.py` restored the file exactly.

## Commands and results

- `scripts/generate_rules.py --check`: "generated rule files are current (3)".
- `docs/verification/lint_rules.py`: 87 rules compiled and linted, 2 vendor overrides.
- `docs/verification/check_rule_generator.py`: passed, 22 checks.
- `docs/verification/check_rule_pairs.py`: passed, 117 ids.
  `docs/verification/check_added_rules.py`: passed, 242 cases plus 4 vendor-override cases.
- `docs/research/probe_rule_coverage.py --verify`: passed, 617 library cases, 55 CLI cases,
  9 benign observations. Verdict, exit code, findings, and finding context are the same in
  every case as in the run before this change. Five zip fixtures the probe builds have a
  different input hash, because a zip member records when it was written.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 275 `ok` and 4 `open` (B3, B5, B6,
  B7); every row is the one from the run before this change.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete;
  the 87-row table is identical: 83 rules at 0 files and the four documented Windows
  collisions.
- `docs/verification/sweep_rule_changes.py`, base `838b11d` (so both commits of the pull
  request): 8,116 installed text files (Node 22, `/usr/share/doc`, the Python 3.12 and 3.13
  libraries, Vim and Perl runtime files, `/etc`, shell completions, the project's virtual
  environment), 0 with changed findings, 36 hits before and after.
- `docs/verification/check_worst_case_timing.py`: PASS, 36 inputs of 4 MiB; slowest
  `pdf-page-fonts.pdf` at 7.37 s against the 10 s ceiling (7.39 s before this change).
- `scripts/record_pages_demo.py --baseline web-demo/recordings.json`: "Outcomes match the
  reviewed baseline" for the 64 scenarios under 3 policies, recorded with 87 rules and the
  new digest. The committed baseline is unchanged; a deployment refreshes its provenance.
- `yara-gate selftest`: SELFTEST PASS. `check_text_controls.py` (311 files),
  `check_doc_links.py` (690 relative links), `check_scan_only.py`, `check_rules_lock.py`:
  passed. `ruff check .`, `ruff format --check .`, and `mypy --strict src scripts` (27
  files, the generator among them): passed.
- The workflow gained one step. `actionlint` v1.7.12, built with `go install` as CI builds
  it, and `zizmor --offline --pedantic .github`: no findings.
- A wheel built from this tree holds the 58 rule files, the three generated ones with
  their header, and no template, fragment file, or generator.
- `pytest` on the rules loader, hunt, release, Pages build and deploy, and demo tests: 124
  passed. The whole suite is left to hosted CI.

## After `main` moved

#210 merged at `85b0be5` before this was published. `main` was merged into the branch
(`d1d839b`), no file in conflict, and these were run again on the merged tree:

- `lint_rules.py` (87 rules), `check_rule_generator.py` (22 checks), `check_rule_pairs.py`
  (117 ids), `check_added_rules.py` (242 plus 4), `probe_rule_coverage.py --verify`,
  `probe_detection_gaps.py --verify` (275 `ok`, 4 `open`), and
  `measure_precision.py --fail-over`: all passed. The precision table and every gap-probe row
  are the same as before the merge.
- `check_worst_case_timing.py`: PASS, 36 inputs, every verdict and reason as before. Single
  runs on this container gave `pdf-page-fonts.pdf` 7.10 s (7.37 s before the merge) and
  `pdf-font-definitions.pdf` 7.55 s (6.71 s). The rules are the same bytes on both sides of
  the merge, so that difference is #210's code and this container's run-to-run spread, which
  one run each cannot separate.
- `record_pages_demo.py --baseline`: outcomes match for the 64 scenarios under 3 policies.
- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts`,
  `check_doc_links.py`, `check_text_controls.py`, and `yara-gate selftest`: passed.

## What was left written by hand

- **The forms each string uses.** `$a` writes its optional determiner as four alternatives
  that each end in the separator, and `$a_post` as one group followed by it. The templates
  keep both. Unifying them is a pattern rewrite, and this change was checked by comparing
  bytes.
- **Lists that differ on purpose.** `earlier` and `earlier_or_above` are two lists, as are
  `order_nouns` and `replace_nouns`; `$a_your` keeps `(ignore|disregard)` inline because
  `forget` counts only before the prompt or programming. Each difference is a recorded
  boundary, noted beside the list.
- **Strings with their own separator.** The disclosure, authority, persona, and memory
  strings take spaces and tabs only (`[ \t]+`), not a line break. They are in the templates
  as written; giving them the shared separator would change what they match.
- **Other rules.** `agent_prompt_injection_multilingual` and the rule bodies that repeat a
  list elsewhere (the workflow, git-config, credential-upload, and PowerShell rules) are
  candidates in the [backlog](../research/detection-backlog.md#further-candidates-not-yet-in-the-probe).

## What this does not establish

- That the word lists are the right ones. This change moves them; it adds no word and
  measures no recall.
- Anything about a future edit. A word added to a list reaches several strings at once,
  and each needs its near-miss, the sweep, and the timing check, as before.
- The lazy rendering beyond what is used. It handles `?`, `*`, `+`, and `{m,n}` and refuses
  an exact count, a possessive quantifier, and one that is already lazy; no reviewed pattern
  uses those.
- Hosted CI on macOS and Windows had not run on this commit when this was written.
