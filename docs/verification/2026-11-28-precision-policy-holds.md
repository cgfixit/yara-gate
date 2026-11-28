# Benign files each policy holds, beside the per-rule rate (2026-11-28)

Source: `main` at `0480d67`, branch `claude/serene-brown-qb93an`. Linux x86_64, Python 3.12,
YARA-X 1.24.0, 89 compiled local rules, no vendor packs. Only
`docs/verification/measure_precision.py` changes; the scanner, the rules, and the policies do
not. This answers finding 5 of [#376](https://github.com/cgfixit/yara-gate/issues/376). The
2% limit is per rule, so it says nothing about how many distinct benign files the ruleset
holds in total.

## The change

- Each corpus file is scanned once under `default`, as before, and then under
  `agent-ingest` and `agent-document` with `scan_file(..., policy=...)`. The scanner applies
  each policy, so the script does not copy that logic.
- The report adds a `held` row for each policy, with three things in it:
  - the distinct files whose verdict is `block`;
  - their rate over all files;
  - a count by corpus folder (`chat`, `pdf`, `office`, `windows`, …), where the folder
    stands for the channel a file came through.

  A separate `groups` field records each folder's size.
- The markdown adds a table of those rows. No limit applies to it.
- An incomplete scan under any policy is listed in `incomplete`, so `--fail-over` fails it,
  as it already failed an incomplete `default` scan.

## Observed

`uv run python docs/verification/measure_precision.py --fail-over --json <scratch>` exited 0:

| Policy | Files held | Rate | Held by corpus folder |
| --- | ---: | ---: | --- |
| `default` | 1 | 0.30% | windows 1/21 |
| `agent-ingest` | 4 | 1.22% | windows 4/21 |
| `agent-document` | 4 | 1.22% | windows 4/21 |

The held paths in the JSON are exactly the files that have findings:

- `Team.library-ms`, a block under every policy;
- `Handbook.url`, `Intranet.searchConnector-ms` and `desktop.ini`, advisories held by both
  agent policies.

These are the tagged Windows collisions that `docs/rules.md` already counted by hand: "four
distinct files had findings (4/328)". The per-rule table is unchanged.

`ruff check`, `ruff format` and `mypy --strict` on the script are clean. The three-policy run
took under a second on this machine, with the compiled-rule cache warm.

## What this does not show

- A production false-hold rate. The corpus is generated and small (328 files, 21 of them
  Windows), and a folder is a stand-in for a channel, not a measured workload.
- The other two measurements #376 asks for: benign tasks that lose a required source, and
  held items in real security articles. They need the replay captures (#294), not this corpus.
- A limit. Whether CI should fail above some aggregate rate, and at what rate, is the
  maintainer's decision. The table only reports.
