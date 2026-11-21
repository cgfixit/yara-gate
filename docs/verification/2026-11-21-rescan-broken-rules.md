# `rescan` with rules that cannot scan

Date: 2026-11-21. Base: `main` at `78e26bb`. Engine: YARA-X 1.23.0, Python 3.12, x86_64 Linux
container running as root. Rules: a disposable copy of the shipped `rules/local` (89 rules),
no vendor packs, under a temporary root; every gate home was disposable. Every run below is a
direct run on this container; nothing here is hosted CI.

## The lead

`rescan_clean` scans empty bytes first to learn the current ruleset and detector identity.
When that scan was `incomplete`, the pass carried on: every copy in `clean/` was scanned,
came back `incomplete` for the same reason, had an incomplete report written over its clean
one, and moved to `quarantine/<digest>/`. The ruleset's fault was recorded against each file.
A later pass never rechecks `quarantine/`, so repairing the rules did not bring the copies
back. `test_missing_vendor_withdraws` asserted the withdrawal, and `docs/integrations.md`
described it ("Missing recorded vendor rules make rescans incomplete").

## Reproduced on the base

A disposable home with three ordinary text files admitted clean, then one break to the rules,
then `yara-gate rescan --home GATE --rules RULES`, then the break undone and the same command
again.

| Break | First pass, base | Pass after repair, base |
| --- | --- | --- |
| `vendor.installed.json` lists `pack/missing.yar` | exit 2, three `incomplete` lines with `installed vendor rules missing`, `newly_incomplete: 3`; `clean/` 0, `quarantine/` 3 | exit 0, `rescanned: 0, unchanged: 0`; `clean/` 0, `quarantine/` 3 |
| `local/zz_broken.yar` that does not compile | exit 2, `local rule compile failed` three times, `newly_incomplete: 3`; `clean/` 0, `quarantine/` 3 | exit 0; `clean/` 0, `quarantine/` 3 |

The second pass exits 0 over an empty `clean/`. Recovery was resubmitting every file by hand.

## The change

`rescan_clean` raises `ValueError("rules cannot scan: <reason>")` when the identity scan is
`incomplete`, before the first slot. The CLI's existing abort path prints
`incomplete: rules cannot scan: <reason>; remaining copies are unvalidated`, the summary line
with zero counts, and exits 2. The same check applies to `--dry-run`. A failure that shows
only on one copy is unchanged: that copy is still reported and moved to `quarantine/`.

## Observed after the change

| Break | First pass | Pass after repair |
| --- | --- | --- |
| missing vendor file | exit 2, stderr `incomplete: rules cannot scan: installed vendor rules missing; remaining copies are unvalidated`, `rescanned: 0`; `clean/` 3, `quarantine/` 0, report count unchanged (6) | exit 0, `unchanged: 3`; `clean/` 3 |
| local compile failure | exit 2, `rules cannot scan: local rule compile failed`; `clean/` 3, `quarantine/` 0 | exit 0, `unchanged: 3` |
| malformed `vendor-overrides.json` (library call, path patched) | `ValueError: rules cannot scan: invalid vendor-overrides.json`; `clean/` 1, `quarantine/` 0 | not run |
| no bundled rules compiled (library call, empty root) | `ValueError: rules cannot scan: no rules compiled`; nothing moved | not run |

`test_rules_that_cannot_scan_stop_before_any_copy` replaces `test_missing_vendor_withdraws`.
It covers the first two breaks, with and without `--dry-run`. It checks that every file in the
home other than the lock files is byte-identical after the failed pass, and that the repaired
pass keeps both copies. It fails on the base source (4 of 4) and passes on the change. The
whole `tests/test_rescan.py` gives 22 passed.

Checks: `ruff check`, `ruff format --check .`, `mypy --strict src scripts`,
`docs/verification/check_doc_links.py`, and `docs/verification/check_text_controls.py` pass.

## What this does not cover

- Rules that break partway through a pass, for example a file another process removes after
  the identity scan. The pass is not a transaction over the rules tree, as
  [revalidation](../integrations.md#revalidating-admitted-files) already says. Copies
  scanned after the break are still withdrawn one by one.
- The trade-off. Before, a broken ruleset failed closed per copy: nothing stayed in `clean/`.
  Now `clean/` keeps the copies admitted under the earlier rules, and exit 2 is the signal
  to keep consumers paused. That is the same state as any other abort, which the contract
  already treats as "remaining copies are unvalidated". A consumer that resumes reading on
  exit 2 was already wrong for every other abort.
