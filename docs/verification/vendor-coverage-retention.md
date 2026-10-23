# Installed vendor coverage retention

Verified October 22, 2026 (America/New_York), with Python 3.12.12 and locked
YARA-X 1.21.0. The starting main revision was
`3926e0dc89112f07795861e24fbea76ef9667359`. This addresses issue #11 using the
operator's selected policy: bundled-only scans remain valid before installation;
loss of recorded installed vendor files makes scans incomplete.

## Before and after

The new `test_installed_vendor_loss_holds_identical_resubmission` regression
failed on the starting application source for each of three losses: one rule
file, its pack directory, and the entire vendor tree. Each scan incorrectly
returned clean/exit 0. All three cases pass with this change:

```text
bundled-only scan -> clean/0
successful locked install -> clean/0
delete recorded file/pack/vendor -> incomplete/2, identical bytes quarantined
reinstall locked packs -> clean/0
```

`rules install` and `rules update` share `_swap_vendor`, which now records the
installed relative rule filenames in the root's `rules.lock`. Compilation checks
that inventory before memory or disk cache reuse. Neither scans nor the demo
download or repair packs. Existing optional vendor compile skips remain visible.

## Executed checks

- Maintained `uv run --frozen python docs/research/probe_rule_coverage.py --verify`:
  120 library cases, 24 CLI operations, nine benign observations and three failure
  paths passed; 20 shipped local rules compiled with zero skips.
- Nine focused rule regressions passed, covering the three new loss/recovery
  cases, successful locked installation, failed-update retention of the lock and
  inventory, bundled-lock fallback, SHA mismatch, missing bundled rules and
  visible vendor skips.
- The focused wheel-install end-to-end check passed using a separately built and
  installed wheel and disposable homes.
- A separate runtime probe called the real updater with inert metadata and ZIP/
  tar bytes supplied through its transport seam. A successful three-pack update
  recorded all three installed files; removing one returned incomplete.
- Ruff lint/format, strict mypy and `git diff --check` passed.

All inputs were inert; rule bodies came from synthetic archives, with no vendor
network download, target execution or operator-home modification. Hosted CI is
reported separately on the PR's exact head. Local checks are focused; the broad
regression suites remain enabled in Ubuntu/macOS CI.

## Limits and compatibility

Legacy locks have no installation inventory. One successful install or update
with the new version establishes it; scans do not infer or write historical
state. The inventory detects missing filenames, not changed rule contents or
deletion of the lock itself. It records the rules actually installed rather
than asserting comprehensive malware coverage. Older releases whose lock schema
rejects unknown fields cannot read an inventoried lock.
