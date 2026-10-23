# Vendor swap commit and cleanup

Verified October 22, 2026 (America/New_York), with Python 3.12.12 and locked
YARA-X 1.21.0. The starting main revision was
`3926e0dc89112f07795861e24fbea76ef9667359`. This records a remaining transaction
failure in issue #9 after its original download/staging fix.

## Reproduced on the baseline

A real filesystem probe put an old rule inside a mode-0500 vendor subdirectory,
then invoked `update_packs` with inert release metadata and archive bytes through
its transport seam. Download, compilation, vendor replacement and lock saving
completed. Deleting the old backup raised `PermissionError`.

The baseline treated backup cleanup as a failed installation: it restored the
old vendor tree while retaining the newly written lock. Cleanup could also have
already removed some old files before rollback. This was reproduced without
mocking filesystem operations or accessing a live vendor endpoint.

A second regression found that a lock-write failure during a first installation
left the new vendor tree present despite reporting failure.

## Resulting behavior

```text
stage + compile -> swap vendor -> write lock -> commit
before commit failure -> restore previous vendor state, including absence
after commit -> best-effort old-backup cleanup, retain new vendor + new lock
```

The same mode-0500 runtime probe now completes successfully and retains the new
vendor tree with its matching lock. The undeletable backup stays under
`.vendor-old-*`, outside the active `vendor/` tree; later manual cleanup may be
needed. The scanner does not select that backup when loading the rules root.

## Executed checks

- The new cleanup regression failed on the baseline. Of the two lock-write
  failure cases, the existing-vendor case already passed and the first-install
  case failed. All three pass after the fix.
- Seven focused regressions passed: those three cases plus successful install,
  download/update retention and SHA-mismatch preservation.
- Ruff lint/format, strict mypy and `git diff --check` passed.

The deterministic regressions inject cleanup/lock I/O failures. The independent
runtime probe uses actual filesystem permissions. Both use inert rules and
disposable directories; no vendor downloads, target execution or operator-home
changes occur. Hosted regression/platform results are reported separately on
the PR's exact head. No full local suite or exhaustive storage-failure audit is
claimed.
