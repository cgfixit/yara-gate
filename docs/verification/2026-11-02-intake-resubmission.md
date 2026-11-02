# Inbox resubmission fix — November 2, 2026

This record covers the P0 intake item from the
[integration readiness review](../reviews/2026-11-02-integration-readiness.md#prioritized-plan):
identical bytes resubmitted under a different name were scanned under the stored name.
It was reproduced on `main` `436569d7ce2b5806b0ca17ee0046047ca4a4667c` and fixed in
`src/yara_gate/quarantine.py` on branch `claude/intake-resubmission`.

Locked environment: Python 3.12.3, YARA-X 1.22.1, yara-gate 0.2.0. Disposable gate homes
and a disposable copy of `rules/local` and `rules/rules.lock`: 82 compiled rules, zero
skips, ruleset `92c9e4282abe5adb4f13a04aab1e0b0718c85d568972b74876702c92432057c3`. The PE
input is the inert `samples.mini_pe()` fixture; nothing was executed and no vendor pack
was installed.

## Why the old behavior was a fail-open

`intake()` hashed a submission and, when those bytes already had a slot in `clean/`,
`blocked/`, or `quarantine/`, returned the stored file and discarded the new inbox entry.
The scan then ran under the stored file's name. A YARA rule does not depend on the
name, but the file-type checks do: a PE named `tool.exe` is an ordinary executable,
while the same bytes named `invoice.pdf` are a disguise that `filetype_mismatch_pe`
blocks. The verdict is a function of the bytes, the name, the policy, and the ruleset,
so reusing a slot keyed by bytes alone let a disguised resubmission inherit an earlier
clean verdict. The same per-digest slot let two concurrent submissions interleave, and
the inbox entry was removed by path, whatever file was there by then.

## The fix

- A digest still has one slot (`quarantine|clean|blocked/<sha256>/`) and one report
  (`reports/<sha256>.{sarif,json}`), as the README documents and integrations read. The
  slot now holds one file under the name of the latest submission: the submitted bytes
  are copied in under that name, any other name in the slot is removed, and the scan,
  report, and folder all follow that scan. A copy of the digest left in both `clean/` and
  `blocked/` (possible after the old race) collapses to one slot.
- `process_inbox_file` holds an exclusive lock on `<home>/.intake.lock` from intake
  through relocation: `flock` on macOS and Linux, `msvcrt.locking` on Windows. The OS
  releases it if the process dies.
- A completed scan whose SHA-256 differs from its slot is recorded as incomplete
  (`quarantined copy changed during the scan`) and stays in quarantine.
- The inbox entry is removed only if `lstat` still matches the file that was opened and
  copied. A file renamed onto the entry during the copy stays in the inbox for its own
  intake. A replacement in the instant between that check and the unlink is still
  possible; POSIX has no unlink-by-descriptor.

One per-slot file rather than one slot per submission keeps the documented
`clean/<sha256>/` and `reports/<sha256>` contracts. The cost: an honest resubmission
of bytes that were blocked under a disguised name moves the slot to `clean/` under the
honest name. That is the correct verdict for those bytes under that name, and any rescan
already re-decides a slot's folder (for example under a stricter or laxer policy).

## Direct probe

`intake_probe.py` (a scratch script, not committed) drove the installed `yara-gate scan
--json` CLI, plus `quarantine.intake` for the mid-copy case:

| Case | `main` `436569d` | This branch |
| --- | --- | --- |
| R1: `inbox/tool.exe`, then the same bytes as `inbox/invoice.pdf` | second scan **clean, exit 0**, slot and report still `tool.exe` | **block, exit 1**, `filetype_mismatch_pe`; slot `blocked/…/invoice.pdf`; report names `invoice.pdf` |
| R1 control: `invoice.pdf` scanned in place | block, `filetype_mismatch_pe` | same |
| R2: `invoice.pdf` first, then `tool.exe` | second scan block under `invoice.pdf` | clean under `tool.exe`; slot `clean/…/tool.exe` |
| R3: `notes.md` (injection) twice, then `--policy agent-ingest` | advisory, advisory, block | same |
| R4: `tool.exe` and `invoice.pdf` submitted by two processes at once, 12 runs | **4 of 12** reported `invoice.pdf` clean | 0 of 12; one slot, one file, folder matching its report |
| R5: another file renamed onto the entry during the copy | replacement **deleted unscanned** | replacement kept in the inbox |

## Checks

- `tests/test_quarantine.py` gains three regressions: the new-name resubmission (and the
  honest rename back), twin slots collapsing, and the mid-copy replacement. All three
  fail with `main`'s `quarantine.py` and pass with the fix; the module passes (22), as do
  `tests/test_cli.py` and `tests/test_cli_json.py`. The one skip there,
  `root reads a mode 000 directory`, is a root-container skip present on `main`.
- `docs/research/probe_rule_coverage.py --verify`: passed, no failures.
- `docs/verification/check_intake.py` and `check_scan_only.py` (7 cases): passed on Linux.
- Ruff check and format (whole tree), `mypy --strict src`, and
  `mypy --strict --platform win32 src/yara_gate/quarantine.py`: clean.

## Not covered here

The Windows lock path (`msvcrt.locking`) was type-checked, not run; the hosted
Windows job runs `check_intake.py` through it. The other P0 rows (a PDF header after
leading bytes, the reviewer-reported parser fail-opens) and #80's paused-writer
truncation are separate and unchanged.
