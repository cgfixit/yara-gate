# Detection documentation audit (2026-11-06)

Source: `39f5aa6f9cca6c002b195062bbf01c75c149a75a`, the base for this documentation-only
branch. Local macOS arm64, Python 3.12.12, locked YARA-X 1.23.0. No scanner, rule,
policy, dependency, or recorded-demo result changes.

## Checked against source

- Followed the scanner entrypoints through raw/member/derived-view scans,
  `filetype.py`, `heuristics.py`, `content.py`, `pdftext.py`, rule loading, and
  policy aggregation. The new `rules/README.md` maps these detection layers and
  links the intake/report/consumer controls separately.
- Recounted both `.yar` and `.yara` recursively: **85 rules in 58 files**, with
  **73 advisory, 6 block, 6 note** metadata declarations. Every local rule ID is
  present in `docs/rules.md`. `lint_rules.py` independently compiled/linted 85
  rules and validated 2 vendor overrides.
- Added missing reference descriptions for embedded-executable findings,
  legacy Office auto-exec/keyword IDs, and filetype mismatches. Corrected the
  broad implication that quotation always permits a document: only notes-only
  results pass agent-document; other findings still hold it.
- Updated the operator's list of existing reader views and the distinction
  between quarantine paths, in-place paths, and in-memory labels. The earlier
  text incorrectly described every report path as a quarantine slot.
- Verified local Markdown link targets/anchors in the edited documentation.
  Ruff format checks passed on changed Markdown, including Python blocks;
  `git diff --check` and `check_text_controls.py` passed.

## Precision reproduction

`uv run python docs/verification/measure_precision.py --fail-over` passed with
324 generated benign files, zero incomplete, and the existing exact hit table:
81 of 85 rules hit no files. Four rules each hit one intentionally represented
Windows collision (1/324, approximately 0.31%): `win_library_unc_location`,
`win_library_remote_location`, `win_shortcut_remote_icon`, and
`win_internet_shortcut_launch`. No heuristic findings occurred. No threshold or
rule change was needed. This corpus has no positive examples and measures neither
recall nor production precision. The README and reference now make that explicit.

No vendor bodies were downloaded or scanned. Historical reports remain dated
records, not current coverage claims. Phase 1c-small and the timing tripwire are
separate drafts; this branch documents the implemented behavior of its base and
links #171 for ongoing work. Full local suites, native/browser UI acceptance,
and exhaustive external-link availability checks were not needed for this
prose-only change. Hosted CI is separate.
