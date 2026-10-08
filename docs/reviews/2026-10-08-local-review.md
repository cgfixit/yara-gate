# Local source review — October 8, 2026

Reviewed the resynced default branch `main` at `254a0535859f878766c83093f974e69d250a1be5`. PRs #3 and #4 are already merged. There were no repository `AGENTS.md`, overrides, custom skills, or PR templates in that tree. This is a focused review for repository guidance, not an exhaustive security audit. No application source or rules were changed.

## Confirmed finding: vendor update removes installed rules before failing (P1)

**Location:** `src/yara_gate/rules.py`, `update_packs` lines 154–166, `_fetch_forge` line 175, and `_allowed_url` lines 240–245 at the reviewed revision.

`update_packs` deletes existing vendor contents before fetching replacement metadata. Its first request goes to `api.github.com`, but `_ALLOWED_DOWNLOAD_HOSTS` contains only `github.com` and `codeload.github.com`. `_bytes` calls that allowlist before opening the request, so the update deterministically fails after the deletion. The lockfile can still describe the previous packs while their bodies are absent; later scans can run with only the remaining local rules.

**Direct evidence:** in a disposable rules directory containing one inert `vendor/retained.yar`, calling the real `update_packs` raised `ValueError: refusing rule URL` and removed that file. Recreating the marker and running the installed `yara-gate rules update --allow-network --rules <temporary-directory>` returned exit 2, printed `incomplete: ValueError`, and again removed it. Neither run reached a network request. No installed user/vendor tree was touched and no mocks were used.

**Suggested follow-up:** stage a complete replacement outside the active vendor tree and retain the prior tree, lock, and usable cache on any download/validation failure. Add the required metadata host through an explicit URL policy, including redirect validation, rather than removing the allowlist. Verify failure preservation and successful replacement separately. This review documents the defect; it does not fix it or authorize a live vendor update.

## Scope and successful execution

Traced CLI dispatch, verdict/policy models, scan/member/text-view processing, document heuristics, quarantine and rescan disposition, report serialization, rule compilation/update/promotion, hunt, launchd generation, and the live demo. Inspected security guidance, locked dependency configuration, relevant regression sources, and both Actions workflows.

On macOS 27.0.1 ARM64 with Python 3.12.12 and YARA-X 1.21.0, the real `docs/research/probe_rule_coverage.py --verify` completed successfully at the reviewed revision:

- 12 shipped local rules compiled, with zero skips.
- 37 library inputs and eight installed-CLI intake/rescan operations matched their expected outcomes.
- Required-local-rule failure, optional-vendor skip, and deadline checks passed.

The probe used inert synthetic inputs, copied local rules, and disposable homes. It performed no target execution or network activity. No local pytest or selftest suite was run. The checks exercise the cases represented in that probe, not a held-out production corpus.

## Limits and review conclusions

The vendor-update finding affects correctness and retention of detection coverage. No unrelated style or refactoring change was justified by this review. Existing resource budgets were inspected, but no new throughput or memory benchmark was performed. The prior macOS watcher shutdown failure was not rerun here and remains a dated observation in the [intake verification record](../verification/intake-coverage.md).

Parser preemption, semantic PDF/Office analysis, full Unicode/encoding coverage, and real-corpus precision remain outside this review. Native Windows behavior and live CyClaw/Harness integration were not exercised. CodeQL's checked-in workflow has report upload disabled. New agent guidance and skill files still require structural validation and runtime discovery; their presence alone does not prove an already-running Codex session loaded them.
