---
name: yara-gate-rule-authoring
description: Add or tune yara-gate local YARA rules, evaluate false-positive boundaries, or assess candidate promotion against the real YARA-X loader. Use for rule coverage changes, not general malware analysis or live vendor updates.
---

# Author yara-gate rules

Work from the repository root. Inspect `rules/local/`, `src/yara_gate/rules.py`, `scanner.py`, and the relevant `content.py` views before designing a detector. Read `docs/research/universal-rule-research.md` as a dated baseline/proposal, not current coverage. Follow `SECURITY.md` when handling samples.

## Define the detection boundary

Name the input surface, combined signals, expected finding severity, and a realistic benign collision. A rule can indicate suspicious bytes; it cannot prove an agent obeyed an instruction or that a document is malicious. Prefer bounded proximity and multiple signals over isolated words such as `curl` or `.env`.

Use stable identifiers and the existing metadata conventions. `verdict_on_match` drives severity; missing/invalid values default to block. Additional metadata does not implement policy. New uncertain indicators should begin advisory unless the task establishes a stronger policy.

The loader skips `status = "candidate"` entirely. To evaluate such a proposal, activate a copy in a disposable rules tree. Do not claim a candidate is scanned as advisory. Promotion changes `verdict_on_match` to block and must be within the user's requested scope; `hunt` uses supplied confirmation/reason, not an independent malware verdict.

## Exercise the actual loader and scanner

- Use the locked environment (`uv sync --frozen --group dev` if needed). YARA-X semantics and available modules come from that environment, not a global classic YARA binary.
- Copy `rules/local/` into a temporary rules root with `local/` beneath it. Pass that root explicitly as `rules_dir` or `--rules`. A scan writes its cache outside that tree and does not rewrite `vendor/SKIPPED.md`. `rules install` and `rules update` are what write the skip list.
- Run `compile_sources` from `src/yara_gate/rules.py` and check the returned error and skip counts. Files are validated individually and compiled into separate namespaces; keep necessary private helpers together and do not assume cross-file references work.
- Pass inert positive and benign near-miss files through `scan_file` and inspect the expected rule IDs, severity, namespace, member path, and view. Test relevant alternate suffixes, UTF-16/HTML forms, and supported archive members. `yara_gate_ext` is the actual scanned unit's suffix; it is not a normalized content-type marker.
- Compare both default and `agent-ingest` policy when disposition matters. An advisory normally exits 0; agent-ingest holds it as overall block/exit 1 without changing its finding severity. A required local compile failure must be incomplete/exit 2.

For changes spanning the covered rule families, run the existing direct probe:

```sh
uv run python docs/research/probe_rule_coverage.py --verify
```

Extend its inert cases only when they exercise a meaningful new boundary. Use narrower direct scans for a single isolated detector. Run changed Python through Ruff and type checking as appropriate; leave broad pytest/selftest to hosted CI by default.

Do not run `rules update` to validate a local rule. Vendor bodies are absent from a fresh checkout. `rules install --allow-network` downloads the locked URLs and checks sha256. An installed copy uses the packaged `rules.lock` when the rules root has none. `rules update --allow-network` resolves new pins. Both keep the previous vendor tree and lock when anything fails. `GITHUB_TOKEN` or `GH_TOKEN` is sent only to `api.github.com` and must not appear in output or reports. Before an authorized vendor update, inspect its failure handling and URL policy on the current revision in a disposable tree.

Report coverage gained, benign collisions, unsupported transformations, source/engine identity, and compile skips. Preserve upstream rule attribution/licenses. Never include real matched secrets, malware payloads, or private sample contents in a PR. Synthetic matches are not a production accuracy estimate.
