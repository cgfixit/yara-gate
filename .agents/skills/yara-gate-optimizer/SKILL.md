---
name: yara-gate-optimizer
description: Review yara-gate for evidence-backed correctness, security, performance, dependency and documentation improvements, then implement and publish focused drafts when requested. Use for an explicitly requested yara-gate optimization pass.
---

# yara-gate optimizer

Read `AGENTS.md`, `SECURITY.md`, `README.md`, and the relevant `user-guide.md`
sections. Run `yara-gate-invariant-guard` first. This optimizer is manual-only.

## Establish current behavior

Inspect root, remotes, actual default branch, dirty state and local-only commits.
Refresh upstream and inspect open PR heads/files/checks before publication work.
Preserve unrelated changes; use an isolated worktree when necessary. Derive the
GitHub repository from its remote and use the session's branch prefix.

Spend a bounded initial read-only pass on production callers, then reproduce
each promising lead before editing:

- `cli.py`, `models.py`, `quarantine.py`: directory traversal, aggregate exits,
  intake identity, identical-byte rescans, report/relocation order, watcher lifecycle.
- `scanner.py`, `content.py`, `filetype.py`, `heuristics.py`: bounded reads,
  decoding, archive coverage, timeout gaps, false positives and offset attribution.
- `rules.py`, `hunt.py`, `rules/local/`: installed overlays, candidates, cache
  invalidation/skips, download staging and credential/redirect boundaries.
- `report.py`, `demo.py`, `demo_page.html`: metadata privacy, browser rendering,
  request limits, origin validation and CSP.
- `pyproject.toml`, `uv.lock`, packaging and workflows: supported toolchain,
  justified dependency updates, shipped assets and actual CI coverage.

Treat dated review/verification documents as leads. Drop work already fixed
upstream. Report each finding with input, path to effect, impact and a reproducer.
Zero findings is valid. Measure before/after with identical inputs and runtime
before claiming a speedup. Dependency freshness alone is not a performance claim.

## Make the smallest complete change

Reuse existing helpers, types, probes and tests. Fix the shared cause and all
affected callers; preserve API and policy behavior unless the requested fix changes
it. Avoid speculative options, wrappers, bootstrap scripts and parallel harnesses.
Keep one earned concern per draft; use independent branches for independent work.

Review dependencies against current package metadata and relevant advisories;
update the existing lock deliberately, preserving Python 3.12 and YARA-X. Do not
download vendor packs or promote candidates as a side effect of dependency review.
Update affected docs in place, including stale counts/examples verified from code.

## Verify and deliver

Run the changed library/CLI path using inert input, copied rules and disposable
homes. Use `yara-gate-runtime-verify` for behavior and
`yara-gate-demo-evidence` for the live browser. Computer Use must exercise the real
loopback demo with the final scanner/rules; `demo.html` is only an illustration.
Browser evidence does not prove inbox disposition, archive limits or packaging.
Record those through their actual interfaces. Preserve original screenshots under
`screenshots/` with revision, date, scenario and hashes.

Run Ruff on changed Python and Markdown, strict mypy for Python contract changes,
and actionlint on changed workflows. Use focused regressions for concrete risks;
leave broad pytest/selftest coverage to hosted CI. Verify installed wheels when
packaging changes. Recheck invariant boundaries affected by the final changes.

For requested publication, inspect the final diff, follow any repository PR
template, stage only intended files, commit, push and create draft PRs. Read back
the published body and exact remote head. Follow that head's CI to terminal results
or a concrete blocker. Report CI, review, mergeability and draft status separately.
CodeQL query success with upload disabled does not prove dashboard delivery.
Keep drafts unmerged unless the user explicitly authorizes merging.

Finish with observed improvements, evidence, unverified boundaries and known risks.
No synthetic corpus or browser run proves perfect detection or production accuracy.

Template provenance: [WynDoze-Shield wyndozescan-optimizer](https://github.com/cgfixit/WynDoze-Shield/tree/4efac182f7538b47a8fd9c54099b7c84e8272781/.agents/skills/wyndozescan-optimizer).
