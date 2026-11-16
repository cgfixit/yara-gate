# Held-item index — November 16, 2026

Issue [#257](https://github.com/cgfixit/yara-gate/issues/257) adds a standalone
`held --home GATE [--json] [--since 7d]` command before the separate private
review-bundle feature. The base was refreshed `origin/main`
`e6d92bc3181a2cb064ecb480eaf1d09a9f81c54c`; the operator checkout was clean and
already at that commit. Work used an isolated `cx/held-item-index` worktree.

## Current issue and PR review

Reviewed all ten open issues and their comments, including the later recorded
owner decisions. Issue-body proposals are not assumed to override those decisions.

| Issue | Current applicability and disposition |
| --- | --- |
| [#258](https://github.com/cgfixit/yara-gate/issues/258) | Main still decodes whole MCP/notebook JSON before its walk limits. Draft [#264](https://github.com/cgfixit/yara-gate/pull/264), head `51622a39c6695eafaf4557dde8011334eff45527`, owns the allocation fix; no duplicate implementation here. Its macOS, Windows, independent-verdict, Pages recording, and CodeQL checks passed when inspected; deployment gates were correctly skipped on the PR. |
| [#257](https://github.com/cgfixit/yara-gate/issues/257) | Selected as the immediate, independent operational improvement. Main's installed CLI returned exit 2, `No such command 'held'`. Release and rescan did not supply an index. This change completes the standalone index acceptance. |
| [#255](https://github.com/cgfixit/yara-gate/issues/255) | All six reported attack strings and the benign email-client control were rerun through `scan_bytes(..., policy='agent-ingest')` with main's unchanged detector/rules: all were clean with no findings. Still valid; the generic-tool/new-id and header-severity decisions remain separate detection work. |
| [#236](https://github.com/cgfixit/yara-gate/issues/236) | No replay or classifier adapter exists. Keep the recorded replay-first, observe-only ownership split and 100 benign/100 attack task pilot with three runs; no live Harness/model experiment was performed here. |
| [#227](https://github.com/cgfixit/yara-gate/issues/227) | No `conform` command or packaged manifest. Keep the later CLI-generated-fixture decision and dependency on #236's shared replay core; existing catalog/recordings are not this consumer contract. |
| [#231](https://github.com/cgfixit/yara-gate/issues/231) | Keep B3/B5 and remaining B8/reader-spelling work open under the recorded measurement gates. B6 is already built: the issue's inert gyp example returned block via `dev_gyp_command_expansion`. JSON allocation is tracked by #258. Existing issue comments already record these corrections. |
| [#229](https://github.com/cgfixit/yara-gate/issues/229) | No assembly-scan recipe or ledger. Preserve the later decision to scan assembled context first and build state only if #236 supplies residual-case evidence. The existing comment's hash/fragment representation concerns remain relevant. |
| [#228](https://github.com/cgfixit/yara-gate/issues/228) | No token/key/verifier implementation. Keep the recorded home/caller-key scope, seven-day expiry, JSON/library-only placement, prerequisite sequence, and the existing correction that a MAC alone cannot carry recoverable metadata. |
| [#225](https://github.com/cgfixit/yara-gate/issues/225) | No `explain` or review-bundle writer. Preserve the recorded 64-byte context/512-byte finding cap, escaping/masking, audit-chain, and incomplete-coverage decisions. The index adds no content disclosure. |
| [#226](https://github.com/cgfixit/yara-gate/issues/226) | No consumer manifest input or separate generated consumer output. Keep the recorded advisory families, public manifests here, output outside bundled `rules/local/`, and later implementation sequence. |

The only open PR at selection was #264. Its file list overlaps this change in
README, user guide, integrations, and the source map; its runtime changes are in
JSON readers, while this change adds the index and CLI. Compatibility is checked
separately from either PR's own acceptance.

## Behavior and acceptance

Present directory entries determine disposition. Reports supply metadata only;
historical reports do not invent held entries. Report paths must associate with the
held name and digest slot, including prior locations after intake/rescan relocation.
A matching newer all-zero-digest recovery report preserves an unreadable-copy reason.
Rejected paths associate with their `rejected-<identifier>.json` report. Missing,
corrupt, ambiguous, linked, oversized, and unassociated reports remain visible as
unreadable. Unknown report ages remain visible under `--since`.

Release eligibility reuses `release_refusal` as a provisional stored-report preview.
Only the existing release command can authorize, after rescanning and verifying the
current bytes, rules, findings, and audit evidence. Default output quotes fields as
JSON to prevent terminal control sequences. The versioned JSON schema and snapshot
limits are documented in [integrations](../integrations.md#listing-held-items),
with operator examples in the README and user guide. Scanner/report schemas,
findings, severities, policies, and vendor behavior are unchanged. Adding a Python
module changes `detector_sha256` under the existing whole-package fingerprint, so
consumers must retain their usual detector-change revalidation.

## Executed verification

Python 3.12.12, YARA-X 1.23.0, Ruff 0.17.4, mypy 2.4.1, arm64 macOS. The locked
environment came from `uv sync --frozen --group dev`; no dependency file changed.
Bundled-only scans compiled 89 rules with zero skips. No vendor packs were downloaded.

- `pytest -q tests/test_held.py`: 17 passed. This focused test file is required for
  the no-held-open acceptance: it intercepts Python and OS file opens while indexing
  real blocked/incomplete/rejected copies and checks unchanged file contents. It also
  covers released/resubmitted copies, corrupt/missing/scalar/malformed/mismatched/
  linked/deep/oversized reports, terminal escaping, filters, unavailable homes,
  rejected directories, linked slots, and unknown-digest recovery metadata. Linked
  reports are refused before any open. Windows CI now runs this file alongside rescan.
- Built sdist and wheel with `uv build`; installed the wheel in a separate locked
  environment, outside the source tree. Actual CLI subprocesses checked exits,
  structured rows, paths, reports and physical disposition for blocked, incomplete,
  rejected and clean inputs; a reviewed release; identical-byte `agent-document` →
  `agent-ingest` → `default` submissions; corrupted reports; `--since`; malformed
  options and missing homes. Listing changed no stored file content and created no
  missing home. The final wheel repeated this acceptance successfully.
- Computer Use drove the fresh installed loopback workbench, using a copied rules
  tree. Final-build `agent-ingest` run: 81/81 results matched reviewed expectations,
  all 40 attacks held, all 40 twins clean with zero findings, unsupported archive
  incomplete. The earlier same-scanner run also verified a secret-transfer paste
  advisory/exit 0 under default, block/exit 1 under ingest with advisory severity
  preserved, and clear/empty-input validation with the old result removed. Painted
  output was inspected. No native macOS application is shipped by this repository.
- Static companion: `scripts/build_pages.py` built its four allowlisted files and
  validated the unchanged 82 scenarios / 246 policy recordings. This is recorded
  playback validation, distinct from live-scanner browser acceptance.
- Ruff check/format on changed Python and Markdown, strict `mypy src scripts`,
  actionlint 1.7.12 on the changed workflow, and `zizmor --offline --pedantic .github`
  passed. Text-control and relative-link checks are run on the staged candidate.

The final installed module bytes were compared with the candidate source. SHA-256:

| Artifact | SHA-256 |
| --- | --- |
| Wheel | `9c54980a14942aca431c27147df9680d4ed91f5237827c89c7ab1fd56096475a` |
| `held.py` | `24faad52611131b114cd91caddd1ce38170b7eaa83f488e9234809f82ec40b20` |
| `cli.py` | `ea453aaf83ce206169874898f5a9aac0f4a1e65ebd96a59cb897db8d74ea3985` |
| `release.py` | `5cfc5071a5701cc8199fc5de494b9ced8398ce4e2105542e0e2cb373abe6a949` |
| `scanner.py` | `1088b0836ed6f9bea90c3d14610a636fb69718ff7fd0199f980fafbc2f1e843b` |
| `demo.py` | `3ed0c9b3a11c868a87c3ce7b8fcafba94d10fecebc895ace204ebf22365f8e2d` |
| `demo_page.html` | `493a3a21e66b77477f3ae4523c670b7fe9e3bce858d9d7d465fa1b8798171d6a` |

Final installed detector identity:
`d0aef3c99e28e079311085fa7d8118e24144e0c86dbae3434f37259b11f262a5`.
The final wheel is retained under the candidate's `dist/`; the candidate's development
entry point and separate installed CLI both expose `held`. The operator's main
checkout and unrelated installed tools/sessions are preserved.

## Limits and closure

This is a best-effort directory/report snapshot, not a transaction or a trust receipt.
The index does not verify content hashes or current rules, cannot recover a rejection
identifier reliably without its report, and lists reports larger than 8 MiB as
unreadable. Report modification time is not a verified admission timestamp. Home
access controls remain the trust boundary; simultaneous hostile same-account changes
are not isolated by this command.

No full local suite, native Windows execution, vendor accuracy evaluation, or live
Harness/Qwen integration was performed. Broad regression and Windows acceptance remain
hosted-CI responsibilities. Synthetic clean twins do not establish a production
false-positive rate. #257 can close after review, required checks, and merge; the draft
alone is not delivery to main.
