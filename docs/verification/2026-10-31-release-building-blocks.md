# Reviewed release, first part: eligibility and the audit log (#39)

Base: `main` `693bca1`. YARA-X `1.22.1`, Python 3.12, Linux container, disposable rules roots. Nothing is wired to the CLI, and nothing moves a file.

## Why only these two pieces

#39 has four open owner decisions:

1. whether a release applies only to gate-home scans, or to every scan of those bytes;
2. whether `agent-ingest` holds are releasable at all;
3. whether the precision fixes for `script_download_execute` and `macos_keychain_dump` land first;
4. how the consumer read rule treats a notes-only `agent-document` record.

Two parts are needed whatever those decisions are. Building them first keeps the security-sensitive logic small and reviewed on its own:

- **`release_refusal(result, policies=...)`** returns why a fresh `ScanResult` may not be released, or `None`. It reads the verdict, the policy, the `policy_reason`, and every finding's severity. It never reads the folder the bytes sit in. `policies` carries decision 2.
- **`AuditLog`** is append-only JSON Lines under mode `0600`, each line hash-chained to the one before. It holds time, OS user and uid, reason, sha256, ruleset digest, policy, and rule ids. It holds no content, names, or paths. The reviewer comes from the operating system, not a flag.

The `policy_reason` strings moved into constants in `models.py`. The scanner and the release check now share one definition, so a wording change cannot silently break eligibility.

## Direct runs

| Scan | Verdict | Refusal |
| --- | --- | --- |
| Ollama install guide, `agent-document` | block | none: releasable |
| Lone override phrase, `agent-ingest` | block | none: releasable |
| The same, with `policies=(agent-document,)` | block | policy is not releasable |
| Lone override phrase, `agent-document` | advisory | not held |
| Install guide, default policy | advisory | not held |
| PDF with a JavaScript open action, `agent-ingest` | block | not a policy hold |
| Encrypted PDF, `agent-ingest` | incomplete | incomplete scan |

- A rule edit changes the ruleset digest, so the release key changes and the bytes are held again. The sha256, policy, and rule ids stay the same.
- The audit log detects an edited earlier line, a deleted line, and a truncated tail. An edit to the newest line alone passes `verify`, because nothing follows it. `head()` returns the hash to record elsewhere, and a changed head shows the edit.
- A reason that is empty, longer than 500 characters, or holds a control or format character (`U+202E`, a newline) is refused before anything is written.

`tests/test_release.py` holds these cases. Each test function was run by calling it directly, 15 calls in all. CI runs the suite.

## Not built yet

These wait on the decisions above: the `release` command, where releases are stored and consulted, `--list-stale`, `--verify-log`, the TTY and `watch` refusals, and the consumer read rule.
