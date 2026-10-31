# Reviewed release, building blocks: eligibility and the audit log (#39)

Base: `main` `693bca1`. YARA-X `1.22.1`, Python 3.12, Linux container (root), disposable rules roots. Nothing here is reachable from the CLI, and nothing moves a file.

## Owner decisions this follows

The owner recorded these on #39 on 2026-10-31:

1. Releases are consulted only for file scans under the same explicit `--home`, never by `scan_bytes` or stdin.
2. Only `agent-document` holds are releasable. Every `agent-ingest` result is refused.
3. Precision work comes first and release activation second. The unreachable components can be reviewed in parallel.
4. Documents are read on a complete `clean` record or on an exact notes-only `agent-document` record.

Decision 3 is why this PR stops short of the command. The `release` command, `apply_release`, and the reviewed-release acceptance branch for decision 4 live on `claude/release-activation` and wait for the precision PRs.

## What is here

- **`release_refusal(result)`** returns why a fresh `ScanResult` may not be released, or `None`. It refuses a result that is incomplete, not under `agent-document`, not a block, a block with any other `policy_reason`, carrying a block-severity finding, without findings, or without a ruleset digest. It never reads the folder the bytes sit in. Decision 2 is a constant, `RELEASABLE_POLICY`, with no parameter to widen it.
- **`release_key(result)`** returns `(sha256, ruleset_sha256, policy, sorted rule ids)`. Any change to any part holds the file again.
- **`AuditLog`** has these properties:
  - It is append-only JSON Lines, mode `0600`. Each line is hash-chained to the one before.
  - `<log>.head` holds the newest line's hash, and every read checks it.
  - Appends take an exclusive lock on `<log>.lock` (`flock`, or `msvcrt.locking` on Windows).
  - Entries hold the uid, which is the identity anchor, and the OS user name for display, plus the reason, digests, policy, and rule ids. They hold no content, names, or paths.
  - `verify(expected_head=...)` checks against a head recorded outside the gate home.
- **Shared reason strings.** The `policy_reason` strings are constants in `models.py`, shared by the scanner and this module.

## Direct runs

| Scan | Refusal |
| --- | --- |
| Ollama install guide, `agent-document` | none: releasable |
| The same guide, `agent-ingest` | only an agent-document hold is releasable |
| Lone override phrase, `agent-ingest` | only an agent-document hold is releasable |
| Lone override phrase, `agent-document` | not held (notes are recorded, not held) |
| Install guide, default policy | only an agent-document hold is releasable |
| PDF with a JavaScript open action, `agent-document` | not a policy hold |
| Encrypted PDF, `agent-document` | incomplete scan |

**Rule edits.** A rule edit changes the ruleset digest, so the key changes. The sha256 and rule ids stay the same.

**Tampering.** The log catches all of these:
- an edited earlier line, or an edited newest line;
- a deleted first line, or a deleted newest line (a suffix);
- a truncated tail;
- a deleted head file, or a deleted log with its head left behind.

A consistent rewrite of both files passes `verify()`, but fails `verify(expected_head=…)` against the head recorded before the rewrite.

**Concurrency.** Eight threads appending at once leave an eight-entry chain that verifies.

**Reasons.** A reason that is empty, whitespace, longer than 500 characters, or contains U+202E or a newline is refused before anything is written.

Each case in `tests/test_release.py` was run by calling the test function directly, with every parametrized case unrolled: 23 calls. CI runs the suite.

## Limits

- **Tamper evidence, not authentication.** Anyone who can write the gate home can rewrite the log and its head together, just as they could move a file from `blocked/` to `clean/` by hand. A head copied outside the gate home is what detects that.
- **Policy selection is the caller's.** A caller that scans a message as `agent-document` makes it releasable, so decision 2 holds only while callers honour the classification contract.
- **Windows identity.** There is no uid on Windows, so the user name is the only identity there.
- **Not a review record.** The log records that an operation happened, not how good the review was.
