# Reviewed release of an agent-document hold (#39)

Base: `main` `693bca1`. YARA-X `1.22.1`, Python 3.12, Linux container (root), disposable gate homes and rules roots.

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

`tests/test_release.py` holds these cases and two CLI tests. Each test function was run by calling it directly, 17 calls in all. CI runs the suite.

## The release command, on conservative assumptions

The four decisions above were open when this was built. Each takes its narrowest answer, stated in `release.py` and changeable in one place:

1. **Gate-home only.** `apply_release` runs in `process_inbox_file` and `scan_in_place`. `scan_bytes` and `scan -` never consult releases.
2. **agent-document only.** `RELEASABLE_POLICIES = (agent-document,)`. A message held under `agent-ingest` is never released.
3. **No dependency on rule fixes.** The command works whatever the rule tiers are.
4. **No read-rule change.** A released result keeps its findings, is `advisory` with `policy_reason` `agent-document hold released by review`, and exits 0. In the inbox flow it moves to `clean/`. The integrations read rule still requires `clean`, so an in-place caller must opt in.

`yara-gate release SHA256 --reason TEXT [--home] [--rules] [--non-interactive]`, or `--path FILE` for a file scanned in place. The command:

- refuses without a terminal unless `--non-interactive` is passed;
- re-hashes the held copy, rescans it under `agent-document` with the current rules, and refuses anything `release_refusal` rejects;
- appends to the log before it writes the report or moves the copy from `blocked/` to `clean/`, and prints the new log head.

`--verify-log` checks the chain. The log is also the store, and a log that does not verify voids every release.

### End-to-end run (real CLI processes, disposable home)

| Step | Exit | Outcome |
| --- | --- | --- |
| Install guide into the inbox under `agent-document` | 1 | `blocked/` |
| `release` with stdin not a terminal | 2 | refused |
| `release --non-interactive --reason …` | 0 | moved to `clean/`, one log entry |
| The same bytes into the inbox again | 0 | advisory, `released by review`, `clean/` |
| The same bytes under `agent-ingest` | 1 | `blocked/` |
| The same bytes on stdin under `agent-document` | 1 | held |
| JavaScript PDF, then `release` | 1, then 1 | `refused: not a policy hold`, stays in `blocked/` |
| Encrypted PDF, then `release` | 2, then 1 | `refused: incomplete scan`, stays in `quarantine/` |
| Malformed digest; unknown digest | 2 | refused |
| Reason containing U+202E | 2 | refused, nothing logged |
| Rule edited, same bytes again | 1 | held: the ruleset digest changed |
| Rules restored, same bytes again | 0 | released again |
| Log with a duplicated line, same bytes again | 1 | held; `--verify-log` exits 2 |
| In-place scan, `release --path`, scan again | 1, 0, 0 | released in place |

The log's fields other than the operator's reason hold no content, names, or paths. Reports hold no content; their `path` field records the scanned name as it always has.

### Limits

- The chain is tamper evidence, not authentication. Anyone who can write the gate home can append a correctly chained entry, just as they could move a file from `blocked/` to `clean/` by hand. The gate home's permissions (`0700`) are the boundary.
- An edit to the newest line alone passes `verify`. Record the printed head elsewhere to detect it.
- The reason is stored as typed.
- Appends are not locked; one operator at a time is assumed.

## Not built

`--list-stale` (releases whose ruleset no longer matches), and anything that widens the four conservative answers, wait on the owner's decisions. `watch` has no code path that releases.
