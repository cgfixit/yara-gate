# Document read rule: clean, or an exact notes-only agent-document record

Base: `main` `693bca1`. YARA-X `1.22.1`, Python 3.12, Linux container, disposable gate homes and rules roots. This implements owner decision 4 on #39 (2026-10-31).

## What changed

- **`docs/integrations.md`.** It now routes content by kind:
  - messages, tool results, webhook bodies, and attachments from an unknown sender go under `agent-ingest` and are read only on a complete `clean` record;
  - corpus, repository, synced, and file-read documents go under `agent-document` and are read on a complete `clean` record or the exact notes-only record.
- **The predicate.** The guide gives it as a checklist and as `document_readable`. The guide's earlier example accepted any `advisory` verdict under `agent-document`, which is the generalization the decision rules out, and is replaced.
- **`docs/examples/yara_gate_pre_read_hook.sh`.** It defaults to `agent-document` and applies the predicate, including the SHA-256 of the file as read. `YARA_GATE_POLICY=agent-ingest` makes it clean-only, and any other value blocks.
- **`docs/examples/sync_folder_gate.py`.** It gains `--policy`, defaulting to `agent-document`, and the same predicate.
- **`README.md` and `docs/rules.md`.** They state the two read rules. They also say that moving a rule to `note` widens what agents read, and so is an integration change.

## Direct runs

Four files: a plain note, a bare override phrase, an Ollama `curl … | sh` install guide, and a PDF with a JavaScript open action.

| Caller | Policy | plain | phrase | install guide | JS PDF |
| --- | --- | --- | --- | --- | --- |
| Pre-read hook (exit) | agent-document | 0 | 0 | 2 | 2 |
| Pre-read hook (exit) | agent-ingest | 0 | 2 | 2 | 2 |
| Pre-read hook (exit) | anything else | 2 | 2 | 2 | 2 |
| Sync folder gate | agent-document | allowed | allowed | held | held |
| Sync folder gate | agent-ingest | allowed | held | held | held |
| `document_readable`, from the guide verbatim | agent-document | true | true | false | false |

The sync folder was unchanged after both runs. Starting from the real notes-only record, ten one-field mutations were each rejected by `document_readable`: a SHA-256 mismatch, `policy` `agent-ingest`, a different `policy_reason`, `note` false, `advisory` true, `exit_code` 1, an `incomplete_reason`, empty findings, an added advisory finding, and `verdict` block.

Checks: ruff check and format, `check_text_controls.py`, `check_scan_only.py`, and `sh -n` on the hook. No CI script or test runs these examples, so this direct run is their only execution evidence.

## Limits

- **The hook hashes the file after the scan.** A file changed in between fails the hash check and is held. A file changed after the hook allows it is outside the hook's reach.
- **Routing is the caller's job.** The scanner cannot tell a message from a document.
- **Reading is not obeying.** A document read under this rule may contain an override phrase, so keep its content fenced as untrusted data.
