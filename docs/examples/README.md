# Integration examples

These are reference integrations, not a substitute for consumer authorization and deployment review. See [integrations](../integrations.md) for policy, ownership, and failure-handling requirements.

- [`sync_folder_gate.py`](sync_folder_gate.py) stages settled sync-folder files and moves verified copies to allowed or held storage without deleting the synced original. Admissions are bound to the detector identity, stale allowed copies are withdrawn, and a hung scan is killed and retried.
- [`yara_gate_pre_read_hook.py`](yara_gate_pre_read_hook.py) scans a captured buffer and hands off those exact bytes or a private snapshot; consumers must not reopen the original as a substitute.
- [`yara_gate_pre_read_hook.sh`](yara_gate_pre_read_hook.sh) is the shell entry point for that hook and fails closed if Python is unavailable.
- [`sms_gate_bridge.py`](sms_gate_bridge.py) illustrates signature-checked Twilio SMS intake, scans text, holds MMS for review, and recovers JSONL queue writes using `MessageSid` and a SQLite transaction. Media URLs are left unopened.
- [`conform_agreement.py`](conform_agreement.py) stands in for a consumer's extractor: it reads the exported [conformance](../conformance.md) fixtures with `pdftotext` and a text-node HTML reader and prints the capture `yara-gate conform --agreement` compares with the file scans.

These examples manage consumer staging and handoff. For a gate-owned `clean/`
folder, use [`yara-gate rescan`](../integrations.md#revalidating-admitted-files)
after a detector, rule, or policy change. Use [`yara-gate held`](../integrations.md#listing-held-items)
to inspect the current gate-owned queue.
