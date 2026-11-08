# Integration examples

These are reference integrations, not a substitute for consumer authorization and deployment review. See [integrations](../integrations.md) for policy, ownership, and failure-handling requirements.

- [`sync_folder_gate.py`](sync_folder_gate.py) stages settled sync-folder files and moves verified copies to allowed or held storage without deleting the synced original. Admissions are bound to the detector identity, stale allowed copies are withdrawn, and a hung scan is killed and retried.
- [`yara_gate_pre_read_hook.py`](yara_gate_pre_read_hook.py) scans a captured buffer and hands off those exact bytes or a private snapshot; consumers must not reopen the original as a substitute.
- [`yara_gate_pre_read_hook.sh`](yara_gate_pre_read_hook.sh) is the shell entry point for that hook and fails closed if Python is unavailable.
- [`sms_gate_bridge.py`](sms_gate_bridge.py) illustrates signature-checked Twilio SMS intake, scanning text and holding MMS for review, and processes each `MessageSid` once; it does not fetch media URLs.
