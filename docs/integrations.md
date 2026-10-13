# Calling yara-gate from an ingestion pipeline

`yara-gate scan INPUT --json --policy agent-ingest --home GATE --rules RULES`
emits one compact JSON object per scanned file on stdout (JSON Lines). Each
object uses the same schema as the JSON report on disk: verdict, exit code,
policy, rule IDs, severity, member/view provenance, engine/ruleset identity,
and scan-completeness fields. No matched content is included. Paths abbreviate
the user's home prefix; other path components remain visible.

The default human-readable output is unchanged when `--json` is absent.
Diagnostics for failures before a file can be scanned go to stderr and return
exit 2. A missing path therefore produces no JSON record. An empty directory
also produces no records, but exits 0. A directory scan emits multiple records
and returns the highest exit code; earlier completed records do not establish
that the entire operation completed.

For one file, an ingestion caller can require a complete clean verdict:

```python
import json
import subprocess

completed = subprocess.run(
    [
        "yara-gate",
        "scan",
        input_path,
        "--json",
        "--policy",
        "agent-ingest",
        "--home",
        gate_home,
        "--rules",
        rules_root,
    ],
    capture_output=True,
    text=True,
    check=False,
)
records = [json.loads(line) for line in completed.stdout.splitlines()]
allowed = (
    completed.returncode == 0
    and len(records) == 1
    and records[0]["policy"] == "agent-ingest"
    and records[0]["verdict"] == "clean"
    and records[0]["exit_code"] == 0
    and records[0]["incomplete_reason"] is None
)
```

Treat malformed output, unexpected record counts, or process failure as a
failed gate. Under default policy, advisory is exit 0; choosing `agent-ingest`
holds those findings as block/exit 1 without changing finding severity.

Inbox inputs still pass through quarantine, receive reports, and move only
after scanning. The reported `path` is the scan-time quarantine location,
not the final destination. Outside-inbox inputs stay in place. The consumer
must prevent modifications between scanning and reading; stdout is evidence
about the scanned bytes, not a lock on future reads. Use an owned gate home
and validate the SHA-256 when handing bytes to another process.

This is a CLI integration surface, not an installed CyClaw, Harness, RAG, or
Windows integration. The command does not execute targets or fetch URLs.
