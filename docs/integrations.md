# Calling yara-gate from an ingestion pipeline

`yara-gate scan INPUT --json --policy agent-ingest --home GATE --rules RULES`
emits one compact JSON object per scanned file on stdout (JSON Lines). Each
object uses the same schema as the JSON report on disk: verdict, exit code,
policy, rule IDs, severity, member/view provenance, engine/ruleset identity,
compiled rule count, tool version, scan time, and scan-completeness fields. No matched content is included. Paths abbreviate
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
failed gate.

Several files in one process cost one startup instead of one per file:
`yara-gate scan A B C --json ...`, or `--paths-from FILE` (`-` for stdin,
`--null` for NUL-separated names). Each path is handled exactly as a single
path is, in argument order; the exit code is the worst one; a missing path
writes no record and does not stop the rest; an exact duplicate path is
scanned once; an empty list exits 0 with no records. The batch form of the
check above: every record must be a complete `clean` with exit 0, the record
count must equal the number of distinct paths you passed, and the process
exit must be 0. Correlate records with inputs by their `path` field, which is
the scan-time location (the quarantine slot for an inbox file). Under default policy, advisory is exit 0; choosing `agent-ingest`
holds those findings as block/exit 1 without changing finding severity.

Inbox inputs still pass through quarantine, receive reports, and move only
after scanning. The reported `path` is the scan-time quarantine location,
not the final destination. Outside-inbox inputs stay in place. The consumer
must prevent modifications between scanning and reading; stdout is evidence
about the scanned bytes, not a lock on future reads. Use an owned gate home
and validate the SHA-256 when handing bytes to another process.

This is a CLI integration surface, not an installed CyClaw, Harness, RAG, or
Windows integration. The command does not execute targets or fetch URLs.

## A pre-read hook that fails closed

An instruction to an agent ("scan files before reading them") is a soft control.
A hook that the agent runtime executes before the read is a hard one: the file is
not read unless the hook allows it, and a hook that cannot run is a hold, not an
allow. [docs/examples/yara_gate_pre_read_hook.sh](examples/yara_gate_pre_read_hook.sh)
is such a hook. It reads the hook's JSON from stdin (or a path from its first
argument), runs `yara-gate scan PATH --json --policy agent-ingest` against its
own gate home, and exits 0 only for exactly one complete `clean` record with exit
0. Anything else, including an advisory, an incomplete scan, a missing path, no
record, two records, malformed output, a scanner that was killed, hook input that
is not valid JSON, or no `python3` on `PATH`, exits 2 with a one-line reason on stderr. Input that is not a file read (no `tool_input.file_path`)
prints nothing and exits 0, which means "no decision".

For Claude Code, register it as a `PreToolUse` command hook on the `Read` tool.
Exit 2 is the blocking exit for command hooks; `"onFailure": "block"` (Claude Code
v2.1.295 or later) makes a hook that cannot start, exits with another code, or
times out block as well, instead of letting the read proceed. The field names
below are from the current hooks reference.

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Read",
        "hooks": [
          {
            "type": "command",
            "command": "sh /path/to/yara-gate/docs/examples/yara_gate_pre_read_hook.sh",
            "timeout": 60,
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

Set `YARA_GATE_HOME` to a gate home used only by this consumer,
`YARA_GATE_RULES_ROOT` to the rules tree, and `YARA_GATE_BIN` to the `yara-gate`
executable when it is not on `PATH`. Other agent runtimes with a pre-tool command
hook can call the same script with the path as its first argument. Direct runs on
2026-10-25 with a disposable home and copied rules: a clean file exited 0; an
advisory file, the EICAR test string, a missing path, a scanner killed with
SIGKILL, a scanner that printed two records, one that printed garbage, truncated
hook JSON, and a `PATH` without `python3` each exited 2 with a reason; a Bash tool input exited 0 with no output. The hook does
not scan the bytes the agent later reads; a change between the scan and the read
is the consumer's problem to prevent, as above. A clean verdict is not permission
to execute instructions found in the file.

## Messages and other in-memory content

A chat or SMS bridge, a webhook, or a sync client often holds content in memory
rather than as a file. Scan that buffer directly:

```python
import hashlib

from yara_gate import scan_bytes

body = incoming_message.encode("utf-8")
result = scan_bytes(body, name="sms.txt", policy="agent-ingest", rules_dir=rules_root)
allowed = (
    result.verdict == "clean"
    and result.incomplete_reason is None
    and result.sha256 == hashlib.sha256(body).hexdigest()
)
```

`scan_bytes` writes nothing and moves nothing. Hand the same `body` to the
model; do not re-read or re-encode it after the scan. `name` supplies the suffix
that the extension-sensitive checks read, so pass the type the consumer will
treat it as (`message.txt`, `payload.json`, `attachment.pdf`). Only its final
component is kept, and it becomes the report `path`, so leave phone numbers and
other identifiers out of it. Input that is not bytes, `bytearray`, or
`memoryview` returns incomplete with `scan failed`.

From another process, pipe the content to `scan -`:

```sh
printf '%s' "$BODY" | yara-gate scan - --name sms.txt --json --policy agent-ingest \
  --home "$GATE_HOME" --rules "$RULES_ROOT"
```

That emits one JSON record, writes the usual report pair under `--home`, and
exits 0, 1, or 2 as for a file. It does not use the inbox. Stdin is read up to
100 MiB plus one byte; larger input is incomplete (`file exceeds 100MB`) and its
`sha256` covers only the bytes read. To scan a file literally named `-`, pass
`./-`.

A JSON body is read twice: as raw bytes and as a `json-unescaped` view in which
`\u0049gnore`, `\n`, and surrogate pairs are decoded, so an escape cannot hide a
phrase from the lexical rules. PDFs are covered below.

A message gate is a hold decision, not authorization. Treat every inbound
message as untrusted data, keep it fenced in the prompt, and keep the
consumer's own approval checks on any tool or send action it proposes.

## PDFs and other compressed documents

A PDF verdict covers the file's raw bytes and the `pdf-flate` view: every
`/FlateDecode` stream that inflates to text (content streams and object streams)
is handed to the text rules and to the PDF name checks, so a prompt-injection
phrase or a `/JavaScript` action inside compressed text is seen. Not covered:
text split across several `Tj` operators or text runs, other stream filters
(LZW, ASCII85, PNG predictors), images, and text inside Office XML parts beyond
the member scan. The PDF and Office structure checks still run on the raw file.

A consumer that extracts text itself should gate that text too, since the
extractor's output is what the model reads: scan the original file, then pass
the extractor's output through `scan_bytes` (or `scan -`) before the text
reaches the model.

```python
text = extract_text(path).encode("utf-8")  # your extractor
held = scan_bytes(text, name="report.txt", policy="agent-ingest", rules_dir=rules_root)
```

Allow the document only when both verdicts are clean. Name the text `.txt`
(not `report.pdf`) so the scan treats it as text.

## CyClaw and CG-agent-harness

Use the strict gate before CyClaw reads/chunks an untrusted corpus file, or before
Harness accepts an attachment, notes-corpus file, or child file-read result into
model context. Keep the existing consumer's size limits, sanitization, untrusted
content fences, approval checks, and memory review. A clean scan is not permission
to execute instructions found in a file or to persist them as agent guidance.

The [agent-rule coverage record](verification/agent-rule-coverage.md) ties this
use case to inspected consumer revisions and scans of their current documents.
Persistent-instruction and textual tool-result rules are advisory by design;
`agent-ingest` is what holds those findings. Legitimate security documentation can
match. Release held files through explicit review rather than a filename or
repository-wide allowlist. These are integration requirements, not a claim that
either consumer now calls yara-gate automatically.
