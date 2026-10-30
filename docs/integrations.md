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

## Which entry point to use

CyClaw, CG-agent-harness, and any other caller use the same CLI or library call.
Pick the row by where the content lives when the caller first sees it.

| Content arrives as | Call | Read afterwards |
| --- | --- | --- |
| A file on disk that the caller owns | `yara-gate scan PATH --json --policy agent-ingest` | The same path, after the SHA-256 in the record matches the bytes you read |
| Several files at once | `scan A B C` or `--paths-from FILE`, same flags | Each path whose record is a complete `clean`, matched by `path` |
| A file the gate should take over | Drop it in the gate `inbox/`; `scan` or `watch` quarantines it | `clean/<sha256>/` only |
| A message, webhook body, or tool result in memory | `scan_bytes(body, name=..., policy="agent-ingest")` or `scan - --name ...` | The same `body` bytes, never a re-read or re-encode |
| A file in a sync client's folder | Copy it out first ([Synced folders](#synced-folders-dropbox-onedrive-icloud-drive)) | `allowed/<sha256>/` only |
| An agent runtime's file-read tool | The [pre-read hook](#a-pre-read-hook-that-fails-closed) | Whatever the hook allowed |

One rule covers every row: **the content is read only when its own input has exactly
one complete `clean` record** (`verdict == "clean"`, `incomplete_reason is None`,
`policy == "agent-ingest"`) **and the process did not exit 2**. `--json` writes one
record per line. For a single input, that means exit 0. A batch exits with its worst
result, so exit 1 still lets a path with its own complete `clean` record through,
while exit 2 means read nothing from that batch. No record, a malformed line, a
crash, or a timeout all mean "not scanned, do not read". A caller must not turn
"the scanner failed" into "nothing was found".

Two things the gate does not decide for the caller: whether a clean file's
instructions may be followed (they may not; keep content fenced as data), and who
releases a held file. Release is a human review of the report, not a filename or
repository-wide allowlist.

## Synced folders (Dropbox, OneDrive, iCloud Drive)

A sync client's folder is never the gate's inbox. Inbox intake copies its input
into `quarantine/<sha256>/` and then removes the inbox entry; a sync client would
treat that as a deletion and propagate it to every other device and shared-folder
member. A directory scan of an inbox also consumes client metadata (`.dropbox`,
`.DS_Store`, `desktop.ini`); only `watch` skips dotfiles. Two more facts decide the
design: inbox intake needs `O_NOFOLLOW` and a link count, which Python provides on
Unix only, so on Windows there is no quarantine, no clean slot, and no settle
logic, only in-place scans; and the inbox settle logic takes a file whose last
write is a second old, so a writer that pauses longer than that is scanned
truncated and the rest of its write is lost with the removed inbox entry.

The consumer therefore copies, never moves, out of the sync folder into a
directory the gate owns, and reads only what the gate allowed:

1. Walk the sync folder without following links. Skip dotfiles and client
   metadata (`.dropbox`, `.DS_Store`, `desktop.ini`, `Icon\r`, `~$` Office locks,
   `.tmp`, `.part`, `.crdownload`), symlinks and other non-regular entries, Windows
   reparse points (junctions and online-only cloud placeholders: a read would make
   the client download them, which is a network side effect the gate must not
   cause), and zero-length files (a placeholder, or a write in progress).
2. Take a file only when two looks at least a second apart agree on its size and
   mtime, then copy it through a temporary name and rename it into the gate's
   staging directory, so no watcher sees a partial copy. Compare the source's size
   and mtime again after the copy and drop the copy if they changed.
3. Scan the staged copy with `yara-gate scan STAGED --json --policy agent-ingest
   --home GATE_REPORTS --rules RULES`. Allow it only for exit 0, exactly one record,
   `verdict` `clean`, `exit_code` 0, `incomplete_reason` null, `policy`
   `agent-ingest`, and a record `sha256` equal to the SHA-256 of the staged bytes.
   Everything else, including a scanner that did not start, is held.
4. Move the staged copy into `allowed/<sha256>/` or `held/<sha256>/` with the
   record beside it. The consumer reads `allowed/` only. The sync folder is never
   written, so a later change there cannot reach bytes already allowed, and a
   changed source arrives as a new SHA-256 on the next pass.
5. Keep a ledger of path, size, mtime, and SHA-256 so unchanged files are not
   rescanned. The ledger and the records hold no file content.

[docs/examples/sync_folder_gate.py](examples/sync_folder_gate.py) does exactly
this with the standard library, on Windows, macOS, and Linux. On a POSIX host the
staging directory may instead be the gate's own `inbox/`, which adds the
quarantine and `clean/` slot semantics on top. A `conflicted copy` file (two
devices edited one file offline) is scanned like any other and named in the log;
whether to allow such files is the consumer's policy. A direct run on 2026-10-29
against a fake sync folder holding a clean file, an injected file, a `.dropbox`
marker, `desktop.ini`, an Office lock file, a `.crdownload`, a zero-byte `.pdf`, a
symlink, a conflicted copy with injected text, and a file still being appended:
the two injected files and the conflicted copy were held, the clean file allowed,
every metadata, link, and placeholder entry skipped with a reason, the growing
file skipped as `changing` and allowed whole on the next pass, the sync folder's
listing and bytes unchanged afterwards, the allowed copies' SHA-256 equal to their
records, no file content in the ledger or records, and a gate home inside the sync
folder refused with exit 2.

Not established here: how the Dropbox client itself writes (temporary name and
rename, or in place), how its online-only placeholders look on each OS, whether it
marks synced files with a Windows `Zone.Identifier` stream or a macOS
`com.apple.quarantine` attribute (the gate's copy drops both), and which device or
member wrote a file (only the client's own log knows). Test each on a real client
before relying on it; the skip rules above fail closed when in doubt.

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

A JSON body (text that opens with `{` or `[` followed by a JSON token, not an INI header such as `[Section]`) is read twice: as raw bytes and as a `json-unescaped` view in which
`\u0049gnore`, `\n`, and surrogate pairs are decoded, so an escape cannot hide a
phrase from the lexical rules. Any text body also gets a `text-folded` view when
fullwidth letters, a Cyrillic or Greek look-alike inside a Latin word, leet digits,
spaced-out letters, or a control character would otherwise keep a phrase from the
rules. PDFs are covered below.

A mail message with a MIME body (an `.eml` file, or the raw bytes a mail hook or
IMAP client holds) is opened as a container, like a zip: each decoded leaf part, a
quoted-printable or base64 body, an attachment, the leaves of a forwarded message,
is scanned as a member `mime:N`, where `N` is the part's position in the message and
never its name. The attachment's own file name drives the name and type checks, so
an `Invoice.pdf.exe` attachment blocks and a `report.pdf` that is really a program
is a `filetype_mismatch_pe`, and a soft line break or base64 wrapping cannot split a
phrase from the lexical rules. A text part declared in a legacy charset
(`iso-8859-1`, `windows-1252`) is transcoded to UTF-8 for its member view. The raw
message is scanned as well. Plain text with mail-like headers but no encoded or
multipart body, an HTTP response, and prose that mentions `Content-Type:` are not
containers. A message that carries an executable attachment blocks as
`heuristic_document_executable`, as a `.docx` carrying an `.exe` does, and the
shared size, count, depth, and deadline limits apply to the decoded parts.

A message gate is a hold decision, not authorization. Treat every inbound
message as untrusted data, keep it fenced in the prompt, and keep the
consumer's own approval checks on any tool or send action it proposes.

## PDFs and other compressed documents

A PDF verdict covers the file's raw bytes and the `pdf-flate` view: every
`/FlateDecode` stream that inflates to text (content streams and object streams)
is handed to the text rules and to the PDF name checks, so a prompt-injection
phrase or a `/JavaScript` action inside compressed text is seen. A Word, Excel,
or PowerPoint verdict covers each XML member and an `ooxml-text` view that joins
the text runs of the body, headers, footers, notes, comments, shared strings, and
slides, so a sentence Word split across formatting runs (the usual case) is seen
whole. Not covered: PDF text split across several `Tj` operators, other stream
filters (LZW, ASCII85, PNG predictors), images, and Office parts a reader does
not see (settings, styles). The PDF and Office structure checks still run on the
raw file.

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
