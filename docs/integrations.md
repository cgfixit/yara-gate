# Calling yara-gate from an ingestion pipeline

`yara-gate scan INPUT --json --policy agent-ingest --home GATE --rules RULES`
emits one compact JSON object per scanned file on stdout (JSON Lines). Each
object uses the same schema as the JSON report on disk: verdict, exit code,
policy, rule IDs, severity, member/view provenance, engine/ruleset identity,
compiled rule count, detector digest, tool version, scan time, and completeness fields. No matched content is included. Paths abbreviate
the user's home prefix; other path components remain visible.

The digest-named JSON and SARIF are latest-report views. Each saved scan also
writes `reports/events/<scan-id>.json` before relocation, with `schema_version`,
`scan_id`, and UTC `recorded_at` alongside the compact report. Events can exist
before a pending move completes. Use the returned record and verify the bytes for
admission. Use the event files to inspect older scan contexts. If a deployment
requires a particular reviewed vendor inventory, also require its expected
`ruleset_sha256` and review the reported skip count before admitting files. Use
`detector_sha256` separately when caching admission across scanner builds.

Dense or deeply nested JSON/notebooks can be incomplete before an object tree is
allocated. Treat the [JSON parsing limits](rules.md#json-parsing-limits) like other
coverage limits: exit 2 is a hold even when the findings list is empty.

A view of a megabyte or more that fills a string's match list is scanned once
more at a higher limit when the time left allows, and the scan is incomplete
(`match cap reached`) when a list is still full. `match_rescan_limit` in the record is non-null when that second scan ran,
and `unguarded_rule_files` counts the rule files it does not cover
([match limit](rules.md#limits)). The scanner sets no memory ceiling: a synthetic
worst case peaked at 2.3 GB ([measured](verification/2026-11-19-rescan-memory.md)).
A consumer that needs a ceiling sets it on the worker process, beside the hard
timeout below.

The default human-readable output is unchanged when `--json` is absent.
Diagnostics for failures before a file can be scanned go to stderr and return
exit 2. A missing path therefore produces no JSON record. An empty directory
also produces no records, but exits 0. A directory scan emits multiple records
and returns the highest exit code; earlier completed records do not establish
that the entire operation completed.

Pick the policy by what the content is, then apply that policy's read rule
([Which entry point to use](#which-entry-point-to-use) lists both):

- **A message, tool result, webhook body, or anything a third party sent into the
  conversation:** `--policy agent-ingest`, and read only a complete `clean` record.
- **A document the agent retrieves from a corpus, repository, or synced folder:**
  `--policy agent-document`, and read a complete `clean` record or an exact
  notes-only record. File consumers can also opt in to [reviewed releases](#reviewed-document-releases). The predicate is in
  [Documents that quote attacks](#documents-that-quote-attacks).

For one message-like file, an ingestion caller requires a complete clean verdict:

```python
import json
import subprocess

# The scanner's own deadline cannot preempt every parser, so the parent's is hard.
# subprocess.run kills the child and raises TimeoutExpired: treat that as a hold.
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
        "--timeout",
        "30",
    ],
    capture_output=True,
    text=True,
    check=False,
    timeout=60,
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
scanned once. An empty list exits 0 with no records. For all-or-nothing
admission of explicit file paths, require process exit 0 and exactly one valid,
policy-allowed record for each expected file. Directory inputs can expand to
multiple records. Correlate records with scanned paths and digests. For inbox
inputs the reported path is the quarantine slot, so use the disposition and
digest to find the admitted copy.

Inbox inputs still pass through quarantine, receive reports, and move only
after scanning. The reported `path` is the scan-time quarantine location,
not the final destination. Outside-inbox inputs stay in place. The consumer
must prevent modifications between scanning and reading; stdout is evidence
about the scanned bytes, not a lock on future reads. Use an owned gate home
and validate the SHA-256 when handing bytes to another process.

This is a CLI integration surface, not an installed CyClaw, Harness, RAG, or
Windows integration. The command does not execute targets or fetch URLs.

## Previewing policies in the local workbench

Run `yara-gate demo --rules /path/to/rules` and open its printed loopback URL to
compare the real scanner's policy outcomes before wiring a consumer. The UI
starts on `agent-ingest`; its note and advisory examples make the difference
between message, document, and default policies visible. **Run every pair**
scans the demo catalog under the selected policy and marks any result that
differs from its reviewed expectation: run it after adding local or vendor rules
to see whether one of them reports a benign twin. Results show the
original finding severities, policy reason, derived/member provenance, and
coverage from the configured rules. A skipped-rule warning is reduced coverage,
and an incomplete result is a hold even when partial findings exist.

This preview does not connect to CyClaw or CG-agent-harness, read their folders,
move/release files, or call an agent. Integrate at the owning caller: before a
CyClaw message becomes a query or a staged corpus file is indexed, and before a
Harness attachment, fetched page, or tool result enters prompt assembly. Keep
their existing consent, write approvals, and untrusted-content fences.

The demo's HTTP endpoint and reduced response are for the page. Production
callers use the CLI/library contracts below, including record counts, policy,
completeness, and byte identity. Never turn a displayed exit 0 or an earlier
preview into permission to read changed content. The browser paste is always
named `paste.txt`; use the original type/name when gating a real file.

Pastes are limited to 64 KiB of UTF-8 and scanned in memory. The app stores no
scan history or content and sends scans only to its loopback server. Expanding
JSON reveals hashes and metadata, which can identify known content even without
matched bytes. This UI is neither an authenticated multi-user service nor a remote
API; the [user guide](../user-guide.md#9-try-a-verdict-in-the-browser) covers its
controls and privacy limits.

## Which entry point to use

CyClaw, CG-agent-harness, and any other caller use the same CLI or library call.
Pick the row by where the content lives when the caller first sees it.

| Content arrives as | Call | Read afterwards |
| --- | --- | --- |
| A document on disk that the caller owns (corpus file, repository file, staged copy) | `yara-gate scan PATH --json --policy agent-document` | The same path, after the SHA-256 in the record matches the bytes you read |
| A message-like file (an attachment from an unknown sender, a saved tool result, a fetched web page) | `yara-gate scan PATH --json --policy agent-ingest` | The same path, after the SHA-256 in the record matches the bytes you read |
| Several files at once | `scan A B C` or `--paths-from FILE`, same flags | The verified copies after the batch passes the checks above |
| A file the gate should take over | Drop it in the gate `inbox/`; `scan` or `watch` quarantines it | `clean/<sha256>/` only |
| A message, webhook body, or tool result in memory | `scan_bytes(body, name=..., policy="agent-ingest")` or `scan - --name ...` | The same `body` bytes, never a re-read or re-encode |
| A file in a sync client's folder | Copy it out first ([Synced folders](#synced-folders-dropbox-onedrive-icloud-drive)) | `allowed/<sha256>/` only |
| An agent runtime's file-read tool | The [pre-read hook](#a-pre-read-hook-that-fails-closed) | The returned snapshot path; a byte consumer uses `--bytes PATH` and consumes stdout only on exit 0 |

The two read rules from the top of this guide cover every row: a message needs
exactly one complete `clean` record and no exit 2; a document needs that or the
exact notes-only `agent-document` record. A file consumer can also check the
separate [reviewed release branch](#reviewed-document-releases). For the batch
recipe above, exit 1 or 2 withholds the batch, even if it contains individual
clean records. Withhold access if records are missing or malformed, or if the
process crashes or times out.

Two things the gate does not decide for the caller: whether a clean file's
instructions may be followed (they may not; keep content fenced as data), and who
reviews a held file. Use [the held index](#listing-held-items) to review the queue. Only eligible
`agent-document` holds can be cleared by [a reviewed release](#reviewed-document-releases).

## Revalidating admitted files

`clean/` records an admission at scan time. After changing rules, detector code, or
policy, pause downstream readers and stop the watcher, then run:

```bash
yara-gate rescan --home GATE --rules RULES --policy agent-ingest --dry-run
yara-gate rescan --home GATE --rules RULES --policy agent-ingest
```

The explicit command applies changes by default. It takes the watch lock and the
intake lock; a running watcher refuses the pass. It never releases or rescans an
existing blocked or quarantined copy. Watch startup does not invoke it. Pending
intake must first be recovered by the existing intake/watch path.

Every clean copy is opened under the intake regular-file, single-link and byte-limit
checks and hashed. A complete clean report with the same bytes, filename, policy,
ruleset and detector identity skips scanning. Missing, malformed or stale reports
and every advisory admission are scanned again. Missing recorded vendor rules make
rescans incomplete, including with a warm compiled cache. Reviewed releases are not
applied by this command; a document may need fresh review after revalidation.

Fresh JSON and SARIF reports precede relocation. Blocks move to `blocked/<digest>/`;
incomplete copies move to `quarantine/<digest>/`; allowed copies remain in place.
Changed or unreadable bytes have an unknown (zero) report digest, stored under the
original slot identifier. Existing held destinations are never overwritten. Malformed
slot layouts, pending intake, report-write or relocation failures abort with exit 2;
remaining copies are unvalidated. A retry rechecks any non-clean report. Keep consumers
paused until the error is resolved and a full pass finishes. This is a maintenance
pass, not a transaction across the whole home or protection against another process
writing files or rules during the pass. It cannot withdraw bytes a consumer already
copied; consumers still need their own exact-byte identity and admission checks.

Stdout is JSON Lines: each rescanned item uses the existing compact report schema
plus `dry_run`; the last line contains `dry_run`, `rescanned`, `unchanged`,
`newly_held`, `newly_incomplete`, and `exit_code`. `unchanged` includes both skipped
current clean copies and rescanned copies that remain allowed. Exit 2 takes precedence
when any result is incomplete or the pass aborts, then 1 for any new block, otherwise 0.
Dry runs return those same predicted exits but do not change reports or copies; lock
files and the ordinary compiled-rule cache may still be written. No finding text is
included, and filenames use the usual home-prefix redaction.

## Synced folders (Dropbox, OneDrive, iCloud Drive)

A sync client's folder is never the gate's inbox. Inbox intake copies its input
into `quarantine/<sha256>/<name>` and then removes the inbox entry (unless another
file has replaced it during the copy); a sync client would
treat that as a deletion and propagate it to every other device and shared-folder
member. Both `watch` and an explicit inbox scan consume dotfiles and client
metadata (`.dropbox`, `.DS_Store`, `desktop.ini`). The watcher holds a dropped
directory intact as incomplete; explicit `scan DIRECTORY` still recurses. The inbox settle logic
also takes a file whose last write is a second old, so a writer that pauses longer
than that is scanned truncated and the rest of its write is lost with the removed
inbox entry. On Windows, intake has no `O_NOFOLLOW`: it refuses a symlink,
junction, hardlink, or cloud-file placeholder from its `lstat` before opening, then
requires the opened file to match that `lstat` (#102, exercised by
`docs/verification/check_intake.py` on the `windows-latest` CI job). `watch` still
needs macOS or Linux, and a real Dropbox or OneDrive placeholder has not been
tested on a Windows host.

The consumer therefore copies, never moves, out of the sync folder into a
directory the gate owns, and reads only what the gate allowed:

1. Walk the sync folder without following links. Skip dotfiles and client
   metadata (`.dropbox`, `.DS_Store`, `desktop.ini`, `Icon\r`, `~$` Office locks,
   `.tmp`, `.part`, `.crdownload`), symlinks and other non-regular entries, Windows
   reparse points (junctions and online-only cloud placeholders: a read would make
   the client download them, which is a network side effect the gate must not
   cause), and zero-length files (a placeholder, or a write in progress).
2. Take a file only when two looks at least a second apart agree on its size and
   mtime, then copy it under its original basename in private, unwatched staging.
   Reject files over 100 MiB before copying and cap the copy at 100 MiB even if
   the source grows. Compare the source's size
   and mtime again after the copy and drop the copy if they changed.
3. Scan the staged copy with `yara-gate scan STAGED --json --policy POLICY
   --home GATE_REPORTS --rules RULES`, and allow it only on exit 0, exactly one
   record, that policy's read rule, and a record `sha256` equal to the SHA-256 of the
   staged bytes. Everything else, including a scanner that did not start, is held.
   Pick the policy by who can write to the folder. For a folder other people can
   write to (a shared Dropbox folder), use `agent-ingest` and read clean records only.
   Use `agent-document` and its notes-only rule
   ([below](#documents-that-quote-attacks)) only for a folder whose authors you trust
   to write about attacks. Under `agent-document`, an override phrase in hidden Office
   or PDF text (a vanished, white, or 1 pt run, a hidden shape, invisible PDF text) or
   in HTML text a browser does not show (`display:none`, a comment, a `data-*` value)
   adds the advisory `heuristic_hidden_text` and is held.
4. Move the staged copy into `allowed/<sha256>/` or `held/<sha256>/` with the
   record beside it. The consumer reads `allowed/` only. The sync folder is never
   written, so a later change there cannot reach bytes already allowed, and a
   changed source arrives as a new SHA-256 on the next pass.
5. Keep a ledger of path, size, mtime, and SHA-256 so unchanged files are not
   rescanned. The ledger and the records hold no file content.
6. Bind each admission to the detector that made it. `ruleset_sha256` and
   `tool_version` can stay the same while a reader or heuristic changes a verdict,
   so also record the report's `detector_sha256`, the policy, and the engine
   version, and rescan an unchanged file when any of them differ. Then withdraw
   every `allowed/` copy with no current admission: a deleted or superseded
   source, a copy whose rescan held or failed, or one not yet revalidated. Check
   the identity in each file's record against the probe before admitting it.
   Move withdrawn files outside the read set and drop them from any index.
   Use one gate process per home and coordinate reads with a completed pass.
7. Give each scan a hard parent timeout a little longer than `--timeout`, since
   the scanner's deadline cannot preempt every parser. Kill a scan that overruns,
   ignore its partial output, hold the staged copy, and retry it on the next pass.

[docs/examples/sync_folder_gate.py](examples/sync_folder_gate.py) does exactly
this with the standard library, on Windows, macOS, and Linux. It reads the
detector identity from one in-memory scan of a fixed probe at the start of each
run. If the probe fails, the script withdraws admissions and exits 2. It withdraws to
`withdrawn/<sha256>/` with a `withdrawn.json` reason, and kills a scan 30 seconds
after its `--timeout`. Oversized
sources are logged and make the run exit 2 without being copied. Staging must
stay outside a watched inbox: dot-prefixed names are scanned too. For a separate
inbox producer, finish writing outside the inbox and atomically rename the
completed file into it on the same filesystem. A `conflicted copy` file (two
devices edited one file offline) is scanned like any other and named in the log;
whether to allow such files is the consumer's policy. A direct run on 2026-10-29
against a fake sync folder (clean, injected, metadata, lock, placeholder, symlink,
conflicted-copy, and still-growing entries) held the injected files, allowed the
clean one whole once it stopped changing, skipped every other entry with a reason,
left the sync folder unchanged, and refused a gate home inside it with exit 2.

Not established here: how the Dropbox client itself writes (temporary name and
rename, or in place), how its online-only placeholders look on each OS, whether it
marks synced files with a Windows `Zone.Identifier` stream or a macOS
`com.apple.quarantine` attribute (the gate's copy drops both), and which device or
member wrote a file (only the client's own log knows). Test each on a real client
before relying on it; the skip rules above fail closed when in doubt.

## A pre-read hook that fails closed

A path check cannot authorize a later read of mutable bytes. The
[shell entry point](examples/yara_gate_pre_read_hook.sh) invokes the adjacent
[Python implementation](examples/yara_gate_pre_read_hook.py), which captures one
local regular file into a bounded byte buffer and checks the scan record against
its SHA-256 and policy. Document scans use a private temporary file with the
original basename so the scanner can verify releases in `YARA_GATE_HOME`.
Message scans pass the buffer through stdin.
It never reopens the source after scanning. Links, devices, directories, cloud
placeholders, files over 100 MiB, and invalid or missing read inputs are held.

The default `agent-document` policy permits a complete clean record or the exact
notes-only record defined below, or a verified reviewed release.
`YARA_GATE_POLICY=agent-ingest` permits only
complete clean records. A scan failure, malformed output, missing scanner,
wrong digest, wrong policy, or timeout exits 2 without output content.

For a Claude Code `Read` hook, success writes the scanned buffer to a **new
private, read-only snapshot** and emits `hookSpecificOutput.updatedInput` with
that path. Other read arguments (offset, limit, pages) are preserved. The original
path is never authorized for a later reopen. Replacing or editing the source
before the tool runs does not change the snapshot. Each read gets a new directory;
later hook calls do not replace prior snapshots. The hook does not return
`permissionDecision: allow`. Runtime permissions apply to the rewritten path,
not necessarily the original source: the integration must authorize the original
read before capture (for example, in the owning read-tool wrapper or an OS
sandbox that restricts the hook too). Do not use a snapshot rewrite to bypass a
source-path deny rule. This scanner decides content policy, not filesystem
access rights; an unrestricted hook is not a substitute for the caller's read
authorization.

Register it on the `Read` tool with failure blocking:

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

The [Claude Code hooks reference](https://code.claude.com/docs/en/hooks#pretooluse-decision-control)
defines `updatedInput`; failure blocking requires v2.1.295 or later. The runtime
must honor rewritten arguments and block hook failures. Auto mode can deny a
rewritten call; retain that denial rather than bypassing permission checks. A
runtime that only checks the exit status and reopens the original path is **not
compatible**. Test the actual runtime before deployment; this repository's
subprocess checks do not establish an installed Claude Code integration.

Keep the shell script, Python script, and `sync_folder_gate.py` beside one another.
Set `YARA_GATE_HOME` to a private consumer-owned home outside the source tree,
`YARA_GATE_RULES_ROOT` to the rules tree, and `YARA_GATE_BIN` to the installed
scanner. `YARA_GATE_SCAN_TIMEOUT` defaults to 30 seconds; set the runtime hook
timeout above it. The hook needs Python 3 and the scanner needs its locked Python
environment. It does not install vendor packs.

Snapshots under `YARA_GATE_HOME/read-*/` contain file content, unlike reports.
They are created in mode-0700 directories with mode-0400 files on POSIX; on
Windows, isolate the home with a private ACL. Retain snapshots until all reads
finish, then remove this consumer's `read-*` directories during session cleanup.
Do not delete them from a concurrent hook. Read-only mode protects against
accidental writes, not a process that controls the same OS account or the home.
For that threat model, enforce OS isolation or use the direct byte handoff below.

**Direct byte handoff:** callers that can implement their own read tool should run
`sh docs/examples/yara_gate_pre_read_hook.sh --bytes PATH`, capture stdout as bytes,
wait for exit 0, then pass that exact buffer to the consumer. A nonzero exit means
discard all output. This mode creates no snapshot path and does not depend on a
second filesystem read; source replacement during or after the scan cannot
change the returned buffer. A direct `sh .../yara_gate_pre_read_hook.sh PATH`
without `--bytes` returns the same snapshot-rewrite JSON as hook mode, not a bare
permission to read PATH. Consumers migrating from the old exit-only hook must
use one of these handoffs. Content remains untrusted data even after clearance.

## Messages and other in-memory content

A chat or SMS bridge, a webhook, or a sync client often holds content in memory
rather than as a file. Scan that buffer directly:

```python
import hashlib
from pathlib import Path

from yara_gate import scan_bytes

body = incoming_message.encode("utf-8")
result = scan_bytes(body, name="sms.txt", policy="agent-ingest", rules_dir=Path(rules_root))
allowed = (
    result.verdict == "clean"
    and result.incomplete_reason is None
    and result.sha256 == hashlib.sha256(body).hexdigest()
)
```

Use `agent-ingest` for a message: it holds notes (a lone override phrase) as
well as advisory findings, because an SMS has no structure to judge by and the
phrase is the whole attack. `agent-document` is the opposite choice, for a
retrieved report or test suite that may quote such a phrase; see
[Documents that quote attacks](#documents-that-quote-attacks).

`scan_bytes` writes nothing and moves nothing. Hand the same `body` to the
model; do not re-read or re-encode it after the scan. `name` supplies the suffix
that the extension-sensitive checks read, so pass the type the consumer will
treat it as (`message.txt`, `payload.json`, `attachment.pdf`). Only its final
component is kept, and it becomes the report `path`, so leave phone numbers and
other identifiers out of it. Input that is not bytes, `bytearray`, or
`memoryview` returns incomplete with `scan failed`. So does a `rules_dir` passed as a
string: it must be a `pathlib.Path`, or every input is held.

Besides the injection rules, a message body can match `agent_message_code_relay`:
a request to send or forward a one-time code or a received sign-in link to
someone, the step that hands an account to whoever wrote the message, including
"I just sent you a code, forward it to me". It is advisory, so `agent-ingest`
holds the message. An ordinary code notice ("your code is 482913, do not share
it") stays clean. Three more advisory shapes are common in SMS: an order to use
your own tool to send data to an outside address
(`agent_tool_hijack_directive`), a request to text the keys from a `.env` file
(`agent_secret_transfer_request`), and "this is the system administrator"
followed by an order to override your safety settings (`agent_role_spoof_action`). See [docs/rules.md](rules.md) for
its boundaries.

From another process, pipe the content to `scan -`:

```sh
printf '%s' "$BODY" | yara-gate scan - --name sms.txt --json --policy agent-ingest \
  --home "$GATE_HOME" --rules "$RULES_ROOT"
```

That emits one JSON record, writes the usual report pair under `--home`, and
exits 0, 1, or 2 as for a file. It does not use the inbox. Stdin is read up to
100 MiB plus one byte; larger input is incomplete (`file exceeds 100MB`) and its
`sha256` is unknown (64 zeroes), not a hash of a truncated prefix. To scan a file literally named `-`, pass
`./-`.

A JSON body is also read as a `json-unescaped` view, including one that opens with a
byte order mark or with comments, any text body gets a
`text-folded` view when look-alike, leet, or spaced-out spellings would hide a
phrase, a base64 run that decodes to readable text (UTF-8, or UTF-16LE as
PowerShell writes it) gets a `base64-decoded` view, and `%XX` query text gets a
`percent-decoded` view, so escaping or encoding a phrase does not hide it from the
lexical rules. Each decoded view is also folded, as `json-unescaped+text-folded` and so
on, so an escape stacked on a look-alike spelling is read too, and `text-folded` drops
terminal colour codes such as `ESC [ 1 m` whole, takes an OSC hyperlink or title and other
terminal strings out of the word they sit in, deletes zero-width marks such as U+034F,
and reads VT, FF, and NEL as line breaks. Cyrillic-only words are lowercased
without transliterating ordinary Russian prose. A view label is a provenance chain:
read a finding's `view` to see which decoding found it, and never treat its offset as
a position in the body unless the view is `raw`. The exact view rules are under
[Limits](rules.md#limits).

A mail message with a MIME body (an `.eml` file, or the raw bytes a mail hook or
IMAP client holds) is opened as a container, like a zip: each decoded leaf part is
scanned as a member `mime:N`, where `N` is the part's position and never its name.
The attachment's own file name drives the name and type checks, so an
`Invoice.pdf.exe` attachment blocks and a `report.pdf` that is really a program is a
`filetype_mismatch_pe`; a message that carries an executable attachment blocks as
`heuristic_document_executable`. The header block is read up to 64 KiB, so a long
relay or ARC chain does not keep a message closed. A message with one body is a
container when a mail reader shows something other than its bytes: a base64,
quoted-printable, or uuencoded body, an HTML body, or text in a charset other than
UTF-8 or ASCII; its body is member `mime:0`, and a finding is added there only for a
rule the message itself does not already report. A transfer-encoding value with a
trailing space, a fold, or a comment is decoded as current mail libraries decode it,
and the body as written is read beside it. One `text/plain` body in UTF-8 or ASCII
with no encoding is not a container. A one-body message whose headers the mail
library cannot parse is incomplete. The shared size, count, depth, and deadline
limits apply to the decoded parts.

A message gate is a hold decision, not authorization. Treat every inbound
message as untrusted data, keep it fenced in the prompt, and keep the
consumer's own approval checks on any tool or send action it proposes.

### A public SMS number

[docs/examples/sms_gate_bridge.py](examples/sms_gate_bridge.py) is a standard-library
bridge for a Twilio number. It verifies `X-Twilio-Signature` against the auth token
and the public URL, and holds every MMS (the gate never fetches media, and image text
is not read). It scans each body and the sender's recent messages joined together, so
an instruction split across two texts is held on the second, and it writes allowed and
held messages to owner-only queues. An owner-only SQLite transaction records the
`MessageSid` and pending JSONL bytes together. A restart or delivery retry finishes
the write at its recorded offset before acknowledging the message. A committed
duplicate is acknowledged without scanning. An overlapping delivery or a storage
failure gets HTTP 503. Stop the bridge before rotating a queue, and check that
`SELECT count(*) FROM pending` in `processed.sqlite3` returns zero first. Consumers
should still deduplicate by `message_sid` when rereading the queue. A message without
a `MessageSid` is held. The bridge sends no automatic reply. The first half of a
split instruction has already been allowed by the time the second arrives; it is
harmless alone, but the consumer should still read messages as one sender's thread,
not as instructions. Measured gaps for this channel, the consumer changes it needs,
and the review queue it lacks are in the
[integration-readiness review](reviews/2026-11-02-integration-readiness.md).

## PDFs and other compressed documents

The [detection-method map](../rules/README.md) links the reader, structural, and policy code; a derived text view exposes bytes to existing rules rather than certifying a document as safe.

A PDF verdict covers the file's raw bytes, the `pdf-flate` view (every
`/FlateDecode` stream that inflates to text, after any ASCIIHex or ASCII85 stage
and PNG or TIFF predictor, handed to the text rules and the PDF name checks), and
the `pdf-text` and `pdf-paragraph` views (the strings a reader shows, decoded
through each font's `ToUnicode` map or as WinAnsi, joined per text object and per
paragraph, so a kerned array, a hex string, glyph-ID text from Chrome, LibreOffice,
or Word, a word in bold, or a wrapped line reads as written). A font object or
`ToUnicode` map that the file defines more than once (an incremental update, a number
reused under another generation, an object-stream member beside a raw object) is read
through every definition, because readers differ in which one they use; each distinct
definition counts as one of the fonts its name means. Each PDF piece is also
spelling-folded when needed, with `pdf-text+text-folded` or
`pdf-paragraph+text-folded` provenance. Look-alikes, leet, Latin small capitals,
and Cyrillic letter case therefore reach the same lexical rules after glyph decoding.
The original bytes, paragraph boundaries, and finding severity are preserved;
these notes still pass the notes-only `agent-document` read rule. A composite font with
no readable `ToUnicode` map leaves text unread. Each page reads a font name through its
own resources, so a merged PDF, whose sources each keep their own `/F1`, is read one font per
page. Where a name still means more than four fonts (one content stream drawn by many pages,
or a file whose syntax or page tree readers could resolve differently), only four of them
decode each string. Either case
is the note `heuristic_pdf_text_unmapped`, so `agent-ingest` holds the file instead of passing
text it could not read; `agent-document` records it and passes the file, so give such a PDF
to your own extractor's gate as well. Annotation `/Contents` strings are decoded separately
as `pdf-annotation` (literal/octal, hexadecimal, PDFDocEncoding, UTF-16BE or
UTF-8 with BOM, including indirect and supported object-stream members), then
folded when spelling changes. Annotations and blank-line-separated paragraphs
are never joined. Unreadable supported annotation contents are incomplete; rich
text `/RC` is not decoded by this reader. Page content under a filter it cannot decode
(CCITTFax, JBIG2, JPX, DCT, Crypt, an ASCII stage with nothing after it, a name no reader
knows, or LZW over 2 MiB and RunLength over 8 MiB encoded) is the note
`heuristic_pdf_content_unread`, graded like `heuristic_pdf_text_unmapped`. The report's
`pdf_content_unread` counts those streams by filter (`{"LZWDecode": 1}`; a name outside the
standard filters is `other`). An empty object means every page content stream with a filter was
decoded, not that the PDF holds no text the gate missed. Under `agent-document`, route a PDF
with a non-empty count to your own extractor's gate: poppler and pypdf show the text of an
LZW or RunLength stream past the caps, and pypdf shows CCITTFax and JPX page bytes as they
are. Images and fonts under those filters are not counted. Form
field values, document information strings, and outline titles are decoded the
way pypdf reads them, as `pdf-string`, and marked content's `/ActualText`, which poppler
and PDFium show in place of its glyphs, as `pdf-actual-text`, whether the content stream
writes the property list or names it from the page's `/Properties`. Text a reader hides (render mode 3 or 7, white on nothing
painted, under 1 pt, or off the page in a PDF; vanished, white, or 1 pt runs and
hidden shapes or slides in Office; in HTML, an exact inline hiding declaration, a
comment, a `data-*` value, or a `template`) is also scanned on its own, and an override
phrase there adds the advisory `heuristic_hidden_text`, so `agent-document` holds a
document whose hidden text instructs the model while it still passes one that
quotes an attack in plain sight. An OCR text layer is render mode 3, so a scanned
page that reads as an override phrase is held too
([boundaries](rules.md#hidden-office-and-pdf-text)). A Word, Excel, or PowerPoint verdict covers each XML member
and an `ooxml-text` view that joins the text runs of the body, headers, footers,
notes, comments, shared strings, and slides, and of the slide masters and layouts,
SmartArt, charts, and worksheet text boxes a renderer draws from, so a sentence Word
split across formatting runs is seen whole. An OpenDocument file (`.odt`, `.ods`,
`.odp`) gets an `odf-text` view, one line per paragraph. Both are read as an XML
parser hands the text on, through a comment, a CDATA section, an internal entity, or
a UTF-16 part ([boundaries](rules.md#office-xml-and-opendocument-reader-boundaries)); an Excel inline-string cell split across rich-text
runs, or a cell value a comment or CDATA section split, is read as an `ooxml-cell` piece,
each section of a worksheet's page headers and footers as an `ooxml-header` piece with its
ampersand codes taken out (`&CIgnore`, `pre&Bvious`), and an HTML page or mail part as one
`html-text` piece per paragraph or cell, with bold, links, and comments dropped, read
both with bounded tags and as the WHATWG tokenizer reads markup a browser discards
(`<!-->`, `--!>`, `</>`, long or odd tag names). An RSS or Atom feed, under any name, is
read as `feed-text`: one piece per text node a comment or CDATA boundary split, and one
per block of the escaped HTML a `description` or `content` element carries or of an Atom
`xhtml` construct. Other XML (a `pom.xml`, a `.csproj`, a `.plist`) is read as `xml-text`:
one piece per text node a comment, a CDATA boundary, or the document's own entity split.

A model address or summary hook paired with a directive can trigger
`agent_model_addressed_instruction`. A matching page holds under both agent policies.
The scanner can report the rule from either contiguous markup or an extracted block.
If the browser hides the matching block and does not also display it, the hidden-text
check can add `heuristic_hidden_text`. See the [rule table](rules.md#agent-ingestion-rules).

A Markdown paragraph or list item split by emphasis, a code span, or a link is read
as one `markdown-text` piece, a word hyphenated at a line end is rejoined in every
folded view, a sentence wrapped over two `//`, `#`, `--`, `;`, `'`, or block-comment
lines is read as one `comment-text` piece, and a Jupyter cell stored as a list of lines as
one `notebook-text` piece. YAML double-quoted scalars and TOML basic strings with
escapes yield one decoded `config-unescaped` piece each. YAML scalar events preserve
quotation style without constructing tagged objects or expanding aliases. Plain and
block scalars keep their literal backslashes. RTF formatting, hex bytes, and Unicode escapes are read
as `rtf-text`, one piece per paragraph, table cell, or separate story; each piece
is also folded before matching. Malformed RTF or unreadable declared encodings
are incomplete. Not covered: text out of reading order or in columns,
a sentence split across two paragraphs, Type 3 fonts, page content past the LZW and RunLength caps
or under another filter (reported, above, not read),
images, ODT spans, RTF embedded-object or picture text, and Office parts a reader does not see. The
exact mechanics and caps are under [Limits](rules.md#limits); the PDF and Office
structure checks still run on the raw file.


### SVG and Office comments

The reader views scan runs inside each Excel or modern PowerPoint comment and
inline spans inside one SVG text element. Separate comments and text elements stay
separate. Latin small-capital spellings fold before lexical matching; a matching
phrase keeps its note severity and follows the selected policy. These views do not
measure visibility or SVG positioning. Continue to scan the exact text your
extractor hands to the consumer; [reader boundaries](rules.md#phase-1c-small-reader-boundaries)
list the supported parts and exclusions.

A consumer that extracts text itself should gate that text too, since the
extractor's output is what the model reads: scan the original file, then pass
the extractor's output through `scan_bytes` (or `scan -`) before the text
reaches the model.

```python
text = extract_text(path).encode("utf-8")  # your extractor
held = scan_bytes(text, name="report.txt", policy="agent-ingest", rules_dir=Path(rules_root))
```

Allow the document only when both verdicts are clean. Name the text `.txt`
(not `report.pdf`) so the scan treats it as text.

To measure this before enforcing it, capture the extractor's output and run
[`yara-gate replay`](#replaying-captured-model-input) over it.

### Documents that quote attacks

A threat report, a red-team corpus, or a rule's own test file quotes the phrases
the override rules match. Under `agent-ingest` those files are held, which is
right for a message and wrong for a document a person wrote about attacks. The
`agent-document` policy records a `note` finding (the three phrase rules,
`agent_prompt_injection_phrases`, `agent_prompt_injection_multilingual`, and
`agent_override_imperative`, the same phrase in a decoded base64 run,
`agent_encoded_instruction`, a lone Unicode control, a page-open `/OpenAction`, or
PDF text the font map could not decode) without changing the verdict, and still
holds every `advisory` finding: a settings file that turns off approvals, a code-relay
request, a request to send the system prompt, an order to exfiltrate, to call a
tool and hide it from the user, or to use your own tool to send data to an outside
address (`agent_tool_hijack_directive`), a hidden-text run, or a role-spoof or
override header. The verdict is `advisory` with `policy_reason` set to
`agent-document records note findings` when only notes matched, and `block` with
`agent-document holds advisory findings` otherwise.

A document without a reviewed release must have a complete `clean` record or
meet **every** one of these conditions:

```text
policy         == "agent-document"
verdict        == "advisory"
policy_reason  == "agent-document records note findings"
note           == true
advisory       == false
exit_code      == 0
incomplete_reason is None
findings is non-empty
every finding.severity == "note"
SHA-256 matches the bytes actually read
```

The record-count and process-exit checks from the top of this guide still apply.
Do not shorten this to "exit 0", "verdict is advisory", or "no block finding":
each of those also accepts records this predicate rejects.

```python
import hashlib

NOTES_ONLY = "agent-document records note findings"


def document_readable(record: dict, data: bytes) -> bool:
    """One complete clean record, or one exact notes-only agent-document record."""
    if record.get("sha256") != hashlib.sha256(data).hexdigest():
        return False
    if record.get("incomplete_reason") is not None or record.get("exit_code") != 0:
        return False
    if record.get("policy") != "agent-document":
        return False
    if record.get("verdict") == "clean":
        return True
    findings = record.get("findings") or []
    return (
        record.get("verdict") == "advisory"
        and record.get("policy_reason") == NOTES_ONLY
        and record.get("note") is True
        and record.get("advisory") is False
        and len(findings) > 0
        and all(finding.get("severity") == "note" for finding in findings)
    )
```

Reading a document is not permission to follow it. The notes are override phrases
the document contains, so keep its content fenced as untrusted data, never execute
or persist instructions from it, and scan text extracted from it under the same
policy. A rule moved **to** the `note` tier widens what this predicate accepts, so
treat every such change as an integration change and re-run your consumer checks.

The caller picks the policy because it knows whether it is reading a message or
a document; the scanner does not guess from the content, and a size or ratio
rule would be defeated by filler. A document that asks the reader to forward a
one-time code, or that carries an instruction in hidden text, is still held. An
encoded override phrase is a note, recorded like the plain phrase.

## Replaying captured model input

`yara-gate replay CAPTURE` answers one question before a consumer enforces anything: on
the text this consumer hands its model, what would the gate have decided? It scans a
capture of that text and prints the gate's record beside the consumer's own decision. It
is a measurement. It admits nothing, holds nothing, writes no report, needs no gate home,
and never downloads. The [shadow evaluation protocol](research/shadow-evaluation-protocol.md)
says how to turn its output into a decision.

```sh
yara-gate replay capture.jsonl --rules RULES > replay.jsonl
yara-gate replay - --rules RULES --policy agent-document < capture.jsonl
```

The capture is JSON Lines, one object per item, at most 16 MiB a line:

| Key | Required | Holds |
| --- | --- | --- |
| `source_id` | Yes | Your identifier for the item, up to 256 characters. It is copied to the output, so keep query strings, tokens, and personal identifiers out of it |
| `channel` | Yes | A lowercase label for where the text entered: `search-snippet`, `fetched-html`, `pdf-text`, `cached-passage`, or your own |
| `text` or `text_base64` | One of them | The exact text handed to the model. `text` is scanned as its UTF-8 bytes; `text_base64` carries bytes that are not UTF-8 |
| `text_sha256` | No | Your own SHA-256 of those bytes. An item whose digest differs is `failed` with `receipt mismatch` and is not scanned |
| `name` | No | The logical file name whose suffix drives the type checks; `item.txt` when absent |
| `policy` | No | `agent-ingest`, `agent-document`, or `default` for this item; otherwise `--policy`, which defaults to `agent-ingest` |
| `label` | No | Ground truth, `attack` or `benign`, for the summary |
| `actual_decision` | No | What the consumer did: `admitted` or `held` |
| `original_sha256` | No | The SHA-256 of the file the text was extracted from, recorded beside the text's own digest |
| `extractor`, `extractor_version` | No | What produced the text |
| `classifier` | No | A flat object of scores and identity from a separate classifier. It is copied through, and the gate never reads it |

An unknown key, a repeated key, or a control character in an identifier makes the line
malformed. A malformed line still produces an item, `failed`, so every line of the capture
is counted.

Each item becomes one envelope on stdout, and a summary follows the last one:

```json
{"record":"item","schema_version":1,"line":2,"source_id":"task-017:fetch-2","channel":"fetched-html","label":"attack","policy":"agent-ingest","text_sha256":"345d…b5e4","text_bytes":62,"original_sha256":"abab…abab","extractor":"pdf-text-worker","extractor_version":"0.3.1","status":"complete","status_reason":null,"proposed_decision":"hold","actual_decision":"admitted","agreement":"gate-would-hold","wall_seconds":0.248,"classifier":null,"gate":{"sha256":"345d…b5e4","verdict":"block","exit_code":1,"…":"the compact report"}}
```

- `gate` is the same compact report `scan --json` prints, present only when it is one valid
  record for exactly these bytes and this policy. The envelope never holds the text or
  matched bytes.
- `status` describes the scan, and each value is distinct from clean:
  - `complete`: a complete record for these bytes.
  - `truncated`: the gate returned an incomplete record (a limit, its own deadline, the match
    cap, rules that did not load). `status_reason` is its `incomplete_reason`.
  - `failed`: no usable record. The child was killed at the hard deadline, crashed, printed
    something other than one valid record, answered for other bytes or another policy, the
    scanner itself raised (`scan failed`), or the capture line was malformed.
- `proposed_decision` applies the policy's read rule from the top of this guide: `admit` for
  a complete `clean` record, and under `agent-document` also for the exact
  [notes-only record](#documents-that-quote-attacks). Everything else is `hold`, including
  every `truncated` and `failed` item. `default` admits a complete record that exits 0.
- `agreement` compares that with `actual_decision`: `agree`, `gate-would-hold`, or
  `gate-would-admit`. It is null without an `actual_decision` and for a `failed` item.
- `wall_seconds` includes one process start; `gate.scan_seconds` is the scan alone.

The summary (`"record":"summary"`) counts items by `status`, by proposed decision, by
agreement, and by label (`admit`, `hold`, `truncated`, `failed`, so a scan that did not
finish is never counted as an admit). It also lists items per rule ID, the median and
maximum of both timings, and `identities`: each distinct ruleset digest, detector digest,
engine and tool version, and rule counts seen. `mixed_identities` is true when a run saw
more than one, which means its numbers mix two baselines.

Each item is scanned in its own child process, which the parent kills 30 seconds after the
scan's own `--timeout`, because the scanner's deadline cannot preempt every parser. One
item cannot affect the next. A small text item takes about 0.2 s of wall time once the
compiled rules are cached.
`--no-timings` leaves the seconds out, so two runs over the same capture with the same
rules and detector print the same bytes.

The exit code is 0 when every item got a gate record and 2 when one did not. It is never
1: a proposed hold is an observation here, not a verdict. Exit 0 does not mean every item
was fully scanned: a missing rules directory makes every item `truncated` and still exits
0, so read `status` in the summary before using a run. Like any scan, a replay fills the
compiled-rule cache under the user cache directory; it writes nothing else. Do not use this command to admit
content. An envelope describes a capture; admission uses a fresh `scan` or `scan_bytes`
record for the bytes being read.

A caller that already holds bytes in Python can use the same core:

```python
from yara_gate.replay import proposed_decision, shadow_scan

data = text.encode("utf-8")  # bytes, as handed to the model
scan = shadow_scan(data, name="page.txt", policy="agent-ingest", rules_dir=rules_root)
observed = {"status": scan.status, "would": proposed_decision(scan, "agent-ingest")}
```

## Checking a pin bump and your own extractor

Two things can change what your model receives without any change in your code: a new
`yara-gate` version that answers differently, and a reader of yours that shows the model
text the gate judged differently in the file. `yara-gate conform` checks the first against
fixtures and expected verdicts shipped in the package, and `yara-gate conform --agreement`
shows the second on the same fixtures.

```sh
yara-gate conform                                   # exit 0, 1 (a verdict changed), or 2
yara-gate conform --export kit                      # the fixtures, for your reader
yara-gate conform --agreement extraction.jsonl > agreement.jsonl
```

- Run the plain command in CI whenever the pin moves. It uses the bundled rules only, needs
  no network and no gate home, and takes a few seconds.
- Run agreement mode after every extractor change and every pin move, and fail CI when the
  committed `agreement.jsonl` changes. A `file-holds-only` line is an input the gate holds
  as a file and would admit as your extraction.
- Installed vendor packs are compared in a section of their own that never fails the run.

The record types, exit codes, capture keys, and the change list are in the
[conformance kit guide](conformance.md).

## Listing held items

`yara-gate held --home GATE --json` is a read-only queue index for an operator or
consumer UI. It enumerates current entries under `blocked/`, `quarantine/`, and
`quarantine/_rejected/`, then associates their reports. It does not read held bytes,
compile rules, scan, download, create a home, acquire a write lock, or move anything.
Historical reports alone, released copies in `clean/`, and files scanned in place
are not current held entries. The caller must use a private gate home.

The JSON object has `schema_version: 1` and `items`, an array with these fields:

| Field | Meaning |
| --- | --- |
| `disposition` | `blocked`, `incomplete` (still quarantined), or `rejected`, from the entry's current directory; not a new scanner verdict |
| `identifier` | Digest slot name, or rejection identifier from an associated report; `null` when unknown |
| `sha256` | Content digest recorded by the scan, or `null` for a rejection, unknown digest, or unreadable report; bytes are not rehashed |
| `path` | Current held entry's path, with the usual user-home prefix replaced by `~`; this is not filename anonymization |
| `age_seconds` | Nonnegative integer seconds since the associated report's modification time, or `null` when no readable report is associated; not the original file age or a verified admission timestamp |
| `policy`, `policy_reason`, `incomplete_reason` | Stored report fields, or `null` without a readable report |
| `findings` | Array of `{ "rule_id": string, "severity": "note" \| "advisory" \| "block" }`; empty without a readable report; no matched bytes |
| `report_status` | `readable` or `unreadable`; the latter also covers a missing, invalid, oversized, or unassociated report |
| `release_eligible` | Boolean stored-report preview using `release_refusal`; only a single regular blocked copy with an eligible `agent-document` report can be true |
| `release_refusal` | Reason the preview is false, or `null`; never permission to release |

The scan/report schema and verdict semantics are unchanged. `--since 7d` filters on
`age_seconds`; supported units are seconds (`s`), minutes (`m`), hours (`h`), days
(`d`), and weeks (`w`), with a nonnegative integer amount. Unknown ages stay visible.
Without `--json`, the command prints one JSON-escaped row per item, or `No held items.`
Both empty and nonempty indexes exit 0. Invalid arguments, an unavailable home, or a
held/report directory that cannot be safely enumerated exit 2 without a partial index.
Individual corrupt reports remain rows marked unreadable and do not fail the command.

The reader accepts regular, single-link reports up to 8 MiB; linked reports and
linked slot directories are not followed. Rejected directories are listed as single
entries, never traversed. A rejection's identifier cannot be recovered reliably from
its filename when its report is missing or corrupt, so it is `null` rather than a
guessed hash. Multiple reports claiming the same rejected path are also unassociated.

This is a best-effort snapshot during concurrent intake or release, not a transaction
or a content-integrity check. Poll again when entries move. Report paths must match
the held name and digest slot (including its prior quarantine/clean location after a
move). A stale report can still describe older rules or a previous same-name copy.
Never use `release_eligible`, an empty index, or the absence of a finding as admission
authority. The release command below freshly verifies the bytes, rules, findings,
and audit trail before authorizing a release.

## Reviewed document releases

Review the document's exact bytes and the JSON report from a completed
`agent-document` hold. For a blocked inbox copy, run:

```sh
yara-gate release SHA256 --home GATE --reason "Reviewed findings and accepted risk"
```

For a file scanned in place, add `--path FILE`. Use the same rules root as the
reviewed scan. For the sync example, use `GATE_HOME/reports` as `--home` and the
reviewed source file as `--path`. For the pre-read example, use
`YARA_GATE_HOME` and the reviewed source path. The command rescans the bytes,
checks the ruleset and findings against the last report for the digest, and
moves a blocked copy to `clean/<sha256>/` after recording the review. An
in-place file stays in place. Releases require a terminal by default. Use
`--non-interactive` only to record a completed human review in a non-TTY session.

A subsequent file scan under the same explicit `--home` verifies the audit log
and looks up the content SHA-256, ruleset SHA-256, policy, and sorted finding
IDs. The trusted scanner emits an advisory verdict and the exact reason
`agent-document hold released by review`, with the original findings and
severity flags. The example consumers accept that result through a separate
branch, with exit 0, exactly one complete record, at least one advisory,
no block-severity findings, and a SHA-256 match to the bytes they consume.
The sync example rechecks released copies on every pass and withdraws them
when the evidence is missing, invalid, or stale. Coordinate reads with the
completed pass.

The watch loop, stdin, `scan_bytes`, and the live workbench scan without applying
releases. An `agent-ingest` hold, actual block-severity finding, or incomplete
scan cannot be released. A changed ruleset or finding IDs require fresh review.
A reviewed release permits reading as untrusted data. Keep the existing rules
against following or executing its instructions.

The audit lives in `GATE/releases.jsonl` with a `.head` sidecar and an append
lock. Each entry records time, rules, digest, policy, the reason, and the OS
identity. Windows records the username with `uid: null`. Use a private gate
home with OS access controls. The chain detects inconsistent edits and
deletions, and cannot authenticate a log and head both rewritten by someone
with access to that home. Preserve the printed head with your review evidence.
Keep secrets and file content out of the reason. If the log fails verification,
the scanner keeps the hold. Previously moved copies require a new scan to
re-evaluate their disposition.

## CyClaw and CG-agent-harness

Use the gate before CyClaw reads or chunks a corpus file, and before Harness
accepts an attachment, notes-corpus file, or child file-read result into model
context. Corpus files, notes-corpus files, and file-read results are documents:
`agent-document`, with the document read rule. Chat messages, webhook bodies, SMS,
tool output that relays what someone else wrote, and attachments from an unknown
sender are messages: `agent-ingest`, clean only. Keep the existing consumer's size limits, sanitization, untrusted
content fences, approval checks, and memory review. A clean scan is not permission
to execute instructions found in a file or to persist them as agent guidance.

The [agent-rule coverage record](verification/agent-rule-coverage.md) ties this
use case to inspected consumer revisions and scans of their current documents, and
the [integration-readiness review](reviews/2026-11-02-integration-readiness.md) maps
both consumers at named commits: where CyClaw's indexer can call the gate (at load
time, so `rclone copy` cannot restore a moved file), and what the harness would need
for an inbound SMS channel. These are integration requirements, not a claim that
either consumer now calls yara-gate automatically.
