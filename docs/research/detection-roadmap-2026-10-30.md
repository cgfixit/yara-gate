# Detection roadmap for agent intake (2026-10-30)

Scope: what yara-gate can detect, or be extended to detect, for agent apps
(CyClaw, cg-researcher, cg-agent-harness) that ingest synced folders, cloned
repositories, mail, and short text such as chat or SMS bodies, without breaking
the contracts in `AGENTS.md` (no execution, no URL fetch, no network during a
scan, in-memory archives, `verdict_on_match` controls severity).

Evidence labels: **verified** means run on this host in this batch (see
`docs/verification/2026-10-30-review-batch.md`); **sourced** means a public
write-up named in the rule's `reference` metadata; **assessment** means my
judgment, not measured.

## Delivered in this batch

| Technique | Platforms | Mechanism | Status |
| --- | --- | --- | --- |
| Defender off/exclusions, AMSI/ETW patching, shadow-copy and recovery deletion | Windows 10/11, Server 2022+ | YARA, advisory | verified (#115) |
| ClickFix stage via `finger user@host \| cmd` | Windows | YARA string | verified (#115); sourced |
| Reverse shells (`/dev/tcp`, `nc -e`, mkfifo relay, socat, Python, PowerShell) | Linux, macOS, Windows | YARA, advisory | verified (#116) |
| Gatekeeper off, LSQuarantine off; `ditto` + `curl` exfiltration (AMOS/Poseidon shape) | macOS | YARA, advisory | verified (#116); sourced |
| VS Code `tasks.json` `runOn: folderOpen` auto-run (fake-interview repo lure) | all | YARA, advisory | verified (#116) |
| Base64-encoded PE/ELF/Mach-O in text, JSON, `data:` URIs | all | scanner signal + YARA global, block | verified (#117, #118) |
| Archive names that escape (`../`, absolute, NUL), zip symlinks | all consumers that unpack | content limits, incomplete | verified (#113) |
| Encrypted PDF/Office (contents unreadable to the gate) | all | heuristics, incomplete | verified (#114) |

## Candidates not built, in priority order (assessment)

1. **Note tier and the SMS decision (#105).** Blocks #106, #109, #110. A short
   text body is where one phrase is the whole input; the owner has to pick
   between the three options in #105.
2. **Hidden Office/PDF text conjunction (#110).** `ooxml-hidden-text` and
   `pdf-hidden-text` views so "invisible + instruction" stays advisory while a
   visible quote becomes a note.
3. **Reviewed release (#39).** Security write-ups trip the new advisory rules
   under `agent-ingest`; a hash- and ruleset-scoped release keeps them usable
   without an allowlist.
4. **Long-lived `serve --stdio` (#38).** Removes ~0.2 s per-file startup for a
   harness that gates every synced file; must fail closed on EOF or timeout.
5. **More Windows delivery formats.** MSBuild inline tasks (`UsingTask` with
   `CodeTaskFactory` plus `Process.Start`/`VirtualAlloc`), ClickOnce
   `.application`/`.appref-ms` with a remote deployment provider, `cmstp` INF
   `RunPreSetupCommandsSection`. Each needs a benign sweep of build repos first.
6. **npm/pip install hooks beyond `curl | sh`.** `postinstall` running
   `node -e` with a URL, `.pth` files whose line starts with `import` and calls
   `exec`. `script_download_execute` already covers the `curl | sh` form
   (the probe's `postinstall.json` baseline note is stale).

## Integration paths that keep the contracts (assessment)

- **Sync folders (Dropbox/OneDrive/iCloud):** copy, never move, into a
  gate-owned staging directory; `docs/examples/sync_folder_gate.py` already
  does this. Untested: a real cloud placeholder on a Windows host.
- **Chat/SMS bodies:** `scan_bytes(body, name="sms.txt", policy="agent-ingest")`
  or `scan - --name sms.txt`; hand the model the same bytes. Watch #105 before
  relying on a lone phrase being held.
- **Agent pre-read hook:** `docs/examples/yara_gate_pre_read_hook.sh` as a
  command hook that fails closed. This is a hard control; an instruction to
  "scan first" is not.
- **Coverage checks:** with #120, a consumer can require `units_scanned > 1`
  for a `.eml` or archive before trusting `clean`.

Not proposed: live URL reputation or sandbox detonation. Both need the network
or execution, which the scan contract forbids. They would be a separate
service, not part of the gate.
