# Agent ingestion rule coverage — October 22, 2026

Starting point: clean `main` at `d0c5a0f2af48288b8f13de3d757e97a338ae587a`.
Verification used Python 3.12.12 on macOS 27.0.1 ARM64, copied local rules,
disposable homes, inert text, and the actual library/CLI. No target was executed
and no vendor pack was downloaded.

## Coverage and match boundaries

| Rule | Signals required | Benign boundary |
| --- | --- | --- |
| `agent_persistent_instruction` (new) | Append/write/save/store within 96 characters of `AGENTS.md`, `CLAUDE.md`, `MEMORY.md`, or memory, then within 160 characters bypass/skip/disable plus approval, confirmation, safety checks, or audit logging; alternatively remember + future sessions/tasks + the same bypass instruction | Ordinary memory notes, guidance edits, and mentions of approval policy stay clean |
| `agent_tool_output_override` (new) | A textual `tool_result`/`tool_response` opening tag, within 160 characters call/invoke/run/execute plus `run_command`, `execute_command`, shell, or terminal; within 96 more characters a named control bypass | Plain tool output, read-file requests, and a command outside the closing tag stay clean |
| `agent_role_spoof_action` | Existing patterns plus Llama-style headers, `[start]`/`[message]` role markers, or XML system/developer tags followed within 256 characters by an override/action/disclosure term | A role marker and ordinary greeting alone stay clean |
| `agent_prompt_injection_phrases`, `agent_hidden_html` | “you are now” needs, within 96 characters, an override/action term (ignore, override, bypass, reveal, execute), an unrestricted/unfiltered/uncensored term, `jailbroken`/`jailbreak`, `developer mode`, `do anything now`, `(without\|no) [any] restrictions/rules/limits/limitations/filters/guardrails`, or a **case-sensitive** `DAN`; other existing phrases remain | Ordinary status text, hidden status text, and the name “Dan” stay clean |

These are lexical heuristics with advisory severity. The default verdict is
advisory/exit 0; `agent-ingest` holds it as block/exit 1 without changing finding
severity. ASCII/wide patterns and existing derived views cover the tested UTF-16
and HTML forms. Archive members use the existing bounded reader. The character
bounds correspond to ASCII pattern characters (twice the bytes for wide matches).
Tool-result matching is limited to these textual tags, not an MCP protocol parser.

The design follows the indirect-content, persistent-instruction and tool-output
threats described in [OWASP prompt-injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html)
and [OWASP MCP guidance](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).
No match proves malicious intent or that an agent would follow the instruction.

## Before and after

At the baseline, persistent-bypass requests, forged tool results, and the added
role-marker variants scanned clean. The ordinary sentence “You are now connected
to the local server.” produced an advisory. The added fixtures demonstrated those
failures before rule edits. The candidate detects the targeted combinations and
keeps the ordinary sentence clean, including in hidden HTML.

The maintained probe now includes 78 agent fixtures, covering renamed files,
UTF-16 LE/BE, HTML entities, ZIP/gzip members, benign near-misses, and deliberately
separated signals. It checks rule IDs and derived/member provenance. CLI cases
check original finding severity, process exits, physical relocation, report
privacy, and SARIF offset attribution under both policies.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
```

Revalidated on YARA-X 1.22.0 (the current main lock): **22 rules, zero skips; 198 library
cases, 36 CLI operations, 109 benign observations, three failure paths; all pass**.
The 109-file set is the nine shipped benign fixtures plus 100 standard-library
files selected by the probe. All 109 complete clean with no rule/heuristic findings.
All 78 agent fixtures are included. The `expected` field of a fixture may be a list when
several rules legitimately co-fire (the hidden-HTML cases fire both
`agent_prompt_injection_phrases` and `agent_hidden_html`); the probe compares the exact set.

The earlier local invariant gate passed all eight focused checks for rejected
symlink/hardlink/FIFO intake, missing bundled rules, failed update preservation,
cross-host token stripping, loopback binding, and cross-origin requests. Those
boundaries were not changed. Ruff lint/format and strict mypy are recorded with
final delivery checks. Hosted broad/platform regression results belong to the
published PR head, separately from this local evidence.

## Current consumer-document comparison

All tracked root and `docs/` Markdown files were scanned from these pinned
snapshots, before and after, through `scan_file` with the complete local pack.
The [manifest](agent-ingest-corpus.jsonl) records each file hash and rule IDs;
no document contents or matched snippets are published. Every pinned file hash
and both sets of findings were revalidated on YARA-X 1.21.0 before publication.

| Snapshot | Files | Baseline advisory | Candidate advisory | Newly matching files |
| --- | ---: | ---: | ---: | ---: |
| CyClaw `34b44e1197b24cace55194d0ac3ccc82a6815266` | 122 | 15 | 13 | 0 |
| CG-agent-harness `3301c0c7b6ca88ff498387f3aca820d56cb3b76b` | 28 | 2 | 2 | 0 |

There were no blocks or incomplete scans. The two removed advisories were CyClaw
NeMo planning documents discussing ordinary “you are now” status prose. Fifteen
documents still match existing injection phrases or download/execute examples.
They are legitimate repository documents requiring review under `agent-ingest`;
this is **not** a zero-false-positive claim for the complete pack. The new rules
added zero collisions in this sample. The set is small, English-heavy, and not an
independent production corpus or a statistical estimate of precision/recall.

Current production source was inspected: CyClaw's `retrieval/indexer.py` bounds
file loading and sanitizes chunks; Harness's `src/server/notes_corpus.rs` checks
stored byte identity and scans/fences retrieved text. Neither path was modified.
The [integration guide](../integrations.md#cyclaw-and-cg-agent-harness) identifies
where a separately reviewed gate can run. This work does not install a consumer
integration or replace its existing controls.

## Earlier combined candidate and live browser

This draft retains the main lock (YARA-X 1.21.0). The earlier local browser
evidence below used the same final rule bytes with YARA-X 1.22.0. The lock refresh
is a separate dependency draft; it is not required by these rule changes.

Computer Use exercised an owned live loopback demo with the final 22-rule pack and
YARA-X 1.22.0: persistent-bypass text was advisory/0 under default and block/1 under
agent-ingest; ordinary status text stayed clean/0; an HTML-encoded tool-result
instruction was block/1 with `view=html-unescaped`. The [original capture and
provenance](../../screenshots/README.md#persistent-instruction-rule) show the
persistent-bypass case. Browser checks do not prove inbox disposition or another
product's runtime behavior.

English paraphrases outside the bounded vocabulary, arbitrary base64, OCR and
semantic intent remain unsupported. Narrowing “you are now” deliberately stops
flagging that phrase alone; oblique role changes without the listed terms can
remain undetected. Quoted attack examples can still match.

## Jailbreak-persona terms (October 23, 2026)

PR #25 narrowed “you are now” to the override/action terms, which silently stopped
blocking “You are now DAN”, “…in developer mode”, “…jailbroken” and “…without
restrictions” under `agent-ingest`. The term list now also covers those. `DAN` is a
separate case-sensitive string (`$d_dan`, `$hidden_dan`) so “You are now Dan’s
reviewer” and “Dandelion” stay clean; the lead-in phrase stays case-insensitive.
The 32 added fixtures (17 positive, 15 benign near-misses incl. a name, a login/Wi-Fi
status, a bare `Jailbreak`/`DAN`/`no limits` sentence without the lead-in, and
out-of-window terms) fail against the previous rules (each positive was observed clean there) and pass now.

Measured on 876 text-like files from a CyClaw checkout plus this repository: 76 files
matched the two rules before, 77 after. The one new match is CyClaw’s
`docs/NeMo/phase4b_soul_leak.md`, a design document that quotes the phrase (a
quoted-attack example, arguably a false positive). This is not a precision estimate.

Known cost: the window is 96 characters of any text, so “You are now connected. There
are no limits on file size.” matches via `no limits`. `developer mode` likewise matches
“You are now in developer mode” in genuine Android/browser setup prose. Both are
advisory, and blocks under `agent-ingest` only. No native Windows,
live consumer, or vendor-pack accuracy claim is made.
