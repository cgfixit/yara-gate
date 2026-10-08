# YARA rule coverage research and expansion plan

Research date: October 7, 2026, America/New_York. Source revision: `3667747ee4394a4453d16a6d9e6ecf8eb1660ef2`, the fetched default branch `grok/yara-gate` of `cgfixit/yara-gate`.

Implementation follow-up: this document preserves the baseline and proposal at that revision. The first implementation adds the P1 rule families, contextual Unicode verdicts, bounded archive/derived views, report provenance, and an opt-in agent-ingest policy. See the [verification record](../verification/intake-coverage.md) for delivered behavior and deferred work. Statements below about six rules or absent policy describe the baseline, not the implementation branch.

Broader coverage should combine contextual YARA rules, consistent scanning of extracted content, and explicit policy for each consumer. The strongest first additions are agent authority spoofing, requests to transfer secrets, encoded instruction variants, document references to external payloads, and script download/execute combinations. Before enabling broad blocking, address the existing Unicode false positives and archive coverage differences demonstrated below.

“More universal” here means reusable across agent/RAG ingestion, ordinary document intake, and developer files, including multilingual text and files originating on Windows, macOS, or Linux. It does not mean that a signature match proves malicious intent or that no match establishes safety.

## Relationship to the brainstorm page

The [linked brainstorm](https://cgfixit.com/-/yara-cyclaw/yara-brainstorm.html) proposes a separate scanner called before CyClaw ingestion or the Harness child's file read. It marks those integrations as unimplemented and keeps the Veeam restore scanner and other projects separate. This research follows that boundary. Rule additions remain owned by yara-gate; consumer integration is a separate change.

The page's exit-code warning is confirmed against the current scanner and CLI: advisory findings exit 0 and inbox files move into `clean/`. An indexer must inspect the structured verdict and its own policy. The directory name alone is insufficient. The page's historical CyClaw/Harness revisions and Windows observations were not revalidated here.

## Current coverage and executed observations

The fresh checkout contains six local rules and no vendor rule bodies. `rules.lock` records earlier vendor download pins; it does not install those packs. The README's historical 13,535 compiled rules are not the active coverage of this checkout. The isolated probe compiled all six shipped rules with zero skips.

| Current component | Actual scope |
| --- | --- |
| `agent_eicar` | Blocks the EICAR marker substring; a scanner exercise, not general malware coverage |
| `agent_prompt_injection_phrases` | Seven English strings, any one sufficient for advisory |
| `agent_hidden_html` | Four literal CSS spellings plus one of the same seven phrases anywhere in the file |
| `agent_base64_blob` | A 400-character run in selected filename extensions; advisory |
| `agent_invisible_unicode` and `agent_bidi_override` | Block on individual matching byte sequences, including legitimate joiners and directional isolates |
| PDF/Office/executable heuristics | Raw PDF tokens, extracted VBA autoexec/selected keywords, embedded executable headers; outer file only |
| Containers | ZIP and tar members receive YARA scans; their extension is passed as an empty string. Gzip is recognized but not expanded |

The source paths establishing these boundaries are [scanner.py](../../src/yara_gate/scanner.py), [heuristics.py](../../src/yara_gate/heuristics.py), [rules.py](../../src/yara_gate/rules.py), and [local rules](../../rules/local).

Direct execution used macOS ARM64, Python 3.12.12, and locked `yara-x` 1.21.0. The [probe](probe_rule_coverage.py) supplies 21 inert synthetic inputs to the real `scan_file`, then performs two real CLI intake/relocation runs in temporary homes. It copies local rules to temporary storage, so compilation does not rewrite the checkout's cache or skipped-rule record. [Recorded results](rule-coverage-baseline.json) include source revision, engine version, rule hashes, sample hashes, verdicts, and process exits.

| Input or comparison | Observed result | Implication |
| --- | --- | --- |
| Ordinary English text | Clean | Benign control |
| Woman-technologist emoji containing U+200D | Block | Normal emoji triggers the invisible-Unicode rule |
| Persian word containing U+200C | Block | Legitimate word shaping triggers the same rule |
| Arabic name wrapped in directional isolates | Block | Isolates are treated like hostile overrides |
| Direct English override phrase and a warning quoting it | Both advisory | The current phrase rule does not distinguish instruction from discussion |
| Same phrase in UTF-16LE bytes or short base64 | Both clean | The phrase rule has no corresponding encoded patterns |
| Same phrase inside gzip / ZIP | Clean / advisory | Gzip content is not expanded; ZIP content is scanned |
| HTML entity inserted between phrase words | Clean | Raw bytes differ from the reader's decoded text |
| Hidden HTML requesting `.env` contents be sent to an inert URL | Clean | The specific request avoids the existing seven phrases |
| Role delimiter claiming system authority plus a credential request | Clean | No explicit role-spoofing detector |
| Same long benign base64 as `.txt`, `.bin`, and a ZIP member named `notes.txt` | Advisory / clean / clean | Filename gating and discarded member extensions change coverage |
| Synthetic PDF with only a navigation OpenAction | Block | Presence of `/OpenAction` is a feature restriction, not proof of executable code |
| Synthetic PDF with inert JavaScript, directly / inside compressed ZIP | Block / clean | PDF heuristics do not run on archive members |
| Synthetic npm postinstall download/execute text and external-template XML | Both clean | Candidate local rule families; vendor coverage remains unknown |

The CLI runs confirmed advisory → exit 0 → `clean/`, and a Unicode block → exit 1 → `blocked/`. These are specific observed outcomes, not precision/recall measurements or demonstrations that an agent followed an injected instruction. Vendor packs, native Windows/Linux behavior, and live CyClaw/Harness integration were outside this run.

## Candidate rule families

These are proposed designs, not installed rules. Start new heuristics as advisory in a research rules directory. A consumer may hold selected advisory findings for review, but the present default drop-folder policy does not do that.

| Priority and proposed identifier | Signals to combine | False positives and implementation boundary |
| --- | --- | --- |
| P1 `agent_role_spoof_action` | Known role/delimiter syntax or a claimed instruction-priority change, near a request to override behavior, disclose protected data, or invoke a tool | Chat exports, prompt templates, and security documentation are legitimate. Require co-occurrence within a bounded region; a role marker alone is advisory at most |
| P1 `agent_secret_transfer_request` | A secret source such as `.env`, credential storage, private keys, or conversation history, plus a read/collect request and an outbound transfer instruction or destination | Backup, migration, and incident-response guides contain the same vocabulary. Match combinations; never block on `.env`, `curl`, or a URL alone |
| P1 `agent_encoded_instruction` | Separate plaintext, ASCII-wide, and base64 patterns for distinctive instruction/action combinations | Encoded examples are common in documentation. Finite variants improve recall but do not cover arbitrary encodings, paraphrases, or languages |
| P1 `agent_hidden_instruction` | Hidden/comment/metadata context paired with authority spoofing or a secret-transfer request | Replace whole-file CSS-plus-phrase coincidence with bounded proximity. Full CSS visibility and HTML entity handling require parsing; YARA does not render pages |
| P1 `doc_external_template` | OOXML attached-template relationship plus external target mode and remote HTTP(S)/UNC target; corresponding RTF template-reference signals | Corporate templates can be legitimate. Begin advisory; evaluate the target on normalized relationship data with network resolution disabled |
| P1 `script_download_execute` | Downloader plus interpreter/evaluation behavior in a bounded command region; separate PowerShell, shell, and JavaScript/Python variants | Common installation instructions are not malware. Distinguish executable content from quoted documentation through consumer policy and parsed context |
| P2 `package_install_exec_chain` | Package lifecycle field or known hook context plus download/execute, credential-access, or security-disabling signals | Ordinary build hooks must remain usable. A JSON/TOML parser must establish which value executes; YARA is a first-pass indicator |
| P2 `shortcut_remote_or_encoded_exec` | Parsed LNK target/arguments or Internet Shortcut fields indicating an interpreter plus encoded/remote execution | Administrative shortcuts are legitimate. Prefer the YARA-X `lnk` module over extension-only matching; verify fields on locked engine 1.21.0 before adopting examples from current docs |
| P2 `doc_active_payload_chain` | Parsed PDF action type plus script/launch/embedded executable; Office autoexec plus decoded suspicious actions; RTF embedded-object indicators | Extend existing heuristics instead of duplicating broad `/OpenAction` or `CreateObject` matches. Object parsing, VBA extraction, and member traversal are scanner work |
| Optional `sensitive_material_present` | Complete private-key structures or carefully constrained credential formats | This is a data-handling finding, not malware. Useful for external indexing/export policies, noisy for source/security archives. Preserve reports without matched secret bytes |

The first four families target indirect instructions in untrusted material. OWASP describes indirect, encoded, multilingual, and multimodal injection, and treats filtering as one layer alongside constrained privileges and separation of external content. YARA should supply indicators to those controls. It cannot establish whether a model will obey a document. [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/), [OWASP prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html).

External-template rules address a documented technique in which Office or RTF references retrieve another resource, sometimes without an embedded macro in the original document. A remote template is still a legitimate feature, so its presence warrants contextual policy rather than a universal malware label. [MITRE T1221](https://attack.mitre.org/techniques/T1221/).

Install-hook rules address actual execution surfaces: npm documents lifecycle scripts during installation, and Git documents hooks around repository operations. Neither the presence of a hook nor an interpreter name proves compromise. [npm lifecycle documentation](https://docs.npmjs.com/cli/v11/using-npm/scripts/), [Git hooks](https://git-scm.com/docs/githooks). For Windows shortcut structure, the [YARA-X LNK module](https://virustotal.github.io/yara-x/docs/modules/lnk/) exposes parsed target and argument fields.

## Changes needed around the rules

**Unicode handling.** Separate directional overrides, legitimate isolates, valid emoji sequences, language shaping, and suspicious tag runs. Add contextual findings instead of globally accepting or blocking every joiner. Preserve the original bytes. A suspicious instruction containing an emoji must still be examined. Unicode defines valid ZWJ emoji sequences and legitimate isolate behavior; the current byte-pattern decision cannot express that context. [Unicode emoji standard](https://www.unicode.org/reports/tr51/), [bidirectional algorithm](https://www.unicode.org/reports/tr9/).

**Equivalent content views.** Scan raw bytes and bounded derived text that reflects what the eventual reader sees: HTML entities, explicitly supported character encodings, document text, and supported archive members. Preserve member identity, type, extension, transformation provenance, and offsets relative to the correct view. Never remove suspicious bytes in place or claim transformed offsets refer to the original. Do not execute scripts or fetch referenced URLs to decode content.

**Honest coverage.** Run applicable document heuristics on members. Expand gzip under shared depth, size, time, and member-count budgets, or report that required content inspection was incomplete. Apply the same principle to encrypted or unsupported containers, failed parsing, and unavailable text extraction. Ordinary OCR or image understanding would be a separate feature; raw YARA scanning cannot cover instructions visible only after image interpretation.

**Explicit policy.** Proposed consumer policies are `agent-ingest`, `document-intake`, and `developer-content`. The first can hold selected instruction/exfiltration findings; the second can restrict active content; the third can retain readable security documentation while exposing suspicious execution patterns. These policies do not exist today. Preserve the current exit contract and make any future disposition change explicit. A trusted source label alone should not exempt content from scanning.

**Rule and result identity.** Today only `yara_gate_ext` is provided as contextual input. `verdict_on_match` determines severity; missing or invalid values default to block. Extra metadata such as `confidence`, `profile`, or `category` would not change behavior by itself. `Finding` has no namespace/member identifier, and `ScanResult` has no engine/ruleset fingerprint. Future policy needs explicit wiring and provenance, especially when vendor rules have overlapping names. See [models.py](../../src/yara_gate/models.py) and [scanner.py](../../src/yara_gate/scanner.py).

**Compilation completeness.** `compile_sources` skips individual compile failures; the scanner discards the skip list and can complete using the remaining rules. Define which rules are required for a profile and surface missing coverage. A new rule that silently fails compilation must not count as delivered detection.

## Rule authoring and acceptance

Use specific literal anchors, bounded regular expressions, and multiple independent signals. Measure performance before choosing proximity distances or occurrence caps. A `filesize` condition is not a substitute for scanner-level resource limits. Compile against the locked YARA-X version, including any modules and external globals actually used.

For English byte strings, `ascii wide` can cover zero-interleaved text. It is not general Unicode/UTF-16 language support. Keep base64 patterns separate because `base64` cannot be combined with `nocase`; include plaintext separately. Multilingual coverage needs reviewed language examples and text decoding, not simply the `wide` modifier. [YARA-X text pattern semantics](https://virustotal.github.io/yara-x/docs/writing_rules/text-patterns/).

Store stable rule IDs, version, purpose, source reference, proposed verdict, supported views, and documented benign collisions. Use existing `status = "candidate"` for inactive proposals, recognizing that the current loader skips candidates entirely. A dedicated temporary evaluation rules tree can activate advisory copies without installing them. Keep related private helper rules in the same source unless cross-file loading has been verified: this loader validates files individually and assigns separate namespaces.

Before promotion, require:

1. Positive examples, benign near-misses, and real representative benign files for the intended consumer. Include multilingual prose, emoji, quoted attacks, source code, installation instructions, and legitimate templates.
2. Equivalent-content cases: alternate encoding, whitespace, entities, supported containers, and extension changes. Document which transformations remain unsupported rather than claiming exhaustive recall.
3. Expected rule IDs and consumer dispositions, not just exit codes. Verify report redaction, correct member/view attribution, and incomplete-scan behavior through the actual CLI path.
4. Measured false-positive rate with a denominator, per-family detection rate on a labeled corpus, compile skips, and scan latency/memory on representative large benign files. This synthetic probe supplies no production accuracy or performance estimate.
5. Independent held-out samples before enabling block. Matching the sample used to author a rule and two small benign fixtures is insufficient evidence of generality.

## Recommended order of work

1. **Coverage and policy prerequisites:** address the demonstrated Unicode collisions, archive member metadata/heuristic behavior, and advisory handling. Keep each production change focused and verify it separately.
2. **First advisory research pack:** implement role/action spoofing, secret-transfer requests, encoded variants, and external-template rules in an isolated rules tree. These cover both agent-specific and ordinary document intake gaps without immediately changing default blocking.
3. **Developer and attachment pack:** evaluate download/execute combinations, lifecycle hooks, shortcuts, and parsed active-document chains on relevant benign corpora.
4. **Vendor comparison:** load the pinned packs into a disposable rules tree, identify actual compiled coverage and duplicate findings, then assess marginal benefit of local additions. YARA Forge already aggregates multiple sources; adding another broad pack by count alone can duplicate existing detections. [YARA Forge](https://github.com/YARAHQ/yara-forge). Keep upstream attribution and license terms attached to rule provenance; Elastic labels its artifacts under Elastic License 2.0. [Elastic source](https://github.com/elastic/protections-artifacts).

Candidate production touchpoints are `rules/local/`, `scanner.py`, `heuristics.py`, `models.py`, `report.py`, and later explicit CLI/caller policy. This research adds only this brief, its probe, and recorded observations. It does not enable any proposed detector or change an existing verdict.

## Reproducing the baseline

From the repository root, install the locked runtime with `uv sync --frozen --no-dev`. Run `.venv/bin/python docs/research/probe_rule_coverage.py --verify` for the expanded implementation checks. The baseline JSON preserves the earlier 21-input observation; the current probe has additional cases and expectations. It deletes its own temporary files and homes after reading results and never executes sample commands. Installation may download dependencies, while the probe itself performs no network operations. The installed scanner version was 0.2.0.

Validation for these research artifacts: the probe completed all 21 library scans and two CLI runs; Ruff 0.16.1 lint and format checks passed on the probe. No production source, rule, workflow, or lockfile was edited. No full local suite was run.
