# Prompt-injection coverage: measured baseline, gaps, and an expansion map (2026-11-01)

Scope: how far the shipped detection reaches against prompt injection and nearby agent-intake attacks, what public research says is missing, and what to build next without breaking the contracts in `AGENTS.md`.

The baseline is `main` at `1d13547`, the merge of #147. It ran on Linux with Python 3.12.3, YARA-X 1.22.1 from the lock, and 82 local rules compiled from 57 files with 0 skipped. No vendor packs were installed.

**Status:** F2 and F5 are implemented. [The verification record](../verification/2026-11-01-unicode-channels-turn-markers.md) has the before and after results. LLMail send-tool holds went from 6.41% to 23.95% under `agent-ingest` and from 2.59% to 14.25% under `agent-document`, with no change on the benign sets. The rest of this note describes the baseline at `1d13547`.

**Evidence labels:**
- **measured:** run in this session by the scripts below.
- **probed:** one constructed inert input; this is an observation, not a rate.
- **sourced:** a public write-up retrieved by this session's research agents. *secondary* marks a news summary used because the primary was unreachable.
- **assessment:** my judgment.

**Artifacts added with this note:**
- [`probe_injection_gaps.py`](probe_injection_gaps.py): 104 inert cases, with no network and no Pillow.
- [`measure_injection_corpora.py`](measure_injection_corpora.py): public corpora. It does not download anything.
- [`injection-candidates-2026-11-01.yar`](injection-candidates-2026-11-01.yar): research-only candidate shapes. They are not loaded by the scanner.
- Records that hold no sample text: [`injection-gap-probe-2026-11-01.json`](injection-gap-probe-2026-11-01.json) and [`injection-corpora-2026-11-01.json`](injection-corpora-2026-11-01.json).

## Bottom line

1. **Precision is excellent and recall on real attacks is low (measured).**
   - LLMail-Inject has 3,165 attack emails that made the challenge's email agent call its send tool. `agent-ingest` holds 6.4% of them and `agent-document` holds 2.6%.
   - On 203 benign false-positive-test emails and 399 benign prompts, the hold rates are 0% and 0.5%.
2. **The misses are ordinary, not exotic (measured).**
   - In the tool-triggering set, the canonical override phrase fired on 10 of 3,165 emails (0.3%).
   - What those attacks actually do is spoof conversation turns or context boundaries, and order a tool call ("send … to … with the body …").
   - The shipped rules mostly catch them only when the author also smuggled Unicode. Tag characters account for 64 blocks; invisible-character notes for 109.
3. **Real-world PDFs are the largest verified gap in a channel the README claims (measured).**
   - Chrome print-to-PDF and LibreOffice export write visible text as hex glyph codes decoded through a ToUnicode CMap.
   - An injection sentence that `pdftotext` extracts verbatim scans **clean** from the Chrome PDF. From the LibreOffice PDF it gets only an unrelated `/OpenAction` note.
   - Kerned `TJ` arrays, hex strings, and octal escapes miss as well.
4. **Unicode smuggling is half covered (probed).**
   - Tag characters block.
   - Variation-selector smuggling scans clean.
   - Sneaky Bits and zero-width binary payloads get notes only, so `agent-document` passes them.
5. **Generic deterministic shapes can recover a lot, with a caveat (measured, research-only).**
   - Nine generic rule shapes raised union recall on the tool-triggering set from 6.4% to **53.8%**. They hit 0 of 203 benign emails, 0 of 399 benign prompts, and 0 of 573 stdlib files. They hit 1 of 68 package READMEs, pyparsing's "instructions for AI agents".
   - They were written knowing the LLMail objective, so 53.8% is an upper bound until a held-out corpus confirms it.
6. **Deterministic rules plateau (measured).** Social-engineering emails that read like a normal request to a human stay near 5.6% even with the candidates. The remainder needs one of two things:
   - an optional semantic tier that can only add holds; or
   - consumer architecture: egress allowlists, approval for side-effecting tools, and no auto-rendered images or links.
7. **Strategy (assessment):** the gate still has no consumer (#74). A week of real hold data from one integration ranks the remaining work better than any synthetic corpus, this one included.

## 1. Baseline: claims against measurements

### 1.1 Project state on 2026-11-01

- **History:**
  - Issue and PR numbers have reached #148.
  - 66 commits on `main` since 2026-10-01.
  - Recent themes: the PDF view (#129–#137), precision and tiering work (#126–#139), vendor setup and grading (#142–#144), and the demos (#146–#147).
- **Open issues:**
  - #145: six verified coverage gaps.
  - #110: hidden Office/PDF text, waiting on three owner decisions.
  - #74: first consumer, waiting on decisions (a)–(c).
  - #39: reviewed release, a prerequisite for document corpora.
  - #38: `serve --stdio`.
  - #80: sync folder on Windows.
- **Draft PR:** #148, README links.
- **Integration:** the README says neither CyClaw nor CG-agent-harness calls yara-gate yet. I could not check those repositories from this session.

### 1.2 README claims checked

| README claim | Status | Evidence |
| --- | --- | --- |
| 82 rules in 57 files | Holds | measured: 82 compiled, 0 skipped |
| Override phrases in 8 languages plus English | Holds as stated | probed: Spanish is a note. Dutch, Polish, Turkish, Korean, Arabic, Hindi, Indonesian, Vietnamese, and Ukrainian are clean (not claimed) |
| Markdown-image exfiltration | Narrow | probed: only an inline `](https://…{{` or `${` link matches. Reference-style images, HTML `<img>`, and "replace DATA with …" are clean |
| Invisible Unicode | Partial | probed: tags block; zero-width is a note. Variation-selector smuggling is clean. A 224-character Sneaky Bits or ZW binary payload gets the same notes as one stray ZWSP |
| Look-alike spellings | Partial | probed: Cyrillic, Greek, fullwidth, and math alphanumerics fold. Armenian `օ`, dotless `ı`, and combining overlays are clean |
| Base64-wrapped instructions | Narrow | probed: six literal phrase encodings plus the generic run of ≥400 characters. A paraphrase or upper-case variant in base64 is clean |
| Hidden HTML instructions | Narrow | probed: `display:none`, `font-size:0`, `visibility:hidden`, or `<!--` within 256 bytes of a canonical phrase. `opacity:0`, off-screen, white-on-white, `hidden`, `aria-hidden`, and zero-height are phrase notes only |
| Text in compressed PDF streams | **Overstated** | measured: literal strings in simple fonts work. CID/ToUnicode text (Chrome, LibreOffice), `TJ` kerning, hex strings, octal escapes, and UTF-16 `/Info` strings miss. `docs/rules.md` does not state this limit |
| Sentences split across Word runs | Holds for DOCX | probed: ODT spans miss. XLSX inline strings are #145 item 4 |
| MCP tool poisoning | Narrow | probed: works on a `description` in a `.json` file. Poisoned parameter names, Python `@mcp.tool` docstrings, and text tool results with the same `<IMPORTANT>` block are clean |
| 1–7 ms per message | Holds | measured: 37,729 corpus samples in 161 s (4.3 ms each, longer emails); probe calls averaged about 2.5 ms |
| Synthetic precision | Holds, plus new data | measured: 0/203 benign emails, 2/399 benign prompts (lone-control notes) |

The README is unusually candid about limits ("a paraphrased attack in plain prose can pass"). The PDF row is the one claim to correct. Add the CID/ToUnicode limit to `docs/rules.md` until a fix lands.

### 1.3 The Pages demo

- **Not loaded live.** `cgfixit.github.io` is blocked by this session's network policy, so I did not open the hosted page.
- **Probably live.** The `pages-demo` `workflow_dispatch` run on `main` at `1d13547` succeeded at 2026-11-01 20:29 UTC (run 41347105100).
- **What I did instead:** built the same artifact with `scripts/build_pages.py` from `1d13547` and rendered it in headless Chromium.
  - Zero console errors.
  - Only two `<select>` controls, with no text input, upload, or form.
  - The CSP and disclaimers are as documented.
- **Stale count.** The recordings come from `68e27e7` with 80 rules; `main` has 82. The page labels this.
- **Weakest cases shown.** The six scenarios are plain text, a quoted phrase, a secret request, an entity-encoded phrase, a PE named `.pdf`, and a compile failure. They show the gate at its least distinctive. None shows a tag-smuggling block, look-alike folding, a phrase split across Word runs, MCP poisoning, archive coverage, or a fail-closed encrypted PDF.
- **Recommendation (assessment):** re-record with two or three of those cases when the next refresh is due.

## 2. Measured recall and false positives on public corpora

**Method:**
- Each sample was scanned once with `scan_bytes` under the default policy, against a disposable copy of `rules/local`.
- Message corpora were named `message.txt`; files kept their own names.
- Policy outcomes follow from the strongest finding: `agent-ingest` holds any finding, and `agent-document` holds advisory, block, and incomplete.

| Set | Kind | n | `agent-ingest` holds | `agent-document` holds | Research candidates | Union |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| LLMail: send tool actually triggered | attack | 3,165 | 6.41% | 2.59% | 48.56% | **53.81%** |
| LLMail: judged direct instructions | attack | 13,169 | 5.35% | 0.61% | 38.90% | 40.21% |
| LLMail: judged obfuscation | attack | 4,370 | 5.72% | 1.56% | 39.31% | 43.18% |
| LLMail: judged social engineering ("unclear") | attack | 13,660 | 1.52% | 1.47% | 4.17% | 5.63% |
| deepset prompt-injections, label 1 | attack | 263 | 3.04% | 0.00% | 1.90% | 4.94% |
| LLMail FP-test emails | benign | 203 | 0.00% | 0.00% | 0.00% | 0.00% |
| deepset, label 0 | benign | 399 | 0.50% | 0.00% | 0.00% | 0.50% |
| CPython 3.12 stdlib `.py` | benign | 573 | 0.00% | 0.00% | 0.00% | 0.00% |
| npm and site-packages READMEs/METADATA | benign | 68 | 4.41% | 4.41% | 1.47% | 5.88% |
| `measure_precision.py` corpus | benign | 320 | 1.25% | 1.25% | 0.00% | 1.25% |
| This repository's Markdown | documentary | 73 | 27.40% | 20.55% | 1.37% | 27.40% |

**What the corpora are:**
- **LLMail-Inject** is Microsoft's 2025 challenge (MIT, phase 2 `labelled_unique_submissions_phase2.json`).
  - "Send tool actually triggered" is the challenge's own ground truth.
  - The other LLMail categories are the dataset's LLM-judge labels.
  - Every LLMail attack aims at one objective: make the agent email an address with a fixed body. Recall on other objectives is not measured here.
- **deepset/prompt-injections** (Apache-2.0) is short direct prompts in English and German.

**Who fires (measured):**
- **Shipped rules, send-tool set:**
  - `agent_invisible_unicode`: 109
  - `heuristic_unicode_tag`: 64
  - `agent_fake_chat_marker`: 17
  - `agent_prompt_injection_phrases`: 10
- **Candidates:**
  - `cand_turn_marker_extended`: 873
  - `cand_send_to_address_with_content`: 783
  - `cand_context_boundary_spoof`: 173
  - `cand_task_override` and `cand_tool_call_directive`: 40 each
  - `cand_ai_vocative`: 26

**Benign hits by the shipped rules (measured):**
- npm's README and ruff's package README are held under both agent policies by `script_download_execute`, because of their documented `curl … | sh` installers.
- In the cloned-repository channel, that is the expected cost of the rule, and a reason #39 matters.
- The third package hit is yara-gate's own README inside its METADATA (documentary).
- The 4 precision-corpus hits are the four documented Windows shortcut-family collisions.

## 3. Gap probe: 104 inert carriers (probed)

`probe_injection_gaps.py` builds each case in memory and scans it under all three policies. Of the 103 cases that are not the benign control, 63 are clean under every policy, 31 are notes only (held by `agent-ingest` alone), and 9 are advisory or block.

| Group | Advisory or block | Note only | Clean | Clean cases |
| --- | ---: | ---: | ---: | --- |
| lexical | 0 | 1 | 6 | paraphrase, synonym override, AI-addressed SEO note, reviewer manipulation, résumé ranking, "repeat the words above" |
| multilingual | 0 | 1 | 9 | nl, pl, tr, ko, ar, hi, id, vi, uk |
| encoding | 0 | 1 | 9 | base64 of a paraphrase or upper case, hex, `%XX`, ROT13, reversed, hyphenated syllables, `i/g/n/o/r/e`, `=20` QP |
| unicode | 2 | 6 | 4 | variation-selector smuggling, dotless `ı`, Armenian `օ`, combining overlay |
| exfil | 1 | 0 | 6 | reference-style image, HTML `<img>`, "replace DATA" instruction, `$TOKEN` link, DNS subdomain, `%XX` URL fragment |
| hidden-html | 1 | 7 | 2 | comment without a canonical phrase, phrase split by `<b>` (#145 item 5) |
| media-metadata | 0 | 6 | 2 | PNG `zTXt`, compressed PNG `iTXt` |
| calendar-mail | 0 | 2 | 2 | RFC 5545 folded `DESCRIPTION`, RFC 2047 encoded `Subject` paraphrase |
| document | 0 | 6 | 7 | ODT span split, RTF control-word split, PDF `TJ` kerning, PDF hex string, PDF octal escape, PDF CID/ToUnicode, PDF UTF-16 `/Info` |
| agent-ecosystem | 2 | 0 | 12 | MCP parameter-name poisoning, `<IMPORTANT>` tool result in text, `@mcp.tool` docstring, rules-file script injection, env-var exfil in `AGENTS.md`, GitHub-issue toxic flow, fake `Human:` turn, memory poisoning, delayed tool trigger in ICS, "use the send_email tool", `### SYSTEM OVERRIDE ###`, Policy Puppetry |
| chat-markers | 2 | 0 | 4 | Llama 2 `[INST]`/`<<SYS>>`, Gemma `<start_of_turn>`, Harmony `<\|start\|>`, Zephyr `<\|system\|>` |

**Cases that are only notes and arguably should not be (probed):**
- Six hiding styles carrying a canonical phrase: white-on-white, off-screen, `opacity:0`, the `hidden` attribute, `aria-hidden` with 1px text, and zero-height.
- A two-run DOCX `w:vanish` phrase and a PDF `3 Tr` phrase (#110).
- Sneaky Bits and zero-width binary payloads.

**Real readers see these payloads.** I checked that ordinary parsers recover the hidden text from the probe fixtures:
- `pdftotext` extracts the phrase from the CID, `TJ`, hex, and octal PDFs.
- `pdfinfo` prints the UTF-16 `/Subject`.
- Pillow decodes the PNG `zTXt` comment.
- LibreOffice reads the ODT sentence.

So these are blind spots for the gate, not inputs that nobody reads.

## 4. Documents from real generators (measured)

The same sentence was placed in each document, and each file was scanned with `scan_file(..., policy="agent-ingest")`.

| Generator | Result | Why |
| --- | --- | --- |
| Chromium print-to-PDF (Playwright `page.pdf`) | **clean** | Text is `<0034005800440055…> Tj`: Identity-H glyph codes that only the ToUnicode CMap maps to letters |
| LibreOffice Writer PDF export | block, but only from `heuristic_pdf_OpenAction_goto` (note) | Text is `<0102030405…>Tj` in a subset font; the phrase is never seen. Under `agent-document` it passes |
| ReportLab (Type1 Helvetica) | note on `pdf-flate` | Literal strings, which the current view reads |
| LibreOffice and pandoc DOCX, ODT, EPUB | note | Phrase in one run or span |

**Assessment:** most PDFs that people actually share are written by Chromium/Skia, LibreOffice, Microsoft Word, or Quartz, and those embed subset or CID fonts. The `pdf-flate` view therefore covers a minority of real PDFs for lexical rules. Its structural checks (actions, JavaScript, embedded files) are unaffected.

## 5. Research synthesis

### 5.1 The sources supplied for this task

Three of the six links were read in full. Their hosts are **blocked** by this session's network policy and were not read; content from them is not represented here:
- christian-schneider.net
- iamvera.ai
- www.codeant.ai

**Sysdig, "The Comprehensive Guide to Prompt Injection Attacks in 2026"** (updated 2026-08-07). Sourced.
- It frames risk as the "lethal trifecta": private data, untrusted content, and an outbound channel.
- It calls indirect injection the dominant enterprise pattern.
- It says input filtering "misses anything unfamiliar: encoded payloads, multilingual evasion, and instructions buried in retrieved content". The measurements above agree.
- It recommends capability-based planning, dual-model separation, least privilege, human approval, and egress control.
- Its defense statistics ("adaptive attacks bypass more than 90% of published defenses") cite footnotes that do not resolve on the page. Treat them as unverified there.

**Sinha and Chavan, "Hiding in Plain Floats" (arXiv 2606.08403, June 2026).** Sourced.
- Steganographic carriers in configuration data defeat classifiers. A float-array carrier kept 94.3% leakage success against a Prompt Guard 2 plus TF-IDF ensemble that scans both raw and reconstructed text.
- Zero-shot Prompt Guard 2 detected 0% of their declarative-metadata payloads (`[SYS-ROLE: …]`, `[GRADE: …]`), even as plain text.
- A narrow deterministic xxd-line detector cut one carrier's success from 95.6% to 0.0%.
- Lessons for this gate:
  - Rules keyed on imperatives miss declarative authority tags.
  - Carrier-specific deterministic checks beat general classifiers on the carriers they target.
  - Scan the text the downstream reader reconstructs.
- The paper also argues that a reproduced marker can trigger downstream automation even when the model quotes it while refusing. That is a caveat to `agent-document`'s notes-only read rule, which assumes no grep-like consumer downstream.

**Nguyen and Husain, MMPIBench (arXiv 2609.09404, September 2026).** Sourced.
- Across 720 multimodal runs, 1.11% of attacks completed and 12.8% were attempted.
- OCR-readable text in images produced 7 of the 8 completions. EXIF and QR payloads were never attempted, and went unperceived in about 88% of runs, because models do not read them from pixels.
- Audio completed in 35 of 72 runs where a framework delivered it.
- Containers such as PDF, HTML, and spreadsheet metadata reach the model as text extracted by a parser. That is exactly where a metadata view or a text view in the gate earns its keep.

### 5.2 Carriers documented in the wild, 2024–2026

These come from public reporting gathered in this session. Items marked *secondary* rest on a news summary because the primary host was unreachable from this session.

- **Calibration.**
  - Unit 42 (2026-03) found that 37.8% of observed indirect-injection deliveries were plain visible text, attribute cloaking was 19.8%, and CSS hiding was 16.9% ([Unit 42](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)).
  - A USENIX Security 2026 study found hidden content in about 1% of 196,682 résumés, and over 90% of it was keyword stuffing, not instructions ([arXiv 2605.28999](https://arxiv.org/abs/2605.28999)).
  - So phrase rules on visible text stay primary, and hidden text alone should stay a note. Hidden text *plus* a directive should be advisory, as #110 proposes.
- **PDF hiding at low false-alarm rates is feasible.** PhantomLint reports a 0.092% false-alarm rate on 3,257 papers using render mode, fill colour, size, position, clipping, `/ca`, and OFF optional-content groups ([arXiv 2508.17884](https://arxiv.org/abs/2508.17884)).
  - Malicious fonts that remap cmap/ToUnicode reach up to 70% success in PDFs ([arXiv 2505.16957](https://arxiv.org/abs/2505.16957)).
  - So the PDF text view should read what extractors read (ToUnicode), which is what LLM pipelines ingest.
- **Unicode channels.**
  - Tag smuggling ([Embrace The Red, 2024-01](https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/)).
  - Variation-selector smuggling ([Butler, 2025-02](https://paulbutler.org/2025/smuggling-arbitrary-data-through-an-emoji/)).
  - Sneaky Bits with U+2062/U+2064 ([Embrace The Red, 2025-03](https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/)).
  - Default-ignorable code points outside category Cf: U+034F, U+115F, U+1160, U+3164, U+FFA0, and U+180B–U+180F ([UAX #44](https://www.unicode.org/reports/tr44/)). The current `format-controls-removed` view strips only Cf.
- **Agent ecosystem.**
  - MCP tool poisoning ([Invariant, 2025-04](https://invariantlabs.ai/blog/mcp-security-notification)).
  - Full-schema poisoning in parameter names, enums, and defaults ([CyberArk, 2025-05](https://www.cyberark.com/resources/threat-research-blog/poison-everywhere-no-output-from-your-mcp-server-is-safe)).
  - The GitHub MCP toxic flow ([Invariant, 2025-05](https://invariantlabs.ai/blog/mcp-github-vulnerability)).
  - Rules-file backdoors with hidden Unicode (Pillar, 2025-03, *secondary*: [The Hacker News](https://thehackernews.com/2025/03/new-rules-file-backdoor-attack-lets.html)).
  - Malicious Agent Skills: ClawHavoc, reportedly at least 1,184 skills ([Antiy](https://www.antiy.net/p/clawhavoc-analysis-of-large-scale-poisoning-campaign-targeting-the-openclaw-skill-market-for-ai-agents/)); also [Datadog, 2026-05](https://securitylabs.datadoghq.com/articles/malicious-skills-supply-chain-risks-in-coding-agents-with-dynamic-context/).
  - Calendar-invite injection (SafeBreach, Black Hat 2025, *secondary*).
  - Memory poisoning and delayed tool invocation (*secondary*).
- **Exfiltration shapes.**
  - EchoLeak (CVE-2025-32711) used reference-style Markdown to get past link redaction ([arXiv 2509.10540](https://arxiv.org/abs/2509.10540)).
  - CamoLeak used one proxied image URL per character ([Legit, 2025](https://legitsecurity.com/blog/camoleak-critical-github-copilot-vulnerability-leaks-private-source-code)).
  - Mermaid `click` links (Cursor CVE-2025-54132, CVE-2025-61589; *secondary*).
  - Link previews (PromptArmor).
  - Percent-encoded URL fragments (HashJack, Cato, 2025-11, *secondary*).
  - ANSI/OSC terminal sequences ([Embrace The Red, 2024-12](https://embracethered.com/blog/posts/2024/terminal-dillmas-prompt-injection-ansi-sequences/)).
- **Taxonomy.** MITRE ATT&CK added T1698 "Indirect Prompt Injection" (tactic Execution; created 2026-09-18, modified 2026-10-12; [T1698](https://attack.mitre.org/techniques/T1698/), checked in this session). New rule metadata can cite it next to ATLAS AML.T0051.

### 5.3 Detector and rule-pack landscape

This section comes from the research agent's checks on 2026-11-01:
- licences and last commits from shallow clones;
- every pack compiled with YARA-X 1.22.1;
- raw YARA-X over plain text, counting the share of items with any match.

That is not the yara-gate pipeline (no views, no globals) and not a production false-positive rate.

**The current vendor packs carry no prompt-injection rules.** That holds for signature-base and Elastic at their heads, and for the YARA Forge `20261101` full release. The one AI-agent exception is signature-base's `susp_claude_magic_strings.yar`: four `ANTHROPIC_MAGIC_STRING_TRIGGER_*` rules, already in the pinned `94a1c48` and Forge core `20261004`.
- Under this repository's grading they **block** any document that merely quotes the string, such as Claude documentation or a security note.
- **Action:** review them for `rules/vendor-overrides.json` (likely `note`).
- **Licence flags already in the vendor set:** signature-base is DRL 1.1, Elastic is ELv2, and the YARA Forge repository is GPL-3.0. The licences of Forge's rule packages are not verified.

**Prompt-injection rule packs:**

| Pack | Licence | Last commit | YARA-X 1.22.1 | Raw hits: benign BrowseSafe / yara-gate docs | Raw hits: LLMail attacks | Fit |
| --- | --- | --- | --- | --- | --- | --- |
| [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) core | Apache-2.0 | 2026-10-26 | 27 rules compile | 0.9% / 2.4% | 3.8% of 21,007 | Best candidate. `prompt_injection_generic` had 0 benign hits in all five benign sets. Low recall; overlap with the local rules is unmeasured |
| [Ramparts](https://github.com/highflame-ai/ramparts) | Apache-2.0 | 2026-10-08 | 40 rules compile | 53.6% / 47.6% | 14.1% | Its prompt-injection file is adapted from Cisco's. Its injection-family rules cause most hits. Borrow the idea of rescanning decoded views, not the pack |
| [ai-dfir-toolkit](https://github.com/depalmar/ai-dfir-toolkit) | Apache-2.0 | 2026-09-30 | 26 rules compile | 15.0% / 9.8% | 2.2% | Broad topics (rules-file backdoor, RAG hidden text, PDF white text). Its any-invisible-character rule matched 233 benign items, so note or advisory only |
| [Cisco mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) / [a2a-scanner](https://github.com/cisco-ai-defense/a2a-scanner) | Apache-2.0 | 2026-10-28 / 2026-04-16 | compile | 10.3% / 42.7% (mcp); 93.5% benign BrowseSafe (a2a) | 2.8% (mcp) | Too noisy to block |
| [Vigil](https://github.com/deadbits/vigil-llm) | Apache-2.0 | 2024-01-31 ("alpha") | `react.yar` fails (E014) | n/a | n/a | Not a fit |
| [ATR](https://github.com/Agent-Threat-Rule/agent-threat-rules) | MIT | 2026-11-01 | 844 YAML regex rules, not YARA; 414 of 3,471 regexes use syntax YARA-X rejects | `maturity: stable` subset: 1.3% / 4.9% | 0.6% (stable) | Every rule ships positive and negative test cases. Use them as regression seeds, not as a pack |
| [Snyk agent-scan](https://github.com/snyk/agent-scan) (Invariant mcp-scan) | Apache-2.0 | 2026-10-28 | n/a | n/a | n/a | Sends components to the Snyk API; not offline |

**Assessment:**
- No external YARA pack moves recall much. The best one, Cisco's, matched 3.8% of LLMail attacks raw, against 6.4% for the shipped rules through the full pipeline. The F5/F6 shapes here reach 48.6% on the send-tool set.
- If a pack is added, take Cisco skill-scanner core alone:
  - pin the codeload tarball by SHA-256;
  - load it in its own namespace (its rule names are generic);
  - grade it through the override list;
  - measure its overlap with the local rules using `measure_injection_corpora.py` first.

**Offline classifiers, for F15:**

| Model | Licence | Notes |
| --- | --- | --- |
| [Llama Prompt Guard 2](https://github.com/meta-llama/PurpleLlama/blob/main/Llama-Prompt-Guard-2/86M/MODEL_CARD.md), 86M / 22M | Llama 4 Community License, gated; **not OSI** | 512-token window. English AUC .998 / .995. On BrowseSafe HTML pages, recall 0.221 / 0.213 at precision 0.983 / 0.975. Zero-shot, it detected 0% of declarative-metadata payloads (arXiv 2606.08403) |
| [ProtectAI deberta-v3-base-prompt-injection-v2](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) | Apache-2.0; the project is archived | English only, about 184M parameters (inferred from deberta-v3-base). Self-reported recall 99.74% and precision 91.59% on 20,000 unseen prompts |
| [PIGuard](https://huggingface.co/leolee99/PIGuard) (formerly InjecGuard) | MIT | DeBERTa-based, aimed at over-defense. NotInject results in [arXiv 2410.22770](https://arxiv.org/abs/2410.22770) |

"The Attacker Moves Second" ([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)) bypassed 12 published defenses "with attack success rate above 90% for most". A search attack that sees the detector's score exceeded 90% against Protect AI, PromptGuard, and Model Armor, and reached 71% against PIGuard.

So a classifier tier can add holds on paraphrases but cannot be trusted to clear anything. That matches F15's "can add a hold, never clears one" design. It also argues for doing F15 after the deterministic families, not instead of them.

**Corpora to add to the harness:**
- **[BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench)** (MIT, 14,719 HTML pages with benign negatives). Write each page as `.html` so the HTML views run. It is the right test for F7 and F8.
- **NotInject** (MIT, 339 benign prompts full of trigger words). An over-defense test for `agent-document`.
- **AgentDojo and InjecAgent** (MIT) for tool-output text.
- **BIPIA** (MIT, archived 2026-09-16) for indirect contexts.
- WASP and Qualifire's set are non-commercial (CC BY-NC); keep them out of any shipped artifact.
- **Generators for real document fixtures** (F17): PyRIT's `pdf_converter`, `word_doc_converter`, and its ASCII and variation-selector smugglers (MIT), and Spikee's document datasets and `*-fp` negatives (Apache-2.0).

### 5.4 Why detection is a narrowing layer, not the defense

Adaptive attacks bypass detectors at high rates: above 90% for most of 12 defenses in arXiv 2510.09023, and 94.3% for a float-array carrier in arXiv 2606.08403. Sysdig's uncited claim matches those primary results. This corpus run shows the same limit from the other side: social-engineering emails that read like an ordinary request to a person are indistinguishable from mail an agent should read.

The gate's job is to remove the cheap, known, and hidden shapes and to fail closed on what it cannot read. The consumer still has to:
- deny auto-rendered external images and links;
- allowlist egress;
- require approval for side-effecting tools such as `send_email`; and
- keep untrusted content fenced as data.

A clean record permits reading, never obeying.

## 6. Feature map

**Priority** is assessment-ranked: evidence × prevalence × feasibility × low false positives. **Severity** follows the existing ladder:
- An encoding channel with no ordinary use blocks, as `heuristic_unicode_tag` does.
- Hidden text plus a directive is advisory.
- A visible directive alone is a note.
- Conjunctions escalate a note to advisory.

**Size:** S is under a day, M is a few days, L is a design decision plus a week or more.

| Intake channel (README) | Verified gaps that matter most there | Features |
| --- | --- | --- |
| Messages: Telegram, SMS, webhooks | Tool directives, turn spoofing, variation-selector smuggling, uncovered languages | F2, F5, F6, F11 |
| Synced corpus and RAG uploads | CID/ToUnicode PDFs, hidden Office/PDF text, ODT and RTF splits | F1, F9, F3 |
| Web pages and HTML tool results | CSS and attribute hiding, exfiltration shapes, inline-tag splits | F8, F7, F3 |
| MCP configs and tool results | Schema poisoning, poisoned text results, server docstrings, rug pulls | F4, F18 |
| Cloned repositories | Agent instruction files, skills, terminal escapes | F12, F13 |
| Mail and calendar | RFC 2047 headers, ICS folding, HTML parts that differ from plain parts | F10, F8 |
| Images and audio for a multimodal model | Pixels and audio are unread | F14 |

### P0: make existing claims true

| ID | Change | Evidence | Mechanism | Severity | FP risk | Size |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | **PDF text view** (`pdf-text`):<br>• ToUnicode CMap decoding (`bfchar`/`bfrange`) for hex and literal strings, per font resource<br>• `TJ` joins, inserting a space for large kerning<br>• literal-string escapes (octal, `\n`, `\(`)<br>• UTF-16BE text strings in `/Info`, annotations, and form values<br><br>Then build #110's `pdf-hidden-text` on it. | §3, §4: Chrome and LibreOffice PDFs clean or phrase-blind; 5 PDF probe misses | stdlib parser with the existing stream reader and budgets. Fix the `sniff()` admission gap noted on #110 (a binary-first content stream skips the view) | Existing rules | Low: same rules, new view; keep samples mode for image streams | M |
| F2 | **Invisible encoding channels:**<br>• supplementary variation selectors U+E0100–U+E01EF outside ideographic variation sequences<br>• runs of BMP VS outside emoji presentation<br>• runs of 8 or more of U+2061–U+2064, U+200B–U+200D, U+2060, or Hangul fillers<br><br>Decode the payload into a labelled view for the phrase rules. | §3 unicode: VS clean; Sneaky Bits and ZW binary are notes | Heuristic beside `tag_findings`; add Default_Ignorable code points to the control-removed view | Block, like tags | Low: emoji ZWJ sequences and IVS handled explicitly | S |
| F3 | **#145 items 1–6** (pickle LONG1/LONG4, `Set-MpPreference`, folding after JSON unescape and OOXML join, XLSX inline strings, HTML text view, SVG event handlers) | Verified in #145 on `68e27e7`. Item 5 re-observed here on `1d13547`; the others were not re-run | As scoped in #145 | As scoped | As scoped | S–M each |
| F4 | **MCP poisoning everywhere:**<br>• run the `<IMPORTANT>`, secret-path, pass-along, and do-not-tell shapes as a YARA rule on every text unit and view<br>• walk every schema string: property names, `title`, `enum`, `default`, `examples` | §3 agent-ecosystem: 3 misses | Port `_HIDDEN_INSTRUCTION` to YARA; extend `_walk_mcp` | Advisory, like the current heuristic | Moderate on security write-ups; pairs needed | S |

### P1: new families with measured lift

| ID | Change | Evidence | Mechanism | Severity | FP risk | Size |
| --- | --- | --- | --- | --- | --- | --- |
| F5 | **Turn and boundary spoofing:**<br>• Llama 2 `[INST]`/`<<SYS>>`, Gemma, Harmony, Zephyr/Phi<br>• piped and XML role tags; BEGIN/END USER<br>• spoofed closers such as `</email>`, `</context>`, `</function_results>`, `</tool_output>`<br>• `\n\nHuman:` turns | §2: `cand_turn_marker_extended` 873/3,165 and `cand_context_boundary_spoof` 173/3,165; 0 benign hits | Extend `agent_fake_chat_marker`; restrict closers to text, mail, and Markdown | Note alone; advisory with an instruction verb or in a message input | Chat-template docs, tokenizer configs, and ML notebooks; scope by suffix | S |
| F6 | **Tool directives:**<br>• send/forward … to an address … with body or subject<br>• "use/call/invoke the X tool to send…"<br>• concealment ("do not tell the user", "silently") within 300 bytes of a target | §2: `cand_send_to_address_with_content` 783/3,165; §3: 4 misses | YARA conjunctions as in the candidate file | Note alone (people ask people to send things); advisory with F5, F8, concealment, or an AI vocative | Business mail; validate on real mail before shipping | S |
| F7 | **Exfiltration shapes:**<br>• reference-style images and links with placeholders<br>• `<img src>` with a placeholder<br>• Mermaid `click`/`<img>`<br>• DNS command templates<br>• 26 or more URLs that differ by one segment (per-character dictionary) | §3 exfil: 6 misses; EchoLeak, CamoLeak, Cursor CVEs | YARA, plus one URL-cluster heuristic | Advisory | Low for the placeholder forms; shields.io badges are a near miss | S–M |
| F8 | **HTML, SVG, and mail hidden-content conjunction:**<br>• hiding via `opacity:0`, off-screen offsets, `clip`, zero height, colour equal to background, `hidden`, `aria-hidden` with visually-hidden<br>• `data-*`, `title`, `alt`, and `<meta name="ai:*">` text | §3: 7 note-only and 2 clean cases; Unit 42: 19.8% attribute, 16.9% CSS | `html.parser` view built on #145 item 5, emitting `html-hidden-text` | Hidden alone: note. Hidden plus any note: advisory | Screen-reader text and menus; this is why hiding alone is a note | M |
| F9 | **#110 Office/PDF hidden text** | §3: `w:vanish` and `3 Tr` are notes only; PhantomLint precedent | As in the issue comment; take option (i) for OCR layers | Advisory with a directive | OCR text layers; option (i) handles them | M |
| F10 | **Bounded decoder views, gated on printable output:**<br>• percent-decoding of URLs including the fragment<br>• hex runs<br>• base64/percent/entity layers to depth 2<br>• RFC 2047 encoded words<br>• ICS/vCard unfolding and unescaping<br>• PNG `zTXt`/`iTXt`; EXIF `XP*` UTF-16<br><br>ROT13 and reversed views only when a marker word is present. | §3: 9 encoding, 2 calendar-mail, and 2 media misses | Labelled views in `text_views`, sharing `Budget` | Existing rules; generalizes `agent_encoded_instruction` | Low if gated; hashes fail the printable test | M |
| F11 | **Lexicon breadth:**<br>• the 9 languages that missed (native review plus near-miss pairs)<br>• full TR39 Latin-target confusables, with combining marks stripped in `text-folded`<br>• declarative authority tags (`[SYSTEM OVERRIDE]`, `[SYS-ROLE:`, fake verdict keys)<br>• memory-write and propagation lures<br>• Policy Puppetry keys | §3: 9 language, 3 confusable, and 6 lexical misses (some need semantics); arXiv 2606.08403 | YARA and the fold table | Mostly notes | Moderate for memory and propagation lures (licence text says "included in all copies"); require an AI vocative nearby | S each |
| F12 | **Agent instruction files and skills by path:**<br>• `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, `.cursorrules`, `.cursor/rules/*.mdc`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `SKILL.md`<br>• block any invisible code point<br>• advisory on `` !`cmd` `` lines touching the network or credentials, on `Bash(*)`, and on concealment or script-injection directives | §3: 2 misses; Rules File Backdoor; ClawHavoc | A name-aware global (`yara_gate_ext` exists; a basename global would be new) | Block for invisible code points; otherwise advisory | Low | S–M |
| F13 | **Terminal escapes:** OSC 7/8/52 and conceal or cursor-erase sequences in text going to a terminal-rendering agent | Terminal DiLLMa | YARA, ignoring plain SGR colour | Advisory | Coloured CI logs; exclude SGR | S |

### P2: strategic, needs an owner decision

| ID | Change | Why | Cost and risk |
| --- | --- | --- | --- |
| F14 | **Modality policy:** for a multimodal consumer, images, audio, and video become `incomplete: unread modality` instead of clean (opt-in flag) | Fail-closed consistency: pixels and audio are content the gate cannot read. MMPIBench: OCR text is the working visual carrier; audio completed 49% where delivered | S. Changes exit codes only under the new flag; text-only consumers are unaffected |
| F15 | **Optional semantic tier** (`yara-gate[semantic]`): a local, CPU-only classifier on the extracted text views. It can add a hold and can never clear one. Weights pinned by SHA-256 through `setup` | The plateau in §2 (social engineering about 5.6%) | L. Licence and size (see §5.3); adaptive attacks bypass it; must be measured with the same harness before adoption |
| F16 | **Visible-text rendition** ("prompt CDR"): for documents, hand the agent the text a person would see, scanned again, with hidden runs, invisible code points, comments, and metadata removed by construction | Removes hidden channels instead of detecting them; the mail-security CDR pattern | L. Contract change, because the agent reads derived bytes. Fidelity loss. Parser attack surface |
| F17 | **Recall in CI-adjacent records:** this note's corpus script as a dated record per rule PR, plus real-generator fixtures in the precision corpus (Chrome, LibreOffice, Word, and LaTeX PDFs; Word DOCX) | Hand-built minimal PDFs gave false confidence in `pdf-flate` | S–M. The corpora stay out of the repository (licences, size); record hashes and counts |
| F18 | **MCP manifest pinning:** a digest of tool names, descriptions, and schemas, checked on change (rug pulls) | Rug pulls are invisible to a stateless scan | M. Stateful; may belong in the harness rather than the gate |

### Not recommended for the core

- **OCR, QR, and speech-to-text in-process.** They are heavy, add third-party parser surface, and the deadline does not preempt them. F14 holds those inputs instead. An optional tier is possible later.
- **Treating text addressed to an AI as advisory on its own.** Legitimate projects now address agents: pyparsing's README has "instructions for AI agents", and `AGENTS.md` and `llms.txt` exist for this. In this run, `cand_ai_vocative` hit that README.
- **ROT13 or reversed views over all text,** which doubles the scan cost for little gain. Only add them behind a marker word.
- **Any vendor pack whose rules block on documents that merely discuss attacks.** Vendor matches block by default here. §5.3 names the specific packs:
  - Cisco mcp-scanner and a2a-scanner;
  - Ramparts beyond its prompt-injection file;
  - ai-dfir-toolkit's invisible-character rule as a blocker;
  - Vigil.

  The existing signature-base `ANTHROPIC_MAGIC_STRING_TRIGGER_*` rules already need an override review.

## 7. The candidate-rule experiment (research only)

[`injection-candidates-2026-11-01.yar`](injection-candidates-2026-11-01.yar) has nine generic shapes, measured on raw bytes:
- turn markers
- boundary spoofing
- send-to-address-with-content
- tool directives
- concealed actions
- task overrides
- AI vocatives
- memory writes
- Policy Puppetry keys

**Design discipline:**
- No corpus literals. The attacker address and fixed body were not used.
- One refinement pass after the first run, and only to remove false-positive shapes:
  - `f(to=…)` call syntax hit `zoneinfo/_tzpath.py`;
  - `</data>` hit `http/client.py`;
  - a bare "do not tell the user" hit the precision corpus's documentary support-policy plants.
- The refined file also added the memory-write and authority-banner shapes. It scored the same 48.56% on the send-tool set as the first draft.

**Caveats:**
- The send-to-address shape was written knowing the LLMail objective, so the lift is an upper bound.
- Before any of this ships, measure it on a held-out corpus:
  - LLMail phase 1;
  - BIPIA email tasks;
  - a real-mail ham corpus.
- Then give each shape fire and near-miss pairs, and run `measure_precision.py --fail-over`.

## 8. Rules for building any of this

- **New views:**
  - bounded by `Budget` and the shared deadline;
  - labelled (`pdf-text`, `html-hidden-text`, `decoded-percent`, …);
  - `_RAW_ONLY_RULES` applied to every rewritten derivative, as #145 item 3 asks;
  - member and offset provenance kept, and never turned into physical offsets in SARIF.
- **Dependencies:** prefer the standard library. If `pypdf` or `pdfminer.six` is ever used, run it in a subprocess with resource limits and a hard timeout, because in-process third-party parsers are not preempted.
- **Each rule PR:**
  - fire and near-miss pairs;
  - the precision corpus;
  - the corpus record above, with deltas for recall and benign hits;
  - a statement of which policy changes behaviour. Moving anything to `note` widens what `agent-document` callers read.
- **Severity follows the ladder in §6.** Never derive severity from vendor metadata.

## 9. Next steps, in order

1. **Owner decisions:**
   - #74 (a): the first consumer. I recommend the CyClaw artifact gate.
   - #110 decision 1: the OCR-layer rule. I recommend (i).
   - F14: whether a modality policy is wanted.
   - F15: whether a semantic tier is in scope at all.
2. **Small and certain (S):**
   - F2 Unicode channels;
   - F4 MCP everywhere;
   - #145 items 1 and 2;
   - F5 turn markers with pairs;
   - an override review of signature-base's `ANTHROPIC_MAGIC_STRING_TRIGGER_*` rules (§5.3).

   Re-run both scripts and commit the dated records.
3. **The biggest real-world gap (M):** F1 `pdf-text`, then F9 (#110) on top, with Chromium and LibreOffice fixtures added to the precision corpus. Until then, correct the PDF claim in `docs/rules.md`.
4. **M:** F7 exfiltration, F8 HTML hidden content, and F10 decoder views, in that order.
5. **In parallel:** wire the first consumer and record a week of holds per rule, as #74 asks. Re-rank F6, F11, and F12 by what real traffic holds or misses. F6 changes `agent-ingest` hold rates on ordinary mail, which makes #39 more urgent.

## 10. Other observations

- **The fixture distribution is not the attack distribution.** The shipped agent rules were tuned against hand-written phrases. In a large public corpus of human-written indirect injections, phrases are rare (0.3%), and turn spoofing plus tool directives dominate. A recall record per rule PR would have shown this earlier.
- **Precision has been measured carefully; recall has not been measured at all.** The repository has `measure_precision.py --fail-over` and no recall counterpart. The precision discipline (0/203 benign emails) is worth keeping exactly as it is. Adding the counterpart is cheap.
- **Synthetic documents flatter the PDF view.** Every PDF text fixture in `tests/` and `docs/` shows text as a literal `(…) Tj` string (grep, this session). None uses a ToUnicode CMap or hex glyph codes, so the gap in §4 never showed up.
- **`agent-document` assumes a passive reader.** A quoted marker that is read but not obeyed can still trigger downstream automation (arXiv 2606.08403). It belongs in the read-rule caveats in `docs/integrations.md`.
- **Unreached in this session:**
  - `cgfixit.github.io` (the Pages demo);
  - christian-schneider.net, iamvera.ai, and www.codeant.ai (three of the supplied sources);
  - several primaries cited only through *secondary* summaries above.

  Allowing those hosts in the environment's network settings would let a follow-up read them.

## Reproduce

Run from the repository root.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_injection_gaps.py --json /tmp/probe.json
```

Corpora are downloaded by hand into an empty directory.
- From https://huggingface.co/datasets/microsoft/llmail-inject-challenge (MIT), `data/`:
  - `labelled_unique_submissions_phase2.json`
  - `emails_for_fp_tests.json`
- From https://huggingface.co/datasets/deepset/prompt-injections (Apache-2.0): both parquet splits, exported to JSON Lines.

```sh
uv run python docs/research/measure_injection_corpora.py --llmail DIR/llmail \
    --deepset DIR/deepset.jsonl --benign-dir DIR/benign \
    --candidates docs/research/injection-candidates-2026-11-01.yar --json /tmp/corpora.json
```

The real-generator check in §4 used Playwright's bundled Chromium (`page.pdf`), `soffice --headless --convert-to pdf|docx|odt`, `pandoc`, and ReportLab. The documents are not committed.
