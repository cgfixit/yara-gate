# Detection backlog

Last reviewed: November 10, 2026, on `main` at `163ec4a` plus the
[rule-variant change](../verification/2026-11-10-rule-variant-coverage.md). Python 3.12.3,
YARA-X 1.23.0, 85 local rules, no vendor packs.

This is the one living list of detection work that is not built yet, and of ideas that were
tried or weighed and turned down. Read it before drafting a detection change. The dated
notes listed in the [research index](README.md) are records of what was known on their
date; this page is where their open items now live.

Evidence labels: **verified** means run in this tree with inert fixtures. **Sourced** means
a public write-up, with **read** when the page itself was fetched on November 10 and
**located** when only its existence and summary were confirmed. **Assessment** is judgment.
Nothing here is a production false-positive rate or a recall figure.

## Before you draft a detection change

1. **Find the item here.** If it is under [Considered and not planned](#considered-and-not-planned),
   the reason is recorded; a new proposal needs new evidence against that reason.
2. **Reproduce the miss on the base revision** with `scan_bytes` and a disposable copy of
   `rules/local`, beside a control the gate already catches. A miss without a caught
   control may be a broken rules copy.
3. **Name the benign text nearest to the new pattern** before writing the pattern. The
   near-miss is the specification. Three patterns in the November 10 pass were narrowed
   because their near-miss fired (see the record).
4. **Prefer a spelling of an existing rule over a new rule.** A new rule id changes the
   counts in four documents and needs its own pair, precision row, and policy decision.
5. **Run the whole bar** in [What a rule change has to show](#what-a-rule-change-has-to-show).
6. **Update this page in the same change**: move the item to the record, remove its `OPEN`
   marker in [`probe_detection_gaps.py`](probe_detection_gaps.py), and add any boundary you
   found to the not-planned list.

## What a rule change has to show

| Check | Command | What it establishes |
| --- | --- | --- |
| Compiles, metadata complete | `docs/verification/lint_rules.py` | The pack loads; severities are consistent |
| Fires and has a near-miss | `docs/verification/check_rule_pairs.py` | Each new spelling fires; the nearest benign text does not |
| Library, CLI, encodings | `docs/research/probe_rule_coverage.py --verify` | UTF-8, UTF-16, and zipped copies give the same rule ids and exits |
| Benign corpus unchanged | `docs/verification/measure_precision.py --fail-over` | No new hit on the 328 generated benign files |
| Known gaps and boundaries | `docs/research/probe_detection_gaps.py --verify` | No closed gap reopened, no stale `OPEN` marker |
| Installed files unchanged | `docs/verification/sweep_rule_changes.py` | Zero files change findings between the base rules and yours |
| Worst case stays bounded | `docs/verification/check_worst_case_timing.py` | 4 MiB adversarial inputs finish under the ceiling |
| Recorded outcomes unchanged | `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | The public replay still shows what the scanner does |

The sweep and the precision corpus answer different questions. The corpus holds near-misses
written for the rules; the sweep holds thousands of files nobody wrote with the rules in
mind. A change needs both at zero, or an explanation of each changed file.

## Open candidates

Ordered by expected value for the agent-intake use. B1 to B6 are executable: each is an
`OPEN` case in [`probe_detection_gaps.py`](probe_detection_gaps.py) beside a control and a
benign boundary, so the probe fails when one starts to hold without its marker removed.

### B3. HTML text a browser does not show (reader work, highest value)

- **Gap (verified).** `agent_hidden_html` is one regular expression: a hiding cue, then one
  of seven phrases within 256 bytes. A phrase in a `data-*` attribute, under `opacity:0`, or
  in white text is a note, and a notes-only file passes `agent-document`. Hidden Office and
  PDF text is already read on its own and checked against every `agent_` rule
  (`heuristic_hidden_text`); HTML has no such view.
- **Why it matters (sourced, read).** A March 2026 measurement of injections found on the
  web put visible plain text at 37.8%, `data-*` attribute cloaking at 19.8%, and CSS
  suppression (`display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`,
  `left:-9999px`, white on white) at 16.9%
  ([Unit 42](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)). A crawl study
  found about 70% of 15.3K instances in HTML that is not rendered: comments, headers,
  metadata ([arXiv 2604.27202](https://arxiv.org/abs/2604.27202)).
- **Proposal.** An `html-hidden-text` view from the existing linear HTML reader: text of
  elements hidden by their own inline style or the `hidden` attribute, comment text,
  `data-*` values, `<template>` and hidden `<textarea>` bodies, one piece each. An `agent_`
  rule match in a piece adds `heuristic_hidden_text`, as it does for Office and PDF.
- **False-positive class.** Server-rendered animation frameworks write `style="opacity:0"`
  on text the reader sees a moment later; dark themes write white text; share widgets copy
  an article title into `data-title`. This is why the YARA cues were not widened to
  `opacity:0`, white, or `data-*`. The reader has to treat a stylesheet it cannot resolve
  as unknown, not as hidden, and needs twins for each of the three cases.
- **Acceptance.** The three B3 probes hold under `agent-document`; a fade-in paragraph, a
  dark-theme paragraph, and a share widget that quote the phrase stay notes.

### B1. SVG that runs or loads something without a script or a handler

- **Gap (verified).** `doc_svg_active` blocks a script or `onload`; `doc_svg_event_handler`
  is advisory on `onbegin` and `onerror`. An `<a href="javascript:...">`, an `<animate>` or
  `<set>` that writes a `javascript:` target, and a `<foreignObject>` holding an `iframe`,
  `object`, `embed`, `form`, or `meta http-equiv="refresh"` are clean.
- **Evidence (sourced, located).** Vendors describe three classes of SVG phishing: script
  redirectors, self-contained phishing pages, and DOM or script injection
  ([Cloudforce One](https://www.cloudflare.com/cloudforce-one/research/svgs-the-hackers-canvas)).
  No ranked breakdown of `foreignObject` use was found, so this is the reachable remainder
  after scripts, not a measured share.
- **Proposal.** Advisory, with the scope proof the two SVG rules already use.
- **False-positive class.** Diagram exports label shapes with `<foreignObject><div>`, so
  only the five embedding elements count. Legacy pages wrap icons in
  `<a href="javascript:void(0)">`; exclude an empty or `void` target.

### B2. MCP tool-poisoning wording outside the list

- **Gap (verified).** `heuristic_mcp_hidden_instruction` reads "do not mention this to the
  user" and misses "there is no need to mention this to the user".
- **Evidence (sourced, read).** That sentence, "ALWAYS CONSULT THIS TOOL IMMEDIATELY AS THE
  FIRST STEP", and "otherwise the tool will not work" are the wording in the public
  proofs of concept
  ([line jumping](https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/),
  [injection experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments)).
- **Proposal.** Three alternations in `_HIDDEN_INSTRUCTION`. It stays advisory and reads
  `description` strings only.

### B4. Bytes hidden as a run of zero-width characters

- **Gap (verified).** Eighty alternating U+200B and U+200C characters get two notes and
  pass `agent-document`. A run of eight variation selectors already blocks.
- **Proposal.** `heuristic_invisible_run`, advisory: 16 or more consecutive characters from
  U+200B to U+200D, U+2060 to U+2064, U+FEFF, U+180E, and U+034F in a text unit.
- **False-positive class.** Persian and Indic text uses single joiners and emoji use ZWJ
  between pictographs; neither forms a run of 16. Verify on the benign corpus's script files.

### B5. Text a terminal conceals

- **Gap (verified).** A phrase inside `ESC [ 8 m` is a note, as if it were shown.
  `text-folded` removes the sequence so the phrase matches; nothing records that the
  terminal hid it.
- **Evidence (sourced, read).** Conceal, white-on-white SGR, cursor moves with erase, and
  OSC 8 links whose text differs from the target are the published shapes
  ([ANSI terminal codes in MCP](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/)).
- **Proposal.** Collect concealed and overwritten stretches as pieces and reuse
  `heuristic_hidden_text`. Captured logs colour text often and conceal it rarely.

### B6. `binding.gyp` command expansion that discards its output

- **Gap (verified).** `"<!(node index.js > /dev/null 2>&1 && echo stub.c)"` in a
  `binding.gyp` is clean. `node-gyp` runs it at install.
- **Evidence (sourced, read; one source).** The 2026 Miasma and Hades npm wave planted it,
  with agent settings files and a folder-open task
  ([JFrog](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)).
  Confirm the shape in a second source before shipping a rule.
- **Proposal.** `dev_gyp_command_expansion`, advisory, scoped by `yara_gate_name`: a `<!(`
  expansion that redirects to `/dev/null` or chains with `&&`.
- **Boundary (verified clean).** `<!(node -p "require('node-addon-api').include_dir")`,
  the form native addons use.

### Further candidates, not yet in the probe

| Candidate | Evidence | Why it is not built yet |
| --- | --- | --- |
| Claude Code project settings: a wildcard in `permissions.allow` (`"Bash(*)"`), `apiKeyHelper`, `awsAuthRefresh`, or `statusLine` commands | Verified clean. Sourced, read: these keys are honoured from a project file after trust ([settings](https://code.claude.com/docs/en/settings)) | Teams commit allow lists. Needs the committed-file counts the existing rule used to set its boundary |
| Codex: `mcp_servers.*.command` in a project `.codex/config.toml` with `CODEX_HOME=./.codex` in `.env` | Sourced, read: [CVE-2025-61260](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/) | Two files; the gate judges one file at a time. A shell command in the TOML is the one-file signal |
| Workspace settings that point a tool at a file in the repository: `php.validate.executablePath`, `PATH_TO_GIT` in `.idea/workspace.xml`, a remote `"$schema"` with a query string | Verified clean. Sourced, read: [IDEsaster](https://maccarita.com/posts/idesaster/) lists ten CVEs of this kind | Each key needs its own benign boundary; SchemaStore URLs are ordinary |
| VS Code `chat.tools.terminal.ignoreDefaultAutoApproveRules: true` | Sourced, read (VS Code source) | Alone it removes built-in denials and approves nothing. The approve-all pattern beside it is now matched |
| A "fix it" lure with no verification wording | Verified clean | No single sourced vocabulary; "how to fix" is ordinary help text |
| FileFix decoy: a command, `#`, then 16 or more spaces (including U+00A0 and U+2000 to U+200A) and a fake path | Sourced, read: SigmaHQ FileFix rules key on it | The command before the comment is usually matched already. Useful only as a second signal |
| `conhost --headless`, `pcalua.exe -a`, `pushd \\host@SSL\` with `rundll32` | Sourced, read: Unit 42 timely threat intel, 2026 | The fetch-and-run half is matched when present. Each launcher alone needs a benign count |
| `curl ... \| cmd` and `curl ... \| powershell` | Assessment | No campaign source found. `finger ... \| cmd` is matched |
| Reverse shells through `telnet` with a FIFO, awk `/inet/tcp`, zsh `ztcp`, Node `net` with `child_process` | Verified clean | Rare beside the forms now matched; the Node form is a program, not a one-liner |
| macOS stealer cluster: any two of `dscl . -authonly`, a hidden-answer dialog, `find-generic-password`, `ditto -c -k` with a POST, `killall Terminal`, `xattr -c` | Sourced, read: Unit 42, June 2026 | Each is matched alone as advisory. A two-of-six block needs MDM enrolment scripts as twins; vendor rules exclude MDM agents for these |
| Override phrases in BOM-less UTF-16 with no ASCII | Verified clean for Korean; the same holds for Chinese, Japanese, and Russian | `decoded-utf16` needs a byte order mark or ASCII-heavy text. Decide once for all scripts |
| PDF form XObjects read through their own `/Resources` | [2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md): page content streams now read each font name through their page's fonts; a form keeps the file-wide union, so a form drawn on several pages can still pass the four-reading cap (reported as `heuristic_pdf_text_unmapped`) | The form's dictionary sits before its stream and inherits nothing; needs the same fail-safe fallbacks and a tripwire input |
| Linearized PDFs scan `incomplete` (`pdf xref malformed`), and `pdfxref._startxref_candidates` misses `startxref` after binary stream bytes | Verified on main `2b6eda8`. A linearized file's first-page trailer ends with `startxref 0`, which `xref_file_offsets` follows to the file header, and `_trailer` lexes 64 KiB past the dictionary into stream bytes: four qpdf-linearized Chromium and LibreOffice exports are incomplete where their plain saves are clean or carry their usual note. `_classic` also rejects the blank line MuPDF 1.28 writes before `trailer`: 5 of 6 files saved by PyMuPDF are incomplete. The other way round, the keyword scanner tracks literal strings from the top of the file through stream bodies, so one `(` byte in a stream leaves it inside a string: on 29 of 29 non-linearized real PDFs it finds no `startxref`, and `pdfannotations._reject_xref_inside` checks nothing. Not verified: an annotation hidden behind an xref offset into a stream that scans clean because of it | Changes which real files reach the xref check, so some may newly scan incomplete; needs a before-and-after over real files. `xref_tables(..., anywhere=True)` follows every `startxref` in the bytes for the page map, skips the `0`, and stops the trailer lexer at `startxref` |
| PDF pages that inherit `/Resources` read through their own fonts | [2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md): a page with no `/Resources` of its own keeps the file-wide union, because readers inherit either through `/Parent` or down the `/Kids` they walked | Needs both paths to agree: the page's `/Parent` chain and the one `/Kids` path that lists it must name the same resources |
| A PDF font reference in a spelling only some readers take: `6.0 0 R`, `6 0.0 R`, `+6 0 R`, `6- 0 R`, `6 0R`, a vertical tab between the tokens, or an escaped `/F#6Fnt` key | Verified with readers on main `2b6eda8` ([probe_pdf_reader_agreement.py](probe_pdf_reader_agreement.py), the `gap` rows): pdfminer.six reads all of them, PDFium, MuPDF, and pdf.js most; the union's regexes match only `N G R` and a literal `/Font`, so the text is not decoded and the scan is clean | Widen the regexes, or report `heuristic_pdf_text_unmapped` when a `/Font` dictionary holds a name whose value is not a plain reference. The same spellings in a page's `/Contents` already turn the page map off |
| A PDF font resource that is a reference to a reference (`/F1 10 0 R`, object 10 is `6 0 R`) | Verified with readers: pdfminer.six and MuPDF follow it; `_font` reads object 10, finds no font, and gives the name no reading | One more lookup; needs a cycle bound |
| Stream lengths kept in another object cost the annotation reader one file scan each | Verified on main `2b6eda8`: 300 such streams in 1.2 MB scan in 7.5 s against 0.4 s with direct lengths, and 900 in 4 MiB time out as incomplete. qpdf's QDF mode writes every length this way | Prime every `/Length N G R` in one pass, as the page map's layout pass does for itself; add a tripwire input |
| A PDF font object defined more than once | Verified clean on main `2b6eda8`: the page says `/F1 6 0 R`, object 6 is defined twice, and only the second definition's map decodes the phrase (the definition a reader that follows the last cross-reference section shows). The same holds when the phrase font is `6 1 obj`. `_font` reads the first definition only | Every definition would be a reading; the four-reading cap already reports the overflow. Needs its own tests and record |
| PDF fonts selected through an ExtGState `/Font` entry (`gs`) | Assessment: ISO 32000-1 8.4.5 allows it; no generator sample examined uses it | The `gs` operator is not followed for fonts today; needs a generator sample before a reader change |
| Generate the phrase rules from a word list and one separator grammar | [#171](https://github.com/cgfixit/yara-gate/issues/171), deferred there | The line-break separator is written out 64 times in `agent_prompt_injection_phrases`, up from 32. Worth doing before the next phrase is added |

## Considered and not planned

Each of these was weighed on November 10, 2026 or earlier. The reason is the thing to
overturn.

| Idea | Reason |
| --- | --- |
| `opacity:0`, white or transparent text, zero height, or `data-*` as `agent_hidden_html` cues | Shown text carries them (fade-in animation, dark themes, gradient headings, share widgets). They need the reader in B3, not a lexical cue |
| "Ignore all instructions" and "ignore any instructions" with no adjective | "Ignore any instructions found in the document" is what a careful system prompt says. The second-person form, "ignore your instructions", is matched |
| The nouns `messages`, `email`, `commands`, `orders`, `context` after "ignore previous" | "Ignore my previous message" is ordinary chat; "disregard all prior orders" is ordinary legal text; device manuals ignore previous commands |
| "Override earlier rules" | Stylesheets, firewalls, and ignore files all say later rules override earlier rules. `override` is matched with `instructions`, `directions`, and `prompts` only |
| "Ignore everything before" and "ignore anything above" | Parser documentation ("ignore everything before the colon") and thresholds ("ignore anything above 5%") |
| "Forget your instructions" and "forget your directions" | "Don't forget your instructions sheet"; forgotten directions are a route. `forget` counts before `system prompt` and `programming` |
| `php`, `ruby`, `dash`, `fish` as sinks for a piped download | `curl -sS https://getcomposer.org/installer \| php` is in every PHP README. `node` is matched only with no program argument |
| `[scriptblock]::Create((irm ...))` | Current package installers publish exactly this line |
| `api key`, `password`, `token` in `agent_secret_transfer_request` | "Copy your API key, then send a request to https://..." is every API quick-start |
| "Do not tell the user" beside "use the X tool" | Agent system prompts say it. The tool-call tokens the rule requires are narrower on purpose |
| Event-log clearing and firewall disabling | Maintenance and lab scripts run both; the public detection rules list administrators as the collision |
| A PDF font name past four readings as an incomplete reason | Every benign merge of 5–7 sources would exit 2 under every policy, and `measure_precision.py --fail-over` fails on any benign incomplete ([2026-11-07-pdf-font-readings.md](../verification/2026-11-07-pdf-font-readings.md)). Per-page resolution ([2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md)) removed the case for merges |
| Give a PDF stream its page's fonts when the file is not written plainly: an object that is not one well-formed value, a reference or number in a spelling only some lexers read, an object the cross-reference table does not list in use, an object-stream member whose place holds more or less than one object, a name with a `#` escape in the page or its resources | Each was a real miss against a reader before the map turned it down ([2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md)): PDFium reads a string's bytes as tokens where a key belongs and inherits resources for a free object, poppler cuts a name at an escaped NUL and inherits on a generation mismatch, pdfminer.six reads object streams in written order, pypdf takes `5 0 R#` for a reference. Generator output is plain, so the cost is only on hand-made files, which keep the union |
| Follow a PDF page's inherited `/Resources` through `/Parent` alone | PDFium and pdf.js follow `/Parent`; pypdf, pdfminer.six, and poppler use the node whose `/Kids` they walked, and the two can name different fonts (same record). The candidate above needs both to agree |
| Raise `MAX_FONT_VARIANTS` above four | Each reading emits its own text blocks, so benign merges reach the 20,000-block limit sooner, and every string costs one decode per reading |
| `MpCmdRun -DownloadFile`, `Start-BitsTransfer`, `hh.exe http` | Downloaders with no run step. A download alone is not reported for `curl` either |
| HTML `<img src="https://...{{...}}">` as an exfiltration template | Web and mail templates are written this way. The Markdown forms are matched |
| A literal key appended to `authorized_keys` | An administrator's own key looks the same. A downloaded key is matched |
| ClickOnce manifests, `node -e` in `postinstall`, joining CSV cells or JSON array elements | Recorded earlier; see the [October 30 roadmap](detection-roadmap-2026-10-30.md) and [#171](https://github.com/cgfixit/yara-gate/issues/171) |
| A semantic classifier, OCR, URL reputation, or detonation inside the gate | Outside the scan contract. A classifier belongs after the gate, as advisory evidence with its own provenance |

## Keeping the detector current

**Chat-template tokens.** `agent_role_spoof_action` and `agent_fake_chat_marker` list role
openers by model family. Read the tokenizer's own `chat_template` when a family ships; the
closing token changed shape between Gemma 3 (`<start_of_turn>`) and Gemma 4 (`<|turn>`),
and DeepSeek's bars are U+FF5C, not `|`. Read on November 10: ChatML and Qwen
(`<|im_start|>`), Phi (`<|system|>`), Llama 3 (`<|start_header_id|>`), Llama 4
(`<|header_start|>`), Mistral (`[SYSTEM_PROMPT]`), Gemma 4, harmony
(`<|start|>system<|message|>`), DeepSeek, Granite (`<|start_of_role|>`), and Cohere
(`<|SYSTEM_TOKEN|>`). Llama 2 and Gemma 3 files are gated and were not read.

**Agent settings.** The keys that turn approval off move with each release. Read the
product's settings reference, not a write-up. On November 10 the VS Code source named
`chat.tools.terminal.autoApprove` (with `"/.*/": true` documented as "Allow all commands")
and the deprecated `chat.agent.terminal.autoApprove`; Claude Code ignores
`bypassPermissions` from a project file in current releases.

**Measuring recall and benign holds.** The corpus and the sweep measure collisions, not
recall. Whether to measure against a public corpus is still the owner's decision from
[#171](https://github.com/cgfixit/yara-gate/issues/171): a download is outside the
no-download default. If it is taken, keep the corpus out of git, record hashes and counts,
and report per policy. Candidates read on November 10:

| Corpus | License | What it adds |
| --- | --- | --- |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Card states both Apache-2.0 and CC-BY-4.0 | 662 direct prompts in English and German, with benign rows |
| [NotInject](https://huggingface.co/datasets/leolee99/NotInject) | MIT | 339 benign prompts built around trigger words: a hold-rate test |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | MIT | Indirect injections in mail bodies, with 203 false-positive mails |
| [BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench) | MIT | 14,719 HTML pages with injections and benign distractors: the test for B3 |

A lexical gate's recall on paraphrase corpora is a floor to report, not a target to tune.

**Engine.** YARA-X 1.23.0 (November 5, 2026) is the newest release and the locked version.
Its regular expressions have no lookahead, lookbehind, or backreference, and an alternation
holds at most 255 branches; write an exemption as a second string and an offset test, as
`script_download_execute` does. Unreleased commits change the compiled-rule serialization
version, so the next release starts with a cold cache; the cache key already includes the
engine version. A compiled cache is trusted input
([GHSA-2jx3-ff3v-j7jj](https://github.com/VirusTotal/yara-x/security/advisories/GHSA-2jx3-ff3v-j7jj));
it is written under the user cache directory, which someone who can only supply files
does not control. Gaps of up to 8,192 bytes in the
shipped rules were checked on this engine and match.

**Vendor packs.** `rules.lock` pins YARA Forge core `20261004` and one commit each of
signature-base and Elastic protections-artifacts. `rules update --allow-network` resolves
new pins and compiles before swapping. Compare the skip list and a sweep before and after;
an unattended update is not planned.

**Standards to cite.** OWASP Top 10 for LLM Applications 2025 (LLM01 Prompt Injection) and
the [Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/);
MITRE ATLAS v2026.10: AML.T0051.001 (indirect prompt injection), AML.T0068 (prompt
obfuscation), AML.T0080 (agent context poisoning), AML.T0081 (modify agent configuration),
AML.T0086 (exfiltration via tool invocation), AML.T0110 (agent tool poisoning).

## What the research pass could not confirm

These were reported by secondary sources only, or their pages could not be fetched from
this environment. Do not build on them without reading the primary: the `nslookup`-based
ClickFix stage (February 2026), the Windows Terminal `Win+X` campaign (March 2026), the
Rules File Backdoor write-up, ShadowLeak and the Gemini mail-summary injection, AgentFlayer,
the postmark-mcp backdoor, the ToxicSkills scan, and the approval-bypass flags attributed
to the Nx postinstall script (they are not in the advisory text). The CVE often printed
beside CamoLeak, CVE-2025-59145, is the record for a different npm incident.
