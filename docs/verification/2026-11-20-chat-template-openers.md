# Turn openers of Kimi, MiniMax, Granite, and Inkling

Date: 2026-11-20. Base: `main` at `a32b63f`. Engine: YARA-X 1.23.0, Python 3.12.3, Linux
container with 4 cores. Rules: the shipped `rules/local` (89 rules), no vendor packs.

## What changed

`agent_role_spoof_action` and `agent_fake_chat_marker` list the system and assistant turn
openers of chat templates by model family. The [detection backlog](../research/detection-backlog.md#keeping-the-detector-current)
says to read a tokenizer's own template when a family ships. Four families whose templates are
on the Hub were not listed. On `a32b63f` each opener below scanned clean under every policy
with an order after it, beside ChatML, Granite system, Gemma, and `</tool_result>` controls
that were advisory.

| Template | Opener | Rule | Base | Now |
| --- | --- | --- | --- | --- |
| Kimi K2 | `<\|im_system\|>system<\|im_middle\|>` (or `developer`) | `agent_role_spoof_action`, `$header` | clean | advisory |
| Kimi K2 | `<\|im_assistant\|>`, the role or a message name of up to 32 characters, `<\|im_middle\|>` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| MiniMax M2 | `]~b]system` | `agent_role_spoof_action`, `$header` | clean | advisory |
| MiniMax M2 | `]~b]ai` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| Granite 4.0 | `<\|start_of_role\|>assistant<\|end_of_role\|>` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| Inkling 2 | `<\|message_system\|><\|content_text\|>` | `agent_role_spoof_action`, `$header` | clean | advisory |
| Inkling 2 | `<\|message_model\|>` then `<\|content_text\|>` or `<\|content_thinking\|>` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| Qwen 3.8, GLM-4.6, Granite 4.0 | `</tool_response>` with no `<tool_response` anywhere in the unit, before or after it, then an instruction verb within 80 bytes | `agent_fake_chat_marker`, `$close_response` and `$open_response` | clean | advisory |

No rule id, severity, or policy changed. Each opener still needs the rule's own verb after it
(`reveal`, `ignore`, `override`, `execute`, or `credentials` within 256 bytes for the system
openers; `ignore`, `reveal`, `execute`, `run_command`, or `do not tell the user` within 200
bytes for the assistant openers). An advisory is exit 0 under `default` and a hold, exit 1,
under `agent-document` and `agent-ingest`; the CLI gave those exits for a Kimi system fixture
with a disposable copy of the rules, and left the file in place.

## Sources

Sourced, read: each model's `chat_template.jinja`, fetched from the Hub on November 20, 2026.
The first 16 hex digits of each file's SHA-256 are given so a later reader can tell whether
the template moved.

| Model | Template SHA-256 | What it writes |
| --- | --- | --- |
| [moonshotai/Kimi-K2-Instruct-0905](https://huggingface.co/moonshotai/Kimi-K2-Instruct-0905) | `00938c355ca7195f` | `<\|im_system\|>`, `<\|im_user\|>`, or `<\|im_assistant\|>`, then the role or the message's name, then `<\|im_middle\|>`. A tool list is `<\|im_system\|>tool_declare<\|im_middle\|>` |
| [MiniMaxAI/MiniMax-M2](https://huggingface.co/MiniMaxAI/MiniMax-M2) | `86cd6e574dec52bf` | `]~!b[` then `]~b]system`, `]~b]user`, `]~b]ai`, or `]~b]tool`, each closed by `[e~[`. Tool output is `<response>` |
| [ibm-granite/granite-4.0-h-small](https://huggingface.co/ibm-granite/granite-4.0-h-small) | `9524df67b77a7b25` | `<\|start_of_role\|>` role `<\|end_of_role\|>`. Tool output is `<tool_response>` in a user turn |
| [thinkingmachines/Inkling-2-Small](https://huggingface.co/thinkingmachines/Inkling-2-Small) | `53a9035f32559457` | `<\|message_system\|>`, `<\|message_user\|>`, `<\|message_model\|>`, or `<\|message_tool\|>`, then a content token such as `<\|content_text\|>`. A tool list is `<\|message_system\|>tool_declare<\|content_xml\|>` |
| [Qwen/Qwen3.8-27B](https://huggingface.co/Qwen/Qwen3.8-27B) | `af16f654968d47d0` | ChatML, already read. Tool output is `<tool_response>` |
| [zai-org/GLM-4.6](https://huggingface.co/zai-org/GLM-4.6) | `44f815868bf02fa4` | `<\|system\|>` and `<\|assistant\|>`, already read. Tool output is `<\|observation\|>` then `<tool_response>` |

Assessment: that an injected opener of one of these families is more persuasive to a model of
that family than plain text. No published attack that uses these four templates was read; the
rules already rest on the same assessment for the families they list.

### Read and not built

| Marker | Why it is left out |
| --- | --- |
| GLM-4.6 `<\|observation\|>`, MiniMax M2 `]~b]tool` and `<response>`, LFM2 `<\|tool_response_start\|>` and `<\|tool_response_end\|>` ([LiquidAI/LFM2-1.2B](https://huggingface.co/LiquidAI/LFM2-1.2B), `5504d163d879bfb6`) | They open or close tool output, which claims no system or assistant authority. `</response>` closes ordinary XML |
| Maxwell V1 `<\|maxwell_start\|>system` ([maxwell-model/Maxwell-V1-Flash](https://huggingface.co/maxwell-model/Maxwell-V1-Flash), `7f2308665efc243d`) | ChatML under another token name from one publisher |
| Hy4 ([tencent/Hy4-flash](https://huggingface.co/tencent/Hy4-flash), `11b12531403da572`) | The template takes its role tokens from variables, so the template text does not show them. Its tokenizer files were not read |

Each of the first two rows was scanned with an order after it and is clean with the changed
rules, as on the base. Not fetched: the Cohere Command A template (the repository is gated) and
the DeepSeek V3.1 and Phi-4-mini repositories, which hold no `chat_template.jinja`.

## Boundaries

The near-miss was written before each pattern and is kept in
[`check_rule_pairs.py`](check_rule_pairs.py). Every boundary below is about the marker and
what follows it within the rule's window. None of them is a claim about a whole rendered
prompt; the next section says what a rendered prompt does.

- **The tool-list marker is not an opener.** Kimi and Inkling write `tool_declare` under the
  same token as a system message, and a tool list names `execute` and `reveal` in its
  descriptions. Only `system` or `developer` before `<|im_middle|>`, and `<|content_text|>`
  after `<|message_system|>`, open a system turn. A tool list alone stays clean.
- **A user or tool marker is not an opener.** `<|im_user|>`, `]~b]user`, `]~b]tool`,
  `<|start_of_role|>user`, and `<|message_user|>` followed by "please ignore the typo" stay
  clean when no system or assistant opener stands within the window before them, and so does
  an Inkling tool call (`<|message_model|>run<|content_invoke_tool_json|>`).
- **An opener with no verb after it carries no order.** Each template's default system prompt
  and a greeting from the assistant stay clean.
- **Each tool wrapper is paired with its own open tag.** A file that opens `<tool_response>`
  and then carries a stray `</tool_result>` with an order is advisory on the base and still is.
  One open string for both closes would have cleared it. The open tag counts anywhere in the
  unit, before or after the close, and self-closed (`<tool_response/>`).

## What a rendered prompt or transcript does

The rules read a window after an opener, 256 bytes for a system opener and 200 for an
assistant opener, and do not know where a turn ends. That is how they read every family they
list, and the base behaves the same way. An independent review of this change reproduced it
for the new families, each beside a family the base already reads:

| Benign text | New family | Base, same shape in a listed family |
| --- | --- | --- |
| A system turn, then a user turn within the window that says "execute" or "ignore" | Inkling, MiniMax, Kimi: clean on the base, advisory now | ChatML: advisory on the base |
| A system turn that holds a tool list naming `execute` within the window | MiniMax, which renders its tools inside the system turn: clean on the base, advisory now | ChatML: advisory on the base |
| An assistant greeting, then a user or tool turn within the window that says "ignore" | Kimi, MiniMax, Granite, Inkling: clean on the base, advisory now | Phi: advisory on the base |
| A tool named `run_command` called in the assistant turn | The four new families: clean on the base, advisory now | ChatML: advisory on the base |
| Source code that holds the close tag as a constant, with "ignore" in the next comment | `</tool_response>`: clean on the base, advisory now | `</tool_result>`: advisory on the base |

Inkling writes `<|message_system|><|content_text|>Thinking effort level: ...` at the head of
every prompt, so a logged Inkling prompt carries the system opener about 70 bytes before the
user's first words. A captured prompt or a chat log in one of these four templates is
therefore advisory when one of the rule's verbs falls in a window, as a ChatML log is today.
The rules are written for a document or message that imitates a turn; a consumer that scans
its own rendered prompts will see these findings.

## Spellings that still pass

Verified clean with the changed rules, each with an order after it:

- `<|im_system|>tool_declare<|im_middle|>` and `<|message_system|>tool_declare<|content_xml|>`
  followed by an order instead of a tool list. The exemption that keeps a tool list clean also
  passes this. A name other than `system` or `developer` after `<|im_system|>` passes too.
- White space or a line break between the tokens of an opener (`<|im_system|>system
  <|im_middle|>`, `]~b] system`). The Llama 3 header with a space is clean on the base in the
  same way; only the ChatML strings allow blanks after their first token.
- `]~b]assistant` and `]~b]developer`, which the MiniMax template does not write.
- `</tool_response >` with a space, and a close whose `<tool_response>` open is added anywhere
  after it.
- An Inkling `<|message_model|>` turn opened by a name (`<|message_model|>planner<|content_text|>`).

## Review and what it changed

A fresh-context reviewer was given the diff and the fixtures and asked to make the change
wrong. Each finding was reproduced before it was acted on.

| Finding | Outcome |
| --- | --- |
| Kimi writes a message's name between its tokens; `<\|im_assistant\|>Kimi<\|im_middle\|>` with an order was clean | Fixed: the assistant opener takes a name of up to 32 characters |
| Inkling opens a thinking turn with `<\|content_thinking\|>`; an order there was clean | Fixed: the assistant opener takes either content token |
| `<tool_response/>` did not count as an open tag, so a close after it was a stray one | Fixed: the open string takes `/` |
| The Inkling pair fixtures were not shapes the template writes | Fixed: the tool list is a bare sorted JSON array and the tool call is `{"name":...,"args":{...}}` |
| The record said a user turn and a tool list "stay clean" without saying where | Rewritten above; the rendered-prompt table is the result |
| The benign shapes in the table above | Kept as the rule's existing reach, and stated |
| The spellings in the list above | Left open and stated |
| The timing findings | In [Timing](#timing) |

## Timing

Each row is one `scan_bytes` call on 4 MiB, base rules against changed rules in the same run,
on the container named at the top. Rows without a verb are the median of three on `308ee16`,
the second rule commit. The four floods were run once each with a 30 s timeout on `49e6d1d`,
the first; the system openers they use did not change after it.

| Input, repeated to 4 MiB | Base | Changed |
| --- | --- | --- |
| Ordinary notes | 0.47 s clean | 0.49 s clean |
| An opener and a greeting with no verb, for each of the seven new openers | 0.46 to 0.79 s clean | 0.59 to 1.37 s clean |
| `<\|im_assistant\|>` and 32 letters with no `<\|im_middle\|>` | 0.66 s clean | 0.75 s clean |
| The same for Phi's `<\|assistant\|>`, which the base reads | 1.13 s clean | 1.13 s clean |
| `]~b]ai` and a line feed, nothing else | 0.58 s clean | 4.71 s clean |
| Phi's `<\|assistant\|>`, nothing else (on `49e6d1d`) | 1.69 s clean | 1.73 s clean |
| `</tool_response>` and a verb, with one open tag in the unit | 1.27 s clean | 1.67 s clean |
| `]~b]system ignore ` | 2.02 s clean | incomplete (`timeout`) at 30 s |
| `<\|im_system\|>system<\|im_middle\|> ignore ` | 1.38 s clean | advisory in 29.2 s |
| Llama 2 `<<SYS>> ignore `, which the base reads | incomplete (`timeout`) at 30 s | incomplete (`timeout`) at 30 s |
| Phi `<\|system\|>x ignore `, which the base reads | incomplete (`timeout`) at 30 s | incomplete (`timeout`) at 30 s |

Two things follow.

- **A short opener costs more.** `]~b]ai` is seven bytes with its line feed, so 4 MiB holds
  about 600,000 of them, and each one is followed by a 200-byte window. It is about 2.7 times the
  slowest listed opener on the same kind of input and under the 10 s ceiling of
  `check_worst_case_timing.py`.
- **A flood of system openers that each carry a verb does not finish, on the base too.** The
  last four rows are one class: the two the base reads already reach the 30 s deadline on
  `a32b63f`. The new openers join it, so a file of that shape that the base passed as clean in
  2 s is now incomplete or advisory. Incomplete is exit 2 and keeps an inbox copy quarantined.
  The cause is in how `$header` is read, not in the new spellings, and it is not fixed here; it
  is a row in the [detection backlog](../research/detection-backlog.md#further-candidates-not-yet-in-the-probe).

`check_worst_case_timing.py` passed its 96 inputs of 4 MiB on `49e6d1d` and again on `308ee16`;
the slowest was 6.1 s.
No input was added to it: none of its cases is a flood of role openers, and its budget is the
one the [November 14 record](2026-11-14-macos-timing-flake.md) calls thin.

## Checks

Run on `308ee16`, which holds both rule commits; the later commits change documents only.
Direct runs in this container. The broad pytest suite and `selftest` were left to hosted CI.

| Check | Result |
| --- | --- |
| Reproduction on `a32b63f` | 11 spellings with no finding, so clean under every policy, beside 4 controls that were advisory |
| Hits and near-misses, `scan_bytes` | 12 hits and 17 near-misses as expected; the same texts as UTF-16, zipped, and CRLF Markdown: 33 hits, 51 clean |
| The 29 claims of the two sections above (benign shapes, passing spellings) | each as stated, on the base and with the change |
| CLI, disposable rules copy | Kimi system fixture: exit 0 advisory under `default`, exit 1 under `agent-document`; benign twin exit 0; both files left in place |
| `lint_rules.py` | 89 rules compiled and linted |
| `check_rule_pairs.py` | passed; 9 pairs added |
| `measure_precision.py --fail-over` | 328 files, 0 incomplete, 0 hits on either rule |
| `probe_rule_coverage.py --verify`, `probe_detection_gaps.py --verify`, `check_added_rules.py`, `check_scan_only.py` | exit 0 |
| `probe_match_cap.py` | 2,685 flooded texts over 84 rules, 0 with a cap blind spot. Neither rule reads where a match lies; `not $open_response` reads presence only |
| `sweep_rule_changes.py --jobs 3 --base-ref origin/main` over `/usr/share/doc`, `/usr/lib/python3.12`, `/usr/include`, `/usr/share/man`, the locked site-packages, and `docs` | 0 of 6,042 files changed findings (298 hits before and after). The first run, on `49e6d1d`, changed one file: this change's own draft of `docs/rules.md`, which wrote three new openers within 256 bytes of the word "override". The sentence now names the families without their tokens. No installed file holds any of the new tokens, so this sweep shows only that nothing else moved |
| 70 public files that do hold such tokens: chat templates, tool-parser source, and chat-templating documents from llama.cpp, vLLM, Transformers, Qwen-Agent, Hermes-Function-Calling, Ollama, and nine model repositories; 22 hold a new token | 0 changed findings between base and changed rules; 6 have findings on both |
| `check_worst_case_timing.py` | PASS, 96 inputs of 4 MiB, slowest 6.1 s |
| `record_pages_demo.py --baseline web-demo/recordings.json` | outcomes match the reviewed baseline, 91 scenarios under 3 policies |
| `ruff check`, `ruff format --check`, `check_text_controls.py`, `check_doc_links.py` | pass |

## Not established

- A production false-positive rate. The 70-file corpus was fetched for this change and is not
  kept in the repository; the files that fire on both rule sets were not examined one by one.
- That a model of one of these families obeys an imitated opener more readily than plain
  text. No tokenizer or model was run.
- Hy4's role tokens, the gated Cohere template, and any family not named here.
