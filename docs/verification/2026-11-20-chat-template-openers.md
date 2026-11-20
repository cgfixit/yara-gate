# Turn openers of Kimi, MiniMax, Granite, and Inkling

Date: 2026-11-20. Base: `main` at `a32b63f`. Engine: YARA-X 1.23.0, Python 3.12.3, Linux
container with 4 cores. Rules: the shipped `rules/local` (89 rules), no vendor packs.

## What changed

`agent_role_spoof_action` and `agent_fake_chat_marker` list the system and assistant turn
openers of chat templates by model family. The [detection backlog](../research/detection-backlog.md#keeping-the-detector-current)
says to read a tokenizer's own template when a family ships. Four families whose templates are
on the Hub were not listed. On `a32b63f` each opener below scanned clean under every policy
with an order after it, beside a ChatML, Granite system, and Gemma control that were advisory.

| Template | Opener | Rule | Base | Now |
| --- | --- | --- | --- | --- |
| Kimi K2 | `<\|im_system\|>system<\|im_middle\|>` (or `developer`) | `agent_role_spoof_action`, `$header` | clean | advisory |
| Kimi K2 | `<\|im_assistant\|>assistant<\|im_middle\|>` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| MiniMax M2 | `]~b]system` | `agent_role_spoof_action`, `$header` | clean | advisory |
| MiniMax M2 | `]~b]ai` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| Granite 4.0 | `<\|start_of_role\|>assistant<\|end_of_role\|>` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| Inkling 2 | `<\|message_system\|><\|content_text\|>` | `agent_role_spoof_action`, `$header` | clean | advisory |
| Inkling 2 | `<\|message_model\|><\|content_text\|>` | `agent_fake_chat_marker`, `$turn` | clean | advisory |
| Qwen 3.8, GLM-4.6, Granite 4.0 | `</tool_response>` with no `<tool_response` in the unit, then an instruction verb within 80 bytes | `agent_fake_chat_marker`, `$close_response` and `$open_response` | clean | advisory |

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
[`check_rule_pairs.py`](check_rule_pairs.py).

- **A tool list is not a system turn.** Kimi and Inkling write `tool_declare` under the same
  token as a system message, and a tool list names `execute` and `reveal` in its descriptions.
  Only `system` or `developer` before `<|im_middle|>`, and `<|content_text|>` after
  `<|message_system|>`, are read. Both tool lists stay clean.
- **A user or tool turn is not a role claim.** `<|im_user|>`, `]~b]user`, `]~b]tool`,
  `<|start_of_role|>user`, and `<|message_user|>` followed by "please ignore the typo" stay
  clean, and so does an Inkling tool call (`<|message_model|>run<|content_invoke_tool_json|>`).
- **A rendered greeting carries no order.** Each template's default system prompt and a
  greeting from the assistant stay clean.
- **Each tool wrapper is paired with its own open tag.** A file that opens `<tool_response>`
  and then carries a stray `</tool_result>` with an order is advisory on the base and still is.
  One open string for both closes would have cleared it.
- **Unchanged from the base:** a rendered transcript whose system prompt is followed within 256
  bytes by a user turn that says "ignore" is advisory for every family the rule lists, old and
  new. The first draft of the MiniMax near-miss was such a transcript and fired; it was
  rewritten, and the boundary is not new.
