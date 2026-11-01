# Unicode smuggling channels (F2) and spoofed chat turns (F5), 2026-11-01

This implements F2 and F5 from [the coverage research note](../research/injection-coverage-expansion-2026-11-01.md).

**Run environment:**
- Base: `a1b8185` (the research note on `main` `1d13547`).
- Linux, Python 3.12.3, YARA-X 1.22.1 from the lock.
- 83 local rules in 58 files, 0 skipped, no vendor packs.
- Every scan used a disposable copy of `rules/local`. Nothing was executed or fetched.

## What changed

**F2: hidden Unicode channels.** These checks are in `heuristics.py` and run where `heuristic_unicode_tag` runs: the raw or UTF-16 text of a text unit, plus its `html-unescaped` and `json-unescaped` views.
- `heuristic_unicode_variation` (block) fires on either of:
  - two or more variation selectors in a row, unless every one is U+FE0E or U+FE0F;
  - a selector from VS17–VS256 after anything but a CJK ideograph.

  This is emoji smuggling (one selector per payload byte).
- `heuristic_invisible_run` (block) fires on eight or more default-ignorable code points in a row: zero-width characters, directional marks, U+2060–U+2064, Hangul fillers, the CGJ, Mongolian selectors, and soft hyphens. That is enough for one byte of Sneaky Bits or zero-width binary.
- **New `unicode-decoded` view.** It decodes what tag characters, selector runs, and two-symbol invisible runs spell, so the lexical rules can report it. The blocks do not depend on it.
- **Wider `format-controls-removed` and `text-folded` views.** They now drop the other default-ignorable code points as well as category Cf and VS1–VS16, so a phrase split by a Hangul filler reaches the phrase rules.
- **Code-point classes are built from integers at import.** The source stays free of invisible characters, as `check_text_controls.py` requires.

**F5: spoofed chat turns.**
- **New `agent_turn_marker` (note).** It fires on any of these with no order behind it:
  - a chat-template token followed by two words of prose. The tokens are ChatML, Llama 2 `[INST]`/`<<SYS>>`, Llama 3 headers, Gemma, Harmony, Zephyr/Phi, Mistral, and piped `<||user||>`;
  - an upper-case `BEGIN/END USER|ASSISTANT|SYSTEM` banner closed by its delimiter;
  - a closing `</email>`, `</context>`, `</document>`, tool-output, function-results, search-results, or untrusted-content tag that the text never opened.

  It stays clean on template code (a token followed by a quote, brace, or `+`) and on source-code suffixes.
- **`agent_fake_chat_marker` (advisory) widened.** These shapes now escalate to advisory when an order follows within about 200 bytes:
  - the same families;
  - a role tag (`<user>`, `<system>`, …) that opens prose;
  - the closed banners;
  - unopened closers.

  An order is an override or disclosure verb, or `send`/`forward`/`reply`/`respond`/`upload`, or `email`/`post` followed by a space, aimed at an address or URL.
- **No standalone `Human:`/`Assistant:` turns.** Interview transcripts use them.
- **Closer order checked by offset.** For closers, the order is a separate string checked by offset in the condition (see Performance).

## Contract changes

A turn marker followed by prose is now a note. That changes three dated expectations, each updated in this change:
- `check_added_rules.py` `greeting.txt` (`<|im_start|>system` and a greeting) now expects `agent_turn_marker`.
- `probe_rule_coverage.py` `roles_only.txt` is no longer in the clean list.
- `agent-signatures.json`:
  - `agent_role_only.txt` now expects `agent_turn_marker`;
  - the seven `agent_role*` fixtures expect it alongside `agent_role_spoof_action`.

The probe's CLI check now accepts a list of expected rules, as its `rule_set()` already did.

Effect by policy:
- The default policy and `agent-document` still read a lone marker, with the note recorded.
- `agent-ingest` now holds it, as it holds a lone override phrase or a lone zero-width space.

The precision corpus's three planted ChatML greeting examples are now notes (0.91%), by design.

## Verification

| Check | Result |
| --- | --- |
| `ruff check .`, `ruff format --check .`, `mypy --strict src` | pass |
| `lint_rules.py` | 83 rules compiled and linted |
| `check_rule_pairs.py` | 112 rules, each with a fire and a near-miss |
| `check_added_rules.py` | 96 named cases plus 3 vendor-override cases |
| `check_text_controls.py`, `check_scan_only.py`, `check_intake.py`, `check_rules_lock.py` | pass |
| `measure_precision.py --fail-over` | pass |
| `probe_rule_coverage.py --verify` | passed |
| `yara-gate selftest` | `SELFTEST PASS` |

**Pairs added in `check_rule_pairs.py`:**

| Rule | Fires on | Stays clean on (near-miss) |
| --- | --- | --- |
| `heuristic_unicode_variation` | Selector-smuggled "run it" | A doubled heart U+FE0F and an IVS |
| `heuristic_invisible_run` | Sneaky Bits "run it" | A ZWJ family and seven zero-width spaces |
| `agent_turn_marker` | Gemma turn with prose | Jinja template code |
| `agent_turn_marker` | `<-- BEGIN USER -->` | `[END USER LICENSE AGREEMENT]` |
| `agent_turn_marker` | Unopened `</context>` | Opened `<context>…</context>` |
| `agent_fake_chat_marker` | Gemma turn plus "Ignore" | Gemma turn plus a poem request |
| `agent_fake_chat_marker` | Unopened `</email>` plus forward-to-address | The same with `<email>` opened |
| `agent_fake_chat_marker` | `<user>` opening an order | An XML user record |

`check_added_rules.py` adds these named files:
- Expected to fire: a selector payload, a Sneaky Bits payload, an LLMail-shaped piped turn, and a bare `<|user|>` turn.
- Expected to have no findings: a `tokenizer_config.json` chat template, an Ollama `Modelfile`, an EULA heading, an interview transcript, Japanese IVS text, Persian ZWNJ text, and keycap/heart emoji.

The precision corpus gains nine benign look-alikes (329 files):
- 78 of 83 rules hit nothing.
- The four documented Windows collisions are 0.30% each.
- No heuristic id hit.

## Research scripts, before and after

**Gap probe** (`probe_injection_gaps.py`; record `injection-gap-probe-2026-11-01-f2-f5.json`, against `injection-gap-probe-2026-11-01.json`). Eight of 104 cases moved; nothing regressed.

| Case | Before | After |
| --- | --- | --- |
| Variation-selector smuggling | clean | block (`heuristic_unicode_variation`; phrase note on `unicode-decoded`) |
| Sneaky Bits | note | block (`heuristic_invisible_run`; phrase note on `unicode-decoded`) |
| Zero-width binary | note | block (`heuristic_invisible_run`; phrase note on `unicode-decoded`) |
| Llama 2 `[INST]`/`<<SYS>>`, Gemma, Harmony, Zephyr turns | clean | advisory (`agent_fake_chat_marker`) and note (`agent_turn_marker`) |
| `</function_results>` then a `Human:` order | clean | advisory and note |

Still clean in the unicode group: dotless `ı`, Armenian `օ`, and a combining overlay. Those are F11.

**Corpora** (`measure_injection_corpora.py`; record `injection-corpora-2026-11-01-f2-f5.json`, against `injection-corpora-2026-11-01.json`). The inputs were the same as in the research note, with the same SHA-256 values.

| Set | n | `agent-ingest` holds | `agent-document` holds |
| --- | ---: | --- | --- |
| LLMail: send tool actually triggered | 3,165 | 6.41% → **23.95%** | 2.59% → **14.25%** |
| LLMail: judged direct instructions | 13,169 | 5.35% → 20.70% | 0.61% → 14.69% |
| LLMail: judged obfuscation | 4,370 | 5.72% → 17.07% | 1.56% → 12.38% |
| LLMail: judged social engineering | 13,660 | 1.52% → 5.71% | 1.47% → 3.64% |
| deepset injections | 263 | 3.04% → 3.04% | 0.00% → 0.00% |
| LLMail FP-test emails (benign) | 203 | 0.00% → 0.00% | 0.00% → 0.00% |
| deepset benign | 399 | 0.50% → 0.50% | 0.00% → 0.00% |
| CPython stdlib (benign) | 573 | 0.00% → 0.00% | 0.00% → 0.00% |
| Package READMEs and METADATA (benign) | 68 | 4.41% → 4.41% | 4.41% → 4.41% |
| The 320-file precision corpus used in the note | 320 | 1.25% → 2.19% (3 planted ChatML notes) | 1.25% → 1.25% |

**Send-tool set, which rules fire:** `agent_fake_chat_marker` fires on 386 emails, up from 17, and `agent_turn_marker` on 287.

**F2 fired on no LLMail email.** Those attackers used tag characters (64 blocks, unchanged), not selectors or long invisible runs. F2's evidence is the probe and the published techniques, not this corpus.

**deepset is unchanged.** Its direct prompts carry no turn markers.

## Performance

The 3,165 send-tool emails took 4.3–5.2 ms each, against 3.7–4.7 ms with the base rules. That is four alternating runs per side across two sessions in a noisy container, and a paired cost of about 0.3–0.9 ms per email. It is within the README's 1–7 ms per message. 1 MB of Markdown is unchanged (0.74 s both).

The first version of the closer check put a 200-byte regex gap after every closer. That cost 0.4 s by itself on a 1 MB XML export dense with `</email>` and `</context>`, and took the file from 0.62 s to 1.48 s.

The shipped version matches the closer as a literal and checks a separate order string with `$order in (@closer[i]..@closer[i] + 260)`. That brings the file to 0.68 s and avoids a nested loop over matches. The full corpus run took 147 s, against 161 s for the baseline run in the research note.

## Limits

- The `unicode-decoded` view decodes the HTML-unescaped text. A tag or selector payload written only as JSON escapes is still blocked, by the heuristics on `json-unescaped`, but is not decoded into the view.
- A run of four-symbol invisible encoding is blocked but not decoded.
- A fingerprinting watermark made of zero-width runs now blocks. That is a hidden data channel by construction; release it through review (#39).
- Role tags such as `<user>` count only when they open prose and an order follows. An XML record that happens to continue with prose and a send-to-address line would match.
- Chat-template examples in model cards and prompt-format docs are notes: `agent-ingest` holds them, and `agent-document` reads them.
- The LLMail numbers cover one attack objective (make the agent email an address). They are not a production detection rate.
