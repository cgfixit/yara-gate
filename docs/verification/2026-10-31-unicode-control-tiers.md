# Unicode controls: a lone control is a note, binary units are skipped (#109)

Base: `main` `1c3de50`. YARA-X `1.22.1`, Python 3.12, Linux container. Shipped local rules copied into disposable rules roots. Synthetic inputs and two local consumer checkouts. Nothing was executed and nothing was downloaded.

## Root cause

`agent_invisible_unicode`, `agent_bidi_override`, and `agent_bidi_formatting` were byte patterns at block severity, and the scanner ran them on every unit's raw bytes. One stray character blocked a file under every policy, and a binary unit blocked when its compressed bytes happened to contain `E2 80 AE` or `E2 80 8B`. `heuristic_invisible_joiner` also blocked on one hit. Reproduced on `1c3de50` before the change:

| Input | Before, all policies |
| --- | --- |
| `Quarterly` + ZWSP + `notes for the team.` | block `agent_invisible_unicode` |
| `Name: ` + RLO + `abc` | block `agent_bidi_override` |
| 3 MB of `os.urandom` | block `agent_bidi_formatting`, `agent_bidi_override`, `agent_invisible_unicode` |

## What changed

| Piece | Change |
| --- | --- |
| `yara_gate_text` global | Set per buffer to whether it sniffs as text. The three Unicode rules require it. |
| Three Unicode rules | Severity `note`. Unicode tag characters leave `agent_invisible_unicode`. |
| `heuristic_invisible_joiner` | Severity `note`. |
| `agent_bidi_source` (new, block) | Any bidi override, embedding, or isolate in a file with a programming or shell suffix. |
| `heuristic_unicode_tag` (new, block) | A tag character outside an emoji subdivision-flag sequence, in the raw text, `html-unescaped`, or `json-unescaped`. |
| `heuristic_unicode_control_conjunction` (new, advisory) | A control note plus any other note in the same member. |

Two choices go beyond the issue text.

- **Tags keep blocking.** The issue demotes `agent_invisible_unicode` as a whole. Tag characters were part of it and are the ASCII-smuggling carrier. Unicode reserves them for emoji tag sequences, and no text view decodes them into the letters they spell. A lone tag as a note would therefore have dropped hidden-instruction detection to exit 0 under the default policy. They moved to `heuristic_unicode_tag` with the flag exemption instead, so the England, Scotland, and Wales flags, which blocked before, are now clean.
- **"Inside a comment or string literal" is approximated by the file suffix.** `agent_bidi_source` fires anywhere in a source file. Outside comments and literals these characters are a syntax error in the languages listed, and rustc rejects them inside literals and comments by default.

## Direct scans after the change

`scan_bytes` under each policy, in the order default, agent-ingest, agent-document:

| Input | Verdicts | Findings |
| --- | --- | --- |
| ZWSP in prose | advisory / block / advisory | `agent_invisible_unicode` note |
| RLO in a name | advisory / block / advisory | `agent_bidi_override` note |
| Isolates around an Arabic name | advisory / block / advisory | `agent_bidi_formatting` note |
| RLM after a Hebrew name | advisory / block / advisory | `agent_invisible_unicode` note |
| 3 MB random bytes; a zip with a 1 MB random member | clean / clean / clean | none |
| `Ig` + ZWSP + `nore previous instructions.` | advisory / block / block | control note, phrase note in `format-controls-removed`, conjunction advisory |
| Trojan Source line as `.py` | block / block / block | `agent_bidi_source` |
| The same line as `.txt` | advisory / block / advisory | notes only |
| `invoice_` + RLO + `fdp.exe` | block / block / block | `heuristic_filename_control` (unchanged) |
| England flag | clean / clean / clean | none |
| Tag characters spelling a sentence: raw, as HTML entities such as `&#xE0069;`, or as JSON surrogate-pair escapes | block / block / block | `heuristic_unicode_tag` |
| ZWJ emoji, Persian ZWNJ | clean / clean / clean | none |
| ZWSP in UTF-16 text | advisory / block / advisory | note in `decoded-utf16` |

## Checks

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src
uv run python docs/verification/lint_rules.py            # 80 rules
uv run python docs/verification/check_rule_pairs.py      # 104 rules
uv run python docs/verification/check_added_rules.py     # 66 cases
uv run python docs/verification/measure_precision.py --fail-over   # 310 files, exit 0
uv run python docs/verification/check_text_controls.py
uv run python docs/verification/check_scan_only.py
uv run python docs/verification/check_intake.py
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run yara-gate selftest
```

All passed. The probe's expectations moved for three inputs: `bidi_isolate.txt`, `override_utf16.txt`, and `split_instruction.txt` go from block to advisory under the default policy. It gained five fixtures: `trojan_source.py` (block), `trojan_prose.txt` (advisory), `flag_emoji.txt` (clean), `tag_smuggle.txt` (block), and a binary `random.bin` carrying the control bytes (clean). The CLI block case uses the tag fixture in place of a lone RLO. The selftest's block case is now hidden tag characters, and a lone ZWSP plus RLO is checked as advisory.

## Consumer trees

Every file of 1 MB or less in CyClaw `a5b5212` and cg-agent-harness `ff5df3a`, 1,469 files, scanned once each on `main` and on this branch. The policy outcomes come from the same result.

| Policy | main: clean / advisory / block | branch |
| --- | --- | --- |
| default | 1338 / 109 / 22 | 1347 / 116 / 6 |
| agent-ingest | 1338 / 0 / 131 | 1347 / 0 / 122 |
| agent-document | 1338 / 71 / 60 | 1347 / 75 / 47 |

Sixteen files changed outcome, and none became stricter under any policy.

- Nine binary files went from block to clean: eight PNG and JPEG screenshots and a learning-guide PDF. Each had matched a Unicode rule by chance.
- Four text files with only a stray control are notes now. `agent-ingest` still holds them and `agent-document` releases them: a Unicode confusables table, a memory-policy test, a reminder file, and a JSON baseline.
- Three CyClaw files are still held under `agent-document` through the conjunction: the injection red-team probes, the sanitizer tests, and a personality test. Each one carries injection phrases and live controls.

These are two repositories of code and documentation, not a production false-positive rate.

## Limits

- The text decision reads the first 4 KiB of each unit, as the derived views already do. Text after a binary prefix is not checked for controls.
- A raw PDF is not text, so a control in an uncompressed PDF string is no longer reported from the raw bytes. A `pdf-flate` view that sniffs as text is still checked.
- A zero-width character inside a source-code identifier is a note, not a block. Only bidi controls are Trojan Source here.
- The conjunction is per member, not per line. A ZWSP in one paragraph and a quoted phrase in another make an advisory.
