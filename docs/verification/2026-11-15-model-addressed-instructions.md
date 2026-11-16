# Model-addressed instructions

Base `334157681b8c3e9d50a35e6271e77dfcaa246a34`. macOS arm64, Python 3.12.12,
YARA-X 1.23.0, and bundled rules only. The candidate compiled 89 rules without skips.
Rule file SHA-256 `c8c9c4618bb7b2a4d1d5d802376d3cd435799b7a97f1856acdcf6f6fef9039ee`.

## Behavior

The five plain-text examples in [#254](https://github.com/cgfixit/yara-gate/issues/254)
were clean on the base under `agent-ingest`. The existing override control blocked.
The candidate reports `agent_model_addressed_instruction` for all five examples.
The finding is advisory under every policy. The default verdict is advisory with
exit 0. Both agent policies hold it with exit 1.

A reader address and directive must occur in the same clause. The rule also
covers a small set of promotional claims introduced by a note to a model,
a named tool call addressed to the assistant, and a concealed addition to an answer.
A confidentiality request on its own, crawler guidance, citation guidance,
and the same instruction quoted inside explanatory prose scanned clean. A separate
directive in a document that also quotes the example still matched. A standalone
instruction in a prompt example can match. The lexical rule covers the defined
English constructions and cannot infer intent from the document.

A contiguous HTML paragraph matched in the raw view. The same instruction split
across an inline tag matched through `html-text`. With `display:none`, the
scanner also reported `heuristic_hidden_text` from `html-hidden-text`. Separate
paragraphs stayed separate. The checks also cover UTF-16 and a ZIP member.

## Precision and timing

| Check | Result |
| --- | --- |
| `check_rule_pairs.py` | 120 covered rule and heuristic IDs |
| `probe_detection_gaps.py --verify` | 696 passing cases and the two existing open cases |
| `probe_rule_coverage.py --verify` | Passed with 89 compiled bundled rules and zero compile skips |
| `measure_precision.py --fail-over` | Zero new hits on 328 generated files. The four existing Windows shortcut collisions remained |
| `sweep_rule_changes.py --jobs 4 --limit 5000` | Zero changed finding sets on 5,000 Homebrew doc and man files, Python library files, and repository docs |
| `sweep_rule_changes.py --jobs 4` | Zero changed finding sets across 788 English [Transformers documentation pages](https://github.com/huggingface/transformers/tree/cf13eb97cddb3655cd83bada097a7ecfcf108ace/docs/source/en), including prompt-engineering, summarization, and model docs |

The five new 4 MiB repeated near-miss cases took 0.28–0.54 s per scan.
The timing tripwire allows 10 s per scan. These corpora measure the listed
inputs and give no estimate of production precision or recall.

The full timing tripwire passed all 88 cases. The slowest scan took 2.96 s.

## Installed CLI and browser

The installed wheel's rule file and workbench HTML matched the source files
byte for byte. The installed CLI scanned a positive and its crawler near-miss
from a disposable inbox. It wrote reports before returning and placed the
original bytes under `blocked/<sha256>/` and `clean/<sha256>/` respectively.

Computer Use drove the wheel's real loopback workbench. It rendered the default
advisory, both agent-policy holds, the hidden HTML finding and the clean crawler
control. Empty input cleared the prior verdict and displayed a validation
error. Under `agent-ingest`, the Excel pair blocked and passed as expected,
and the live catalog matched 81 of 81 expected results with zero findings
on benign twins. The separately built static replay switched the selected
hidden HTML example from recorded block to recorded advisory when the policy changed.
