# Deflated constant regions and `agent_base64_blob` (2026-11-23)

Source: `main` at `bdd0fa4`, branch `claude/rules-b64-repeat-runs`. Linux x86_64, Python 3.12,
YARA-X 1.23.0, 89 compiled local rules. No rule file, rule id, or severity changes.

## The miss, on the base revision

**Verified.** zlib writes a long run of one byte value as a repeat that falls in the base64
alphabet. At level 6 (the default) and level 9, a constant region of 9 MiB or more of zeros,
`0xFF`, or spaces produced a 4,098-character run of `U` in the compressed stream; 8 MiB and
less produced none (measured in 1 MiB steps from 4 to 16). `base64_run_signals` exempts repeats
only in samples mode, so the raw bytes of the container set `yara_gate_b64_blob`:

| Input (default policy / `agent-ingest`) | `bdd0fa4` | This change |
| --- | --- | --- |
| zip holding 12 MiB of zeros | advisory / block, `agent_base64_blob` on the outer bytes | clean / clean |
| gzip of 12 MiB of zeros | advisory / block | clean / clean |
| `.docm` with a 64 MiB zero member | block (`heuristic_ooxml_vba`, `agent_base64_blob`) | block (`heuristic_ooxml_vba`) |
| `samples.base64_text()` alone, in a stored zip, a deflated zip, a gzip | advisory / block, on the member | unchanged |
| zip of 12 MiB of zeros beside `base64_text()` | advisory / block | advisory / block, on the member |

In a stored zip the outer raw bytes also hold the member's text; there the repeat-only fixture
used to add a second `agent_base64_blob` finding with no member path beside the member's own.
That duplicate is gone; the member's finding and the verdict stay.

## The change

`base64_run_signals` takes `text`, and `_scan_globals` passes `sniff(data) == "text"`, the
value it already gives `yara_gate_text`. When the buffer is not text, a run counts only if it
keeps 400 characters after each unit of 1 to 12 characters repeated four or more times is cut
to one copy (`_b64_holds_data`, the count the `pdf-flate` view uses). The grain count stays
samples-only. A cut run can be rebuilt from the copy that stays, so it carries no more than a
run under 400 characters, which the rule already ignores.

**Declined first draft.** Cutting repeats in every buffer failed `check_rule_pairs.py`: all
three positive `agent_base64_blob` fixtures went clean, including a LibreOffice `PrinterSetup`
item with a small executable in its driver data, which had no other finding. Text buffers are
therefore unchanged.

## Checks

| Check | Result |
| --- | --- |
| `lint_rules.py` | 89 compiled |
| `check_rule_pairs.py` | 120 rules passed (the first draft failed here) |
| `check_added_rules.py` | 267 plus 4 vendor-override cases |
| `probe_rule_coverage.py --verify` | passed |
| `measure_precision.py --fail-over` (328 files) | per-rule counts identical to `bdd0fa4` |
| `probe_detection_gaps.py --verify` | exit 0 |
| `yara-gate conform` | 94 fixtures, 282 checks, 0 changes |
| `scripts/record_pages_demo.py --baseline` | outcomes match; 93 scenarios x 3 policies |
| `tests/test_text_fast_paths.py`, `tests/test_hidden_members.py` | 23 passed |
| Ruff, `mypy --strict src scripts` | passed |
| `check_worst_case_timing.py`, `probe_match_cap.py` | pending at this commit |
| Two-tree comparison over installed binary and compressed files | pending at this commit |

Timing of `base64_run_signals` alone on 4 MiB buffers (one run each, Linux):

| Input | text | not text |
| --- | --- | --- |
| one 4 MiB run of `U` | 5.7 ms | 6.5 ms |
| 400-character repeat runs split by NUL | 9.3 ms | 74.7 ms |
| 12-character units repeated, near the threshold | 8.9 ms | 170.6 ms |
| random bytes | 77.7 ms | 79.7 ms |
| random base64 | 5.6 ms | 5.6 ms |

The text column stops at the first blob; the other walks each repeat-only run to its end, which
is linear.

## Not established

- Real disk images and databases were not collected; the fixtures are synthetic constant
  regions. The claim is the mechanism and its threshold, not a measured rate.
- Vendor rules were not run.
