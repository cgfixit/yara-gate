# Base64 and percent-decoded text views (2026-11-05)

Source: `main` at `7f9934c`, branch `views/base64-percent-text`. Linux x86_64, Python 3.12,
locked YARA-X 1.22.1, a disposable copy of the shipped rules (81 local rules after this change,
no vendor packs). Nothing was executed.

## Baseline

`agent_encoded_instruction` matched four fixed phrases through YARA's `base64` modifier. On
`main`, base64 of any other wording (`Please disregard prior guidelines ...`, caught in plain
text by `agent_override_imperative`), the same text in a JSON value, and percent-encoded text
all scanned clean.

## Change

- `text_views` yields `base64-decoded` (standard or URL-safe runs of 16+ characters, line
  wraps rejoined, UTF-8 or UTF-16LE, kept when 95% printable with a space, one run per line,
  4,096 runs at most, skipped on MIME messages whose parts are already members) and
  `percent-decoded` (three `%XX` escapes, or a token of four letter words joined by `+`).
- Both are raw-only views for `agent_base64_blob` and `agent_base64_executable`, like
  `text-folded`.
- `agent_encoded_instruction` is removed. Its phrases now reach `agent_prompt_injection_phrases`,
  which is also `note`, so no finding drops a tier; `agent-ingest` still holds and
  `agent-document` still records.

## Outcomes

| Probe | `main` | Branch |
| --- | --- | --- |
| The four retired phrases, ASCII and UTF-16LE | note | note (`base64-decoded`) |
| Other override wording, base64 in JSON, URL-safe, wrapped at 76, a phrase off the 3-byte grid, PowerShell `-EncodedCommand` UTF-16LE | clean | note |
| `%XX`, `quote_plus` (`q=Ignore+previous+...`), percent in a URL | clean | note (`percent-decoded`) |
| Base64 of an ordinary sentence or a single word, a PNG data URI, a PEM body, a JWT, 50 hex SHAs, long identifiers, an encoded query, `12%` prose | clean | clean |
| A `.eml` whose base64 body holds the phrase | one finding, member `mime:0` | the same single finding |

`check_added_rules.py` gains 14 cases; with `content.py` and `scanner.py` reverted, the 8 hits
miss and the 6 benign cases pass. `stdin` CLI with `--name sms.txt`: default exit 0, agent-ingest
exit 1, agent-document exit 0 with `agent-document records note findings`.

## Cost

Median of three `scan_bytes` runs on 4 MiB inputs, same host:

| Input | `main` | First draft | Branch |
| --- | --- | --- | --- |
| ASCII prose | 0.46 s | 0.93 s | 0.51 s |
| UTF-16 prose | 0.67 s | 1.17 s | 0.74 s |
| One random base64 run | 0.57 s | 4.29 s | 0.62 s |
| The same run wrapped at 76 | 0.72 s | 1.32 s | 0.83 s |
| Long identifiers | 0.54 s | 0.93 s | 0.52 s |

The first draft used a per-group run regex and a Unicode `+`-word regex that tried every
position, then walked whole base64 runs in Python. The branch uses one possessive token regex
and a `+`-anchored search bounded to 512 characters each side.
`docs/research/benchmark_text_scan.py` stops with `inconsistent scan results` on unmodified
`main` too, so these numbers come from a separate script.

## Checks

`lint_rules.py` (81), `check_rule_pairs.py` (108; the base64 pair moved to
`agent_prompt_injection_phrases`), `check_added_rules.py` (111), `check_scan_only.py`,
`check_intake.py`, `check_text_controls.py`, `measure_precision.py --fail-over` (identical
per-rule counts to `main` apart from the removed row), `probe_rule_coverage.py --verify`,
`yara-gate selftest`, ruff, `mypy --strict src`, and focused pytest (scanner, text fast paths,
report, policies, CLI JSON, heuristics, SMS bridge, pages, demo, rules: 324 passed).

## Not established

Hex, ROT13, and nested encodings are not decoded. No real mail or chat corpus was measured.

## Codex review fixes (2026-11-06)

Codex code and security reviews of `184088a` raised five findings; all reproduced on that head
and are fixed. Four were cases the retired fixed-phrase rule caught through YARA's `base64`
modifier in raw bytes:

| Finding | Before | After |
| --- | --- | --- |
| A padded run followed by a line of text joined into one token that did not decode | miss | padding ends a token; a wrapped token that does not decode is tried line by line |
| Decoded runs joined with one newline let two JSON fields form one phrase | false positive | each decoded run is its own YARA pass |
| Runs after the first 4,096 candidates were dropped silently | miss | every candidate is read under the scan deadline; more than 1,024 readable runs is incomplete |
| Base64 inside a PDF's inflated text stream was not decoded | miss | the `pdf-flate` text gets the same base64 view |
| An RFC 2047 encoded `Subject` in a `.eml` was skipped with the message's base64 view | miss | headers' encoded words get a `mime-headers-decoded` view |

`check_added_rules.py` gains five cases; with `content.py` and `scanner.py` reverted they give
four misses and one false positive. Precision per-rule counts match `main` (less the retired
rule), the 200 host-document PDFs and texts show no new finding, a base64 mail body still gives
one finding at `mime:0`, and the full pytest suite in one run passes (404 passed, 5 skipped).

Cost: with no candidate cap, a 4 MiB file of long identifiers takes 0.81 s against 0.52 s
before (every token is probed); ASCII prose, UTF-16, and base64 runs are unchanged.
