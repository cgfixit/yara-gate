# Exact PDF feature names — October 22, 2026

Baseline: `d0c5a0f2af48288b8f13de3d757e97a338ae587a`, Python 3.12.12,
YARA-X 1.21.0, macOS 27.0.1 ARM64. The production path is `scan_file` →
`heuristic_findings` → `pdf_findings` → `_pdf_name_span`, for both outer files and
archive members.

## Reproduction and change

An inert PDF containing `/JS1`, `/Launch-Report`, and `/AA_Notes` returned block
with JavaScript, Launch, and additional-action findings. None of those names is
`/JS`, `/Launch`, or `/AA`. The suffix test accepted any non-letter after a
feature's name, so digits, punctuation, and their hex escapes caused false blocks.
All 35 initial suffix regression cases failed before the change.

Names now match the complete decoded token. Lexing uses PDF whitespace and the
percent comment delimiter, so exact names followed by null whitespace or comments
remain detectable. Vertical tab is a regular PDF name byte and does not terminate
the name. Existing `#xx` decoding and physical spans remain unchanged.

This follows the lexical/name-object rules in
[ISO 32000-1, sections 7.2 and 7.3.5](https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf).
The [PDF 2.0 syntax errata](https://pdf-issues.pdfa.org/32000-2-2020/clause07.html)
clarify that braces are delimiters only inside Type 4 calculator functions; this
name scanner does not treat them as name terminators.

## Verification

- **56 focused heuristic cases pass**, including all seven risky feature names
  with six benign suffix forms, eight legal whitespace/comment/delimiter forms,
  escaped names and existing Office/embedded-executable coverage.
- Direct `scan_file` calls keep inert metadata-name PDFs clean and exact escaped
  `/JS` PDFs blocked, both directly and inside ZIP members. Member findings retain
  `member_path=["zip:0"]`.
- Eight actual CLI inbox scans (both files, both forms, both policies) return the
  expected exit and physical `clean/` or `blocked/` destination. No scan accesses
  the operator's gate home or executes a target.
- The maintained scanner/CLI probe passes: 20 local rules, zero skips, 120 library
  cases, 24 CLI operations and three failure paths. Ruff and strict mypy pass.

```sh
uv sync --frozen --group dev
uv run pytest -q tests/test_heuristics.py
uv run python docs/research/probe_rule_coverage.py --verify
uv run ruff check src/yara_gate/heuristics.py tests/test_heuristics.py
uv run ruff format --check src/yara_gate/heuristics.py tests/test_heuristics.py
uv run mypy --strict src
```

The focused tests are justified by the risk of dropping real active-name matches
while removing suffix collisions. Broad regression/platform coverage belongs to
hosted CI. This change adds no dependency and does not parse object reachability,
streams, strings or comments semantically. Exact risky names appearing in inert
PDF text may still match. The existing `/OpenAction` feature restriction remains,
including navigation actions. No production false-positive rate is claimed.
