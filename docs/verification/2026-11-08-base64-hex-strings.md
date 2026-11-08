# PDF hex strings and `agent_base64_blob` — November 8, 2026

Base: main `1497368` (Merge #190, after #192 and #194). First measured on `0b2897e`, then rebased and re-run. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X
1.23.0, 85 bundled local rules, zero skips, no vendor download. Every scan used a disposable
copy of `rules/local` and `rules/rules.lock`.

## Defect

`agent_base64_blob` (advisory) reads the `yara_gate_b64_blob` global, which
`heuristics.base64_run_signals` sets for a run of 400 or more `[A-Za-z0-9+/]` characters
that is not media, a font, a PEM body, or an SSH key. Hex digits are 22 of those 64
characters, so a long PDF hex string counted as base64. Ordinary generator output was held
under `agent-ingest` and `agent-document`.

Measured on PDFs generated in this container for
[2026-11-07-pdf-font-readings.md](2026-11-07-pdf-font-readings.md):

| Generator | Files with the finding | View | The run that set the signal |
| --- | --- | --- | --- |
| Chromium 153.0.8010.12 `page.pdf()` | 7 of 12 | `pdf-flate` | a line's glyph-id string, `<002C00510059…> Tj`, 400–464 digits |
| LibreOffice 24.2.7.2 | 8 of 8 | `raw` | a long heading's outline title, `/Title<FEFF0043…>`, 1,340–1,492 digits |

Every run that set the signal was hex digits only. On main, each LibreOffice file was
`advisory` under the default policy and `block` under `agent-ingest` and `agent-document`.
The same held for the Chromium files whose longest line ran to 100 or more glyphs.

The decoded-stream sample filter (`_b64_unsampled`) had already hidden some of these by
accident. Glyph ids numbered as character + 0x100 read as neighboring pixels and were cut.
Chromium's subset ids, which count up from 3, were not.

## Change

A run made only of `[0-9A-Fa-f]` no longer sets the blob signal. The check covers each run
on its own, like the other exemptions. The executable signal is unchanged, though no
hex-only run can match its magic. Two reasons make this safe:

- **Real base64 data never gets there.** Random base64 is hex-only for 400 characters with
  probability (22/64)^400. Base64 of hex text is not itself hex: `MDEy…` for `012…`.
- **Payloads keep their findings.** One character outside the hex digits keeps the run, and a
  payload next to a hex string is its own run.

One consequence: base64 of zero bytes (`AAAA…`) is also hex-only, so it is no longer a blob.
It carries no data. That was the shape of the old fixture `samples.base64_text()`
(`A*200 + B*200`), which never decoded to anything. The fixture is now `A*200 + Q*200`;
`Q` is outside the hex digits.

| Fixture | main `0b2897e` and `1497368` | this change |
| --- | --- | --- |
| `hex-glyph-line.pdf` (588-digit glyph-id string) | advisory, `agent_base64_blob` (raw) | clean |
| `hex-outline-title.pdf` (UTF-16BE outline title) | advisory, `agent_base64_blob` (raw) | clean |
| `hex-beside-base64.pdf` (the same string, then a base64 payload) | advisory, `agent_base64_blob` | advisory, `agent_base64_blob` |
| 12 Chromium exports | 7 advisory | 12 clean |
| 8 LibreOffice exports | 8 advisory (`agent_base64_blob`, `heuristic_pdf_OpenAction_goto`) | 8 advisory, only the `heuristic_pdf_OpenAction_goto` note |

The LibreOffice exports keep `heuristic_pdf_OpenAction_goto`, an existing note for
LibreOffice's open-to-page action. `agent-ingest` still holds them for that note, and
`agent-document` now records it and passes them instead of blocking.

Cost: `base64_run_signals` on 4 MiB of one hex run took 12.2 ms (5.8 ms on main), and on
4 MiB of 400-digit runs 21.3 ms (10.7 ms). A base64 run ahead of hex is unchanged (5.6 ms).

## Commands and results (this container)

- `uv run pytest -q tests/test_text_fast_paths.py tests/test_scanner.py tests/test_demo.py tests/test_heuristics.py tests/test_pdftext.py tests/test_pdf_text_folding.py`:
  290 passed. The new `test_a_hex_only_run_is_hex_text_not_base64` fails on main's
  `heuristics.py`.
- `docs/verification/check_added_rules.py`: passed, 215 cases plus 4 vendor-override cases.
  The three new `hex_string_cases` were checked against main's code: both benign fixtures
  report `agent_base64_blob` there, and the payload control reports it on both.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete,
  and `agent_base64_blob` hits 0 files. The two new hex PDFs would be its only hits on main.
  The only other hits are `heuristic_pdf_text_unmapped` on `pdf/merged-5-fonts.pdf` (from #192)
  and the four tagged Windows files.
- `docs/verification/check_rule_pairs.py`: passed (115 rules). Its `agent_base64_blob`
  positive uses the updated fixture.
- `docs/verification/lint_rules.py`: 85 local rules compiled and linted.
- `docs/research/probe_rule_coverage.py --verify`: exit 0, no failures.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 215 `ok`, no FAIL or STALE.
- `docs/verification/check_worst_case_timing.py`: PASS, 29 inputs of exactly 4 MiB. The
  slowest was `pdf-page-objects.pdf` at 6.29 s.
- `ruff check .`, `ruff format --check .`, `mypy --strict src` (20 files), and
  `check_text_controls.py`: clean.

## Residual risks and boundaries

- **Hex payloads are not reported by this rule.** A program or document carried as 400
  or more hex digits was reported before by accident, as "base64". It no longer is. No rule
  here reads hex-encoded payloads as such. Decoding them would be a separate view.
- **Hex runs with a prefix still count.** A run that starts with a non-hex character, such
  as a SQL dump's `0x89504E47…`, still counts: the `x` belongs to the run.
- **Small sample.** The rates come from 20 locally generated files and synthetic fixtures,
  not a production corpus. Hosted CI has not run this change.
