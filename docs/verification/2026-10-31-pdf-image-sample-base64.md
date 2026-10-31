# PDF image samples read as base64 in the pdf-flate view — October 31, 2026

Baseline: draft PR #134 `claude/cool-albattani-1cujxl` at `0ffb339` (ASCIIHex/ASCII85 stage
decoding, on `main` `03e2404` with #133). This change is stacked on it. Python 3.12.3, YARA-X
1.22.1, Linux x86_64 (root container). Shipped local rules only: 80 compiled, 0 skipped. No vendor
pack was installed, no target was executed, and every CLI scan used a fresh disposable home and a
fresh copy of `rules/local`.

## Defect

`pdf_views` adds every inflated stream that passes `sniff(data) == "text"` to the `pdf-flate`
view. That test only counts control bytes in the first 4 KB, so the decoded RGB samples of a
screenshot pass it. A flat area whose byte values fall in the base64 alphabet then reads as a long
base64 run: RGB `(0x2B, 0x47, 0x39)` is `+G9+G9+G9...`, `(0x73, 0x72, 0x6D)` is `srmsrm...`.
`agent_base64_blob` fired on it: advisory under `default`, block under `agent-ingest` and
`agent-document`.

Reproduced with ReportLab 5.0.1 (`canvas.drawImage` of `screenshots/yara-gate-demo-overview.png`,
`pageCompression=1`) and `yara-gate scan - --name x.pdf --json --home <tmp> --rules <tmp copy of
rules/local> --policy <policy>`:

| Image stream | `main` `03e2404` | #134 `0ffb339` | This change |
| --- | --- | --- | --- |
| `/FlateDecode` (`rl_config.useA85 = 0`) | advisory / block / block | advisory / block / block | clean, exit 0 under all three |
| `[/ASCII85Decode /FlateDecode]` (ReportLab default) | clean (stream not decoded) | advisory / block / block | clean, exit 0 under all three |

The ASCII85 row is the case #134's record lists as a known false positive it extends.

## Options considered

- **Skip `/Subtype /Image` streams.** Rejected, per the task. Readers decode page `/Contents`,
  object streams, `/JS` streams, `/CharProcs`, and appearance streams by how they are referenced,
  not by that key. A skip would be an evasion path for every rule that reads `pdf-flate`.
- **Skip image-labeled streams unless referenced as `/Contents` or `/Type /ObjStm`.** Rejected.
  The set of "decoded by reference" roles is open-ended (`/JS`, `/CharProcs`, `/AP`, XFA, ...).
  References can sit inside object streams, and `/Width`, `/Height`, and `/ColorSpace` that
  would show the bytes are pixels are attacker-chosen as well.
- **A stricter text test for decoded streams.** Rejected for this change. Any byte test that
  drops a stream hides it from every lexical rule and `pdf_token_findings`, and a content stream
  can legitimately carry binary inline images and CID strings.
- **Scope `agent_base64_blob` away from `pdf-flate` entirely.** Rejected. It also drops a real
  base64 payload in a content stream, object stream, or JavaScript string.
- **Chosen: exempt only runs that are repeats, in `pdf-flate` only.** It is decided from the run's
  bytes, not the dictionary, and it removes nothing from the view.

## Change

- `heuristics.base64_run_signals(data, *, samples=False)`: with `samples=True`, a run that would
  be a blob counts only when `_b64_holds_data` finds it still has 400 characters after each repeat
  is cut to one copy. A repeat is a unit of 1 to 12 characters that occurs four or more times in a
  row. That covers 8-bit gray, gray+alpha, RGB, RGBA/CMYK, two-pixel dithers, and 16-bit samples.
  What is cut can be rebuilt from the copy that stays. A run under the threshold therefore
  carries no more content than a run shorter than 400 characters, which the rule already ignores.
  The exemption gives an attacker no room the 400-character floor did not already give. The
  executable check (`agent_base64_executable`) is unchanged.
- `_b64_holds_data` walks the run about 450 characters at a time and stops as soon as 400 are
  kept. A long repeat is skipped with `startswith` in 4 KB blocks. The naive
  `re.sub(rb"(.{1,12}?)\1{3,}", ...)` took 2.1 s on a 5 MB random run; the walk takes 13 ms. A flat
  5 MB run takes 11 ms.
- `scanner`: the `yara()` closure passes `samples=True` for the `pdf-flate` view only.
  `_yara_findings` and `_invoke_scan` take the keyword. Every other view, including `raw`, keeps
  its current behavior, so `samples.base64_text()` (`A*200 + B*200`) still fires everywhere it is
  used: selftest, demo, `check_rule_pairs.py`, and tests.
- The `_invoke_scan` stand-ins in `selftest._forced_timeout` and `test_timeout_is_incomplete`
  accept the new keyword. Without that, the forced timeout raised `TypeError` and would have read
  `content scan failed` instead of `timeout`.
- `docs/rules.md` describes the exemption and the remaining gap.

## Direct verification

- **Walk against the reference.** 20,000 generated runs mix random alphabet stretches and
  repeated units of 1 to 14 characters, at random lengths. `_b64_holds_data` agrees with
  `len(re.sub(...)) >= 400` on all of them, and on every pixel run below. It never reports "no
  data" where the reference reports data.
- **Pixel corpus.** 30 PNGs went through ReportLab, each as plain Flate and as ASCII85: oletools'
  terminal screenshots, LibreOffice gallery and intro art, Go's `benchNRGBA-gradient.png`,
  `gnupg-module-overview.png`, `/opt/nvm/.github/external-threat-actor.png`,
  `yara-gate-demo-overview.png`, and the repository's JPG screenshots re-saved as PNG so they take
  the Flate path. Every 400+ run in their views collapses to at most 90 characters. Runs of
  random or English base64 stay at about 400 per 400.
- **Synthetic images** at 1200x800, mid-tone with values in the alphabet. Horizontal, vertical
  (one 1.2 MB run), radial, and gray gradients all collapse to 143 characters or fewer. Flat UI
  panels with text, sharp or blurred, produce no runs.

### Controls (hand-built PDFs, CLI, three policies)

| File | #134 | Head |
| --- | --- | --- |
| N1: flat RGB pixels in an image XObject | advisory / block / block | clean |
| N2: the same pixels inside a content-stream string | advisory / block / block | clean |
| N3: 300 flat + 392 random base64 + 90 flat (398 kept) | advisory / block / block | clean |
| P1: 600 random base64 characters in a content stream | advisory / block / block | unchanged |
| P2: base64 of `SECURITY.md` text in a content stream | advisory / block / block | unchanged |
| P3: random payload in a stream labeled `/Subtype /Image` and used as `/Contents` | advisory / block / block | unchanged |
| P4: 600-character payload between two 21,000-character flat runs, one run | advisory / block / block | unchanged |
| P5: exactly 400 random characters | advisory / block / block | unchanged |
| P6: base64 PE | block (blob + executable) | unchanged |
| P7: payload stream after a flat image stream | advisory / block / block | unchanged |
| P8: 300 flat + 396 random + 90 flat (402 kept) | advisory / block / block | unchanged |

### Real PDFs, #134 `0ffb339` against head

86 files: the 60 image PDFs above, 7 synthetic image PDFs, the 11 controls, and 8 more:

- LibreOffice 24.2 exports of `README.md`, `SECURITY.md`, `docs/rules.md`, and
  `docs/integrations.md`.
- `xpdfimport_err.pdf` and `theme-showcase.pdf`.
- ReportLab Platypus builds of `README.md` with the demo screenshot, as Flate and as ASCII85.

ReportLab 5.0.1 and Pillow 12.3.0 are system packages outside the locked environment, used only
to make inputs.

- `pdf-flate` views (SHA-256) and `Budget.expanded` are byte-identical on both sides for all 86
  files. The change alters a verdict input, not what is decoded.
- No incomplete on either side. 51 files have identical results under all three policies. The
  35 that changed differ only by a removed `agent_base64_blob@pdf-flate`. No other finding
  appeared or disappeared.
- `agent_base64_blob@pdf-flate` is in 44 files on #134 and in 9 on head. The 9 are P1-P8 and the
  synthetic noisy image below. Across the 28 PDFs built from real images, including both
  Platypus files, it goes from 28 to 0. The Platypus files keep
  `agent_prompt_injection_phrases` and `agent_secret_transfer_request` from README's documentary
  text, as #134's record describes.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src tests && uv run ruff format --check src/yara_gate tests
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_text_fast_paths.py tests/test_scanner.py -k "repeated_samples or image_samples or base64 or timeout"
```

- Probe: passed, 0 failures; 531 library, 55 CLI, and 109 benign observations; 3 failure paths.
- Rule pairs: passed (105 rules).
- Precision: 310 files, 0 incomplete, exit 0. The per-rule table is identical to #134's.
  Three runs each took 0.63-0.77 s on #134 and 0.67-0.75 s on head.
- Ruff, format, strict mypy, and the text control check: clean.
- Tests: the three new cases fail on #134 and pass on head, and the 8 selected tests pass. The
  broad pytest and selftest suites are left to hosted CI.

## Remaining gaps

- **Grainy mid-tone images.** Photo noise breaks exact repeats. A synthetic 1200x800 gradient
  with ±2 noise per channel, all in the alphabet, still gives `agent_base64_blob@pdf-flate`.
  No real image here does. Catching it needs a pixel-likeness test (lag-3/4 byte similarity) with
  tuned thresholds. Such a test could exempt structured payloads such as UTF-16LE PowerShell
  base64, so it is not added here.
- **Other rules on pixel bytes.** On `yara-gate-final-rejection.jpg` re-saved as PNG, both
  encodings give `agent_invisible_unicode@pdf-flate`. The decoded pixels contain a UTF-8 invisible
  code point. This was already present on #134 and is unchanged here; it is the same image-as-text
  gap for a different rule.
- **The raw view.** One ASCII85 file (`yara-gate-agent-ingest`, re-saved as PNG) still gives
  `agent_base64_blob@raw`. Its raw ASCII85 text repeats `+JqAT` for 422 characters. The raw view
  keeps current behavior by design; this was already present on #134.
- **The first-4 KB sniff.** `sniff` checks only the first 4 KB. An attacker can already keep any
  stream out of `pdf-flate` by starting it with binary bytes. That is unchanged and separate from
  this fix.
