# Grainy image samples and pixel-born controls in the pdf-flate view — October 31, 2026

Baseline: draft PR #136 `claude/exciting-curie-7w7bsx` at `feb43a4` (the repeat exemption for
`agent_base64_blob`), stacked on #134 `0ffb339` and `main` `03e2404`. This change is stacked on
#136. Head: `41ca9d8`. Python 3.12.3, YARA-X 1.22.1, Linux x86_64 (root container). Shipped
local rules only: 80 compiled, 0 skipped. No vendor pack was installed, no target was executed,
nothing was fetched, and every CLI scan used a fresh disposable home and a fresh copy of
`rules/local`.

## Defects reproduced on `feb43a4`

#136's record lists two image-as-text gaps. Both reproduce with
`yara-gate scan - --name <file>.pdf --json --home <tmp> --rules <tmp copy> --policy <policy>`:

1. **`agent_invisible_unicode@pdf-flate` on pixels.** `screenshots/yara-gate-final-rejection.jpg`
   re-saved as PNG (Pillow 12.3.0) and drawn with ReportLab 5.0.1 `canvas.drawImage`
   (`pageCompression=1`) gives the note with `rl_config.useA85 = 0` and with the default
   ASCII85 chain. The pixel stream holds `EF BB BF` (an internal BOM) at offset 2,308,407, in an
   anti-aliased edge: `e8 de d4 6a 4e 4a 95 72 70 ff e7 e5 ff e3 df f3 e5 dc bb a8 a1 75 47 49 |
   f0 cd cb 76 5f 59 96 8b 85 ...`. Result: default `advisory` (exit 0), `agent-ingest` block
   (exit 1), `agent-document` `advisory` (exit 0).
   The bytes around the match are neither smooth nor valid UTF-8, so a pixel-likeness measure
   would not have caught this case. It needed its own test.
2. **`agent_base64_blob@pdf-flate` on grain.** 1200x800 synthetic images, mid-tone with every
   channel value in `a`-`z` and ±2 noise per channel (horizontal and vertical gradients, a flat
   noisy panel, a gray diagonal), each as Flate and as ASCII85: all 8 give the advisory
   (block under `agent-ingest` and `agent-document`). Noise breaks #136's exact-repeat collapse.

## Change

Both are decided from the bytes, in `pdf-flate` only. No stream dictionary key is read, and no
stream leaves the view.

- **`heuristics._b64_unsampled`** (used when `samples=True`): a run is a blob only if it has 400
  characters outside *sample-like* 64-character windows, in addition to #136's 400 after the
  repeat cut. A window is sample-like when, at one lag of 1, 2, 3, 4, 6, or 8 bytes (gray,
  gray+alpha, RGB, RGBA/CMYK, 16-bit RGB, 16-bit CMYK), at least 58 of its 64 characters are
  *near* the character that lag before. "Near" buckets each byte by 8 on two grids offset by 4.
  Two bytes are near when they share a bucket on either grid, which is always true within 4 and
  sometimes true up to 7. The masks are built with `bytes.translate` and big-integer XOR, so
  the per-byte work runs in C, and the run is walked in 64 KiB chunks that stop once 400 are
  kept. Windows are aligned at the run's start, each one also compares against the 8 bytes just
  before it, and a partial last window is kept.
- **`heuristics.control_in_text`** and **`scanner._first_match`**: for `agent_invisible_unicode`,
  `agent_bidi_override`, and `agent_bidi_formatting` in `pdf-flate`, the finding is kept at the
  first match where the 16 bytes before *or* the 16 bytes after decode as strict UTF-8
  (allowing a sequence cut at the far edge; an empty side counts as text). If no match
  qualifies, the finding is dropped. `agent_bidi_source` (block) is not touched. Neither is any
  other view, nor the raw-text `heuristic_invisible_joiner` and `heuristic_unicode_tag` checks,
  which never read `pdf-flate`.
- `docs/rules.md` describes both exemptions.

### Why these, and what room they give

- **Skipping `/Subtype /Image`** stays rejected, for the reasons in #136's record: the label is
  attacker-controlled and readers decode by reference.
- **The grain test, measured.** Best-lag near count per window, grid metric:

  | Input | Windows | Median | p99 | Max | Windows cut (≥58) |
  | --- | --- | --- | --- | --- | --- |
  | base64 of random bytes | 624 | 14 | 19 | 22 | 0 |
  | base64 of `README.md` | 395 | 20 | 29 | 35 | 0 |
  | base64 of `SECURITY.md` | 10 | 20 | 24 | 24 | 0 |
  | base64 of UTF-16LE PowerShell (`New-Object Net.WebClient ... Invoke-Expression`) | 183 | 38 | 44 | 44 | 0 |
  | base64 of UTF-16LE `README.md` | 790 | 40 | 48 | 52 | 0 |
  | base64 of UTF-32LE `README.md` | 1580 | 43 | 48 | 51 | 0 |
  | base64 of JSON | 428 | 24 | 33 | 35 | 0 |
  | base64 of zlib data | 172 | 14 | 20 | 23 | 0 |
  | base64 of `content.py` | 917 | 22 | 39 | 44 | 0 |
  | base64 of hex text | 790 | 33 | 43 | 55 | 0 |

  On the exact |Δ| ≤ 4 metric, every 64-character window of the grainy images scored at least
  0.97, and every window of the real screenshots' runs at least 0.89. Those screenshot windows
  are already cut by the repeat count, so they do not depend on this test. The tightest margin
  is base64 of hex text, at 55 against a cut of 58. UTF-16LE text, the PowerShell
  `-EncodedCommand` case, has a margin of 6 or more.
- **Dilution.** A payload inside grainy padding in one run: across 20 trials × 64 alignments ×
  lengths 300-419, the largest contiguous random payload that was exempt was 372 characters. So
  a 400-character payload always fires. Even 8-character fragments of random base64, spread
  between 200-character grain stretches with 600 payload characters in total, still fire: one
  random fragment puts a window over 6 far characters at every lag.
- **What the test does give up.** A payload built so that its base64 characters form smooth
  byte sequences at a 1-8 byte lag is exempt in `pdf-flate`. Meaningful text, scripts,
  executables, and compressed data do not encode that way (see the table). The 400 floor was
  never an adversarial bound anyway: on `feb43a4`, base64 of 3,000 random bytes wrapped at 76
  characters (`base64.encodebytes`) scans **clean**, because a line break ends the run.
- **The control test.** In a single-byte context, `E2 80 8B` reads as `â€‹`, not as a zero-width
  space, and in pixels it is not a character. A real control used to split a phrase sits next
  to letters, which are UTF-8. Hiding one between invalid bytes on *both* sides makes a UTF-8
  reader show replacement characters next to it. That case (`U6` below) is now exempt in
  `pdf-flate`, and the change accepts that.
- **Cost.** The grain walk is linear in the length of a sample-like run. A payload exits after a
  few windows. On a 5 MB grainy run the walk took 0.29 s; on 5 MB of random base64 the whole
  signal took 11 ms. A PDF with one 20 MB grainy RGB stream took 0.90 s on `feb43a4` and 2.25 s
  on head (`scan_seconds`). The deadline and the YARA-X timeout still bound the scan.

## Direct verification

- **Reference check.** 3,000 generated runs mixed random alphabet text and noisy pixel stretches
  at lags 1-8, at random lengths and start offsets. `_b64_unsampled` agreed on all of them with a
  pure-Python per-window implementation of the same rule.
- **Control contexts** (`control_in_text`): text for an English split phrase, an RLM after an
  Arabic name, CJK on both sides, matches at the buffer's start and end, and a CJK sequence cut at
  both window edges. Not text for the pixel context from defect 1, for Latin-1 on both sides,
  and for invalid bytes on both sides. Text when one side is invalid and the other is English.

### Controls (hand-built PDFs, CLI, default / agent-ingest / agent-document)

Every stream is FlateDecode. "Image" means `/Type /XObject /Subtype /Image ... /DeviceRGB`.

| File | `feb43a4` | Head |
| --- | --- | --- |
| U1: ZWSP-split phrase in a content stream | advisory / block / advisory | unchanged |
| U2: ZWSP in UTF-8 XMP metadata | advisory / block / advisory | unchanged |
| U3: RLM after an Arabic name in a content stream | advisory / block / advisory | unchanged |
| U4: ZWSP inside high-byte pixels, image XObject | advisory / block / advisory | clean |
| U5: the same pixels, image-labeled, used as `/Contents` | advisory / block / advisory | clean |
| U6: ZWSP between 8 invalid bytes on each side | advisory / block / advisory | clean (accepted) |
| B1: 60,000 grain characters in a content-stream string | advisory / block / block | clean |
| B2: grainy RGB image XObject | advisory / block / block | clean |
| B9: grainy gray image (lag 1) | advisory / block / block | clean |
| B10: grainy CMYK image (lag 4) | advisory / block / block | clean |
| B3: base64 UTF-16LE PowerShell in a content stream | advisory / block / block | unchanged |
| B4: base64 of `SECURITY.md` in a content stream | advisory / block / block | unchanged |
| B5: 600 random base64 between 30,000 grain characters, one run | advisory / block / block | unchanged |
| B6: base64 UTF-16LE PowerShell between grain, one run | advisory / block / block | unchanged |
| B7: random payload, image-labeled stream | advisory / block / block | unchanged |
| B8: base64 PE in a content stream | block (blob + executable) | unchanged |

### Real PDFs, `feb43a4` against head

114 files under three policies:

- The 12 repository screenshots (JPGs re-saved as PNG), each as Flate and ASCII85 (24).
- 30 system PNG/JPEG images, as Flate and ASCII85 (60): oletools screenshots, LibreOffice
  gallery and intro art, Go image benchmarks, `gnupg-module-overview.png`, the nvm threat-actor
  diagrams, the pyparsing class diagrams, and the requests logos and screenshots.
- The 8 synthetic grainy image PDFs and the 16 controls above.
- LibreOffice 24.2 exports of `README.md`, `SECURITY.md`, `docs/rules.md`, and
  `docs/integrations.md`.
- ReportLab Platypus builds of `README.md` with the final-rejection screenshot, as Flate and as
  ASCII85.

ReportLab, Pillow, and LibreOffice are system packages outside the locked environment, used only
to make inputs. `content.py` is unchanged, so the `pdf-flate` view bytes are the same on both
sides.

- No incomplete result on either side. Findings are identical across the three policies on each
  side. 95 files have identical results.
- The 19 that changed differ only by removed findings. Nothing was added.
  - `agent_base64_blob@pdf-flate`: 12 removed (the 8 grain PDFs, B1, B2, B9, B10). Every
    payload control keeps it.
  - `agent_invisible_unicode@pdf-flate`: 7 removed (both final-rejection PDFs, both Platypus
    builds, U4, U5, U6).
  - The pixel-born `heuristic_unicode_control_conjunction@pdf-flate` (advisory) is removed from
    both Platypus builds. Their verdicts stay the same, because README's documentary
    `agent_prompt_injection_phrases` and `agent_secret_transfer_request` remain, as #134's and
    #136's records describe.
- Default-policy finding counts:
  - `agent_base64_blob@pdf-flate`: 18 → 6 (B3-B8).
  - `agent_invisible_unicode@pdf-flate`: 10 → 3 (U1-U3).

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src tests && uv run ruff format --check src/yara_gate tests
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_text_fast_paths.py tests/test_scanner.py -k "grainy or control_bytes or repeated_samples or image_samples"
```

- Probe at `41ca9d8`: passed, 0 failures; 531 library, 55 CLI, and 109 benign observations; 3
  failure paths.
- Rule pairs: passed (105 rules).
- Precision: 310 files, 0 incomplete, exit 0. The per-rule table is identical to `feb43a4`'s.
  Three runs took 0.56-0.65 s.
- Ruff, format, strict mypy, and the text control check (202 files): clean.
- Tests: the two new cases (`test_grainy_samples_are_not_a_blob_but_structured_payloads_are`,
  `test_pdf_control_bytes_in_image_samples_are_not_text`) fail on `feb43a4` and pass on head.
  #136's selected tests still pass. The broad pytest and selftest suites are left to hosted CI.

## Remaining gaps

- **Dark pixels around a control.** A control sequence in pixels whose neighbors fall in the
  ASCII range is valid UTF-8 and still counts. None occurred in the 84 real-image PDFs.
- **Hex-like base64.** Base64 of hex text reaches 55 of 64 against the cut of 58. That is the
  thinnest margin measured.
- **PDF name checks on ASCII85 image text (raw view).** Separate from this change and unchanged by
  it. `heuristic_pdf_AA@raw` blocks under every policy on `grain-hgrad-a85.pdf` and on the
  ASCII85 build of `pyparsingClassDiagram_3.0.9`. `heuristic_pdf_JS@raw` does the same on the
  ASCII85 build of `pyparsingClassDiagram_1.5.2`. The ASCII85 text of the image spells the
  token.
- **The raw view and line-wrapped base64.** #136's `agent_base64_blob@raw` on the ASCII85
  `yara-gate-agent-ingest` build remains. Base64 wrapped under 400 characters per line never
  forms a run, in any view.
- **The first-4 KB sniff** is unchanged, as in #136's record.
