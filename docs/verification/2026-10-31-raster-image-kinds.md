# Uncompressed rasters and metafiles are images, not text — October 31, 2026

Baseline: `main` `03e2404`. Head: `90a95bc`. Python 3.12.3, YARA-X 1.22.1, Linux x86_64 (root
container). Shipped local rules only: 80 compiled, 0 skipped. No vendor pack was installed, no
target was executed, nothing was fetched, and every CLI scan used a fresh disposable home and a
fresh copy of `rules/local`.

## Defect

This is the DOCX side of the image-as-text work on the PDF view (#136, #137). There, decoded
PDF streams carry pixels. In a DOCX, `word/media/image1.bmp` is its own zip member, scanned as
a unit, and two things go wrong for uncompressed images:

1. **`sniff` has no image kinds.** PNG, JPEG, and GIF come out `unknown` only because compressed
   bytes are full of control bytes. An uncompressed BMP or TIFF of mid-tone pixels has fewer
   than 5% control bytes in its first 4 KB, so it sniffs as `text`. The text views and the
   `yara_gate_text` rules then read pixels. One TIFF gives `agent_invisible_unicode@raw`, and 24
   files give `agent_base64_blob@format-controls-removed`.
2. **The base64 signal ignores the kind.** `base64_run_signals` runs on every unit, and
   `agent_base64_blob` has no text condition. So units that sniff `unknown` fire too: EMF, WMF,
   8-bit gray BMP, and SGI.

Reproduced with python-docx 1.2.0, `doc.add_picture` of the 12 repository screenshots and two
synthetic 800x600 mid-tone images (flat, and ±2 grain), each saved by Pillow 12.3.0 as BMP and
as TIFF (28 DOCX files). Results under default / agent-ingest / agent-document:

| Input | `main` (findings via #138's branch; see note) | Head |
| --- | --- | --- |
| 28 DOCX, BMP or TIFF image | advisory / block / block, all 28 | clean, all 28 |
| Findings (default) | `agent_base64_blob@raw` 28, `@format-controls-removed` 24, `@html-unescaped` 3, `agent_invisible_unicode@raw` 1 | none |

Note: on `main`, the synthetic grain BMP DOCX does not finish (killed at 120 s). That is the
quadratic `text-folded` defect fixed separately in #138. The real final-rejection TIFF DOCX
finishes in 2 s on `main`. The baseline column is #138's head, which differs from `main` only
in that pattern; its `text_views` output was shown to be byte-identical to `main`'s on 484 files.

Bare files, `agent-ingest` (`scan_bytes`, real screenshot and grain image):

| Format | `main` | Head |
| --- | --- | --- |
| BMP 24-bit, 8-bit gray, 32-bit RGBA | block (sniff `text` or `unknown`), RGBA clean | clean, sniff `bmp` |
| TIFF uncompressed / LZW | block / clean | clean, sniff `tiff` |
| EMF and WMF (LibreOffice 24.2 conversions of the PNGs) | block (`unknown`) | clean, sniff `emf` / `wmf` |

## Change

- **`filetype._raster_kind`**, called by `sniff` after the archive and executable kinds and
  before the text test. It recognizes:
  - **`bmp`**: `BM`, a DIB header size of 12, 40, 52, 56, 64, 108, or 124, a pixel offset
    between the end of the headers and the end of the data, and one plane.
  - **`tiff`**: `II*\0` or `MM\0*` with a first-IFD offset inside the data, or BigTIFF
    `II+\0`/`MM\0+` with the fixed 8 and 0 fields.
  - **`emf`**: record type 1, a header size of at least 88 that fits, and ` EMF` at offset 40.
  - **`wmf`**: a standard header (type 1 or 2, size 9, version 0x100 or 0x300), alone or after
    the 22-byte placeable header `D7 CD C6 9A`.

  Each check needs NUL bytes or small binary integers that text cannot hold, so text that
  starts with `BM` or `II*` stays text. `RASTER_KINDS` names the four.
- **`scanner._invoke_scan`**: for a raster kind, `yara_gate_b64_blob` is false.
  `yara_gate_b64_exe` is unchanged, and `yara_gate_text` is false because the kind is not
  `text`. The text views already skip any unit that does not sniff `text`.
- `docs/rules.md` describes the exemption and the mismatch.

## What still applies, and what is given up

| Control | `main` | Head |
| --- | --- | --- |
| C1/C2: `.txt` starting `BMW owners:` / `II* notes`, then an injection phrase | block (phrase) | unchanged, still `text` |
| C9: a `.txt` holding only `BM` | clean | clean, still `text` |
| C3/C4: `.txt`/`.md` with a real BMP header, then injection text | block (phrase @raw, @text-folded) | block: phrase @raw and **`filetype_mismatch_bmp`** (advisory) |
| C5: BMP whose pixels hold a base64 PE | block (blob + executable) | block (`agent_base64_executable`) |
| C6: BMP whose pixels hold base64 of `SECURITY.md` | block (blob) | clean (given up) |
| C7: `.bmp` with a real header, then injection text | block (phrase @raw, @text-folded) | block (phrase @raw); derived views no longer run (given up) |
| C8: DOCX with an injection sentence in `document.xml` and a BMP image | block | block (phrase @raw, @text-folded) |

Given up, on purpose:

- **Base64 in pixel bytes.** A reader shown an image does not see its sample bytes as text.
- **Derived views on a raster unit.** The raw-view rules, executable checks, and installed
  signatures still read it. A text extension on a raster header adds `filetype_mismatch_<kind>`,
  which is advisory and held under both agent policies.

A text payload behind a forged header skips the text checks. But 205 NUL bytes in the first
4 KB already do that today, and the mismatch finding is new coverage for the forged-header
case.

## Verification

- **Unchanged elsewhere.** 45 DOCX files without BMP or TIFF members (the 14 images as PNG,
  JPEG, and GIF; LibreOffice exports of `README.md` and `docs/rules.md`; a README build with a
  screenshot) × 3 policies: 135 scans identical to `main`. The 114-PDF corpus from #137's record
  × 3 policies: 342 scans identical to `main`.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src tests && uv run ruff format --check src/yara_gate tests
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_filetype.py tests/test_scanner.py tests/test_text_fast_paths.py tests/test_heuristics.py
```

- Probe at `90a95bc`: passed, 0 failures; 531 library, 55 CLI, and 109 benign observations; 3
  failure paths.
- Rule pairs: passed (105 rules).
- Precision: 310 files, 0 incomplete, exit 0; the per-rule table is identical to `main`'s.
- Ruff, format, strict mypy, and the text control check: clean.
- Tests: three new behavior tests fail on `main`:
  - `test_uncompressed_rasters_and_metafiles_are_not_text`
  - `test_text_that_starts_like_an_image_stays_text`, its mismatch half
  - `test_raster_samples_are_not_base64_but_an_encoded_executable_is`

  All 200 tests in the four files pass on head. The broad pytest and selftest suites are left
  to hosted CI.

## Remaining

- **Formats not recognized.** Headerless DIB, binary PPM/PGM (`P5`/`P6`), TGA (no magic), PCX,
  and SGI still sniff as before. In the bare-file run, DIB, PPM, TGA, and SGI images still gave
  `agent_base64_blob`. None of them is a format Office stores in `word/media`.
- **Phrase rules on raw pixels.** The raw-view phrase rules have no text condition, so they
  still read a raster's bytes. No real image here matched one.
- **Interaction with #137.** #137 handles PDF image samples by reading the run (`samples=True`),
  because a PDF stream's label is attacker-chosen. Here the kind comes from the unit's own
  header, which decides how readers open the file. If the stack lands, rasters could use
  `samples=True` instead of turning the blob signal off, keeping base64 in pixels detectable at
  the cost of the grain walk.
