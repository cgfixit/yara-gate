# Uncompressed rasters and metafiles are images, not text — October 31, 2026

Baseline: `main` `03e2404`; after #134 merged, `main` `72cb0f4`. Head: `92e6f12` (first version `90a95bc`, revised after the Codex finding below). Python 3.12.3, YARA-X 1.22.1, Linux x86_64 (root
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

| Input | `main` (findings via #138's branch; see note) | Head (`90a95bc` and `92e6f12`) |
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
| BMP 24-bit, 8-bit gray, 32-bit RGBA | block (sniff `text` or `unknown`), RGBA clean | clean |
| TIFF uncompressed / LZW | block / clean | clean |
| EMF and WMF (LibreOffice 24.2 conversions of the PNGs) | block (`unknown`) | clean |

## Change

- **`filetype._raster_kind`** validates the header:
  - **`bmp`**: `BM`, a DIB header size of 12, 40, 52, 56, 64, 108, or 124, a pixel offset
    between the end of the headers and the end of the data, and one plane.
  - **`tiff`**: `II*\0` or `MM\0*` with a first-IFD offset inside the data, or BigTIFF
    `II+\0`/`MM\0+` with the fixed 8 and 0 fields.
  - **`emf`**: record type 1, a header size of at least 88 that fits, and ` EMF` at offset 40.
  - **`wmf`**: a standard header (type 1 or 2, size 9, version 0x100 or 0x300), alone or after
    the 22-byte placeable header `D7 CD C6 9A`.

  Each check needs NUL bytes or small binary integers that text cannot hold, so text that
  starts with `BM` or `II*` is not mistaken for an image.
- **`filetype.raster_image(suffix, data)`** is true only when the suffix is `.bmp`/`.dib`,
  `.tif`/`.tiff`, `.emf`, or `.wmf` and the header validates as that same format. `sniff` does
  not use it, and the kinds `sniff` reports are unchanged.
- **`scanner`**: for such a unit, the text views and the raw decoded-text joiner and tag
  checks do not run. `_invoke_scan` also sets `yara_gate_text` and `yara_gate_b64_blob` false.
  `yara_gate_b64_exe` is unchanged.
- `docs/rules.md` describes the exemption.

### Codex security review (P2), and the revision

The first version (`90a95bc`) made `sniff` return `bmp`/`tiff`/`emf`/`wmf` from the bytes alone.
Codex's security review pointed out that a `.php` or `.py` script behind a valid BMP header is
still run by its interpreter. `sniff` returned `bmp`, `.php` has no `EXT_EXPECT` entry, and
`yara_gate_text` was false, so `agent_bidi_source` (Trojan Source, block) and the bidi notes
stopped firing. Reproduced with about 2 KB scripts, so that `main` still sniffs them as text,
each holding a right-to-left override and isolates:

| File | `main` `72cb0f4` | `90a95bc` | `92e6f12` |
| --- | --- | --- | --- |
| `plain.php` (no header) | block (`agent_bidi_source`) | block | block |
| `polyglot.php` (BMP header) | block (`agent_bidi_source`) | **clean** | block |
| `polyglot.py` (BMP header) | block (`agent_bidi_source`) | **clean** | block |
| `polyglot.txt` (BMP header, short) | advisory (`filetype_mismatch_unknown`) | advisory (`filetype_mismatch_bmp`) | advisory, as `main` |
| `polyglot.bmp` (the PHP, named `.bmp`) | advisory (bidi notes) | clean | clean |

The revision requires the name as well as the bytes, because the name decides how a reader
opens the file. Under any other suffix, a raster header leaves every check as it is on `main`.
`test_raster_samples_are_not_base64_but_an_encoded_executable_is` now includes the `.py` and
`.php` polyglots. It fails on `90a95bc` and passes on `92e6f12`.

## What still applies, and what is given up

| Control | `main` | Head |
| --- | --- | --- |
| C1/C2: `.txt` starting `BMW owners:` / `II* notes`, then an injection phrase | block (phrase) | unchanged |
| C9: a `.txt` holding only `BM` | clean | clean |
| C3/C4: `.txt`/`.md` with a real BMP header, then injection text | block (phrase @raw, @text-folded) | unchanged |
| C5: BMP whose pixels hold a base64 PE | block (blob + executable) | block (`agent_base64_executable`) |
| C6: BMP whose pixels hold base64 of `SECURITY.md` | block (blob) | clean (given up) |
| C7: `.bmp` with a real header, then injection text | block (phrase @raw, @text-folded) | block (phrase @raw); derived views no longer run (given up) |
| C8: DOCX with an injection sentence in `document.xml` and a BMP image | block | block (phrase @raw, @text-folded) |

Given up, on purpose, only for a file named as an image with that image's header:

- **Base64 in pixel bytes.** A reader shown an image does not see its sample bytes as text.
- **Derived views and the Unicode-control notes.** The raw-view rules, executable checks, and
  installed signatures still read it. `polyglot.bmp` (PHP inside a `.bmp`) loses its bidi
  notes. `agent_bidi_source` never applied to a `.bmp` on `main` either. A webshell that relies
  on a server including an uploaded image is left to the installed signatures, as before.

## Verification

- **Unchanged elsewhere**, against `main` `72cb0f4`: 45 DOCX files without BMP or TIFF members
  (the 14 images as PNG, JPEG, and GIF; LibreOffice exports of `README.md` and `docs/rules.md`; a
  README build with a screenshot) × 3 policies, 135 scans; and the 114-PDF corpus from #137's
  record × 3 policies, 342 scans. All identical. Of the 5 polyglots × 3 policies, only
  `polyglot.bmp` differs, as in the table above.
- At `92e6f12`, all 28 raster DOCX files (84 scans) and all 14 bare BMP/TIFF/EMF/WMF files are
  clean.

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check . && uv run ruff format --check .
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_filetype.py tests/test_scanner.py tests/test_text_fast_paths.py tests/test_heuristics.py
```

- Probe at `92e6f12`: passed, 0 failures; 531 library, 55 CLI, and 109 benign observations; 3
  failure paths.
- Rule pairs: passed (105 rules).
- Precision: 310 files, 0 incomplete, exit 0; the per-rule table is identical to `72cb0f4`'s.
- Ruff (whole tree), format, strict mypy, and the text control check: clean.
- Tests: 213 passed in the four files. The broad pytest and selftest suites are left to hosted
  CI.

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
