# Demo update: every attack beside a benign twin, with the #167–#169 detections (2026-11-06)

## What changed

The public Pages demo and the local workbench now show the evasions #167–#169 closed, and
every recorded attack has a benign near-twin of the same channel and shape.

- `src/yara_gate/samples.py` gains six inert attacks and their twins: a zip holding an
  override followed by an ordinary invoice zip; a coloured CI log with a bold escape glued
  to the override's first word; an override split by a `<b>` tag; an Excel inline-string
  cell split across two rich-text runs with a zero for an `o`; an SVG animation with an
  `onbegin` handler (`void 0`); and a source file whose emoji is followed by the override as
  variation selectors. Zips are stored with a fixed timestamp, so the bytes are the same on
  every machine. Control and invisible characters are built from escapes, so no tracked file
  carries them. The Word run fixture moved from the recorder into `samples.py` with
  identical bytes.
- `scripts/record_pages_demo.py` records 35 scenarios: 17 attacks, 17 twins, and the
  failure. The six attacks that had no twin gained one: an ordinary Russian SMS, a request
  to send a README summary to a link, an HTML character reference in ordinary text, menu
  labels in a hidden block, a Word file with an ordinary bold word, and a one-page PDF.
- `scripts/build_pages.py` expects 35 scenarios and requires every detection and control to
  name a pair, so the page's claim that every attack has a twin is checked at build time.
- `web-demo/` shows one row per attack and its twin, filtered by channel, and names the new
  derived views (`html-text`, `ooxml-cell`, `format-controls-removed`, and any
  `<view>+text-folded`). The precision section now reads 81 of 85 rules and adds the host
  sweeps from the [detection-gaps record](2026-11-06-detection-gaps.md).
- `yara-gate demo` offers the six new pairs in its "Attack and its benign twin" group.
- The README, user guide, and Pages guide give the new counts and examples; the user guide's
  shipped-rule count is now 85.

## Fixtures

Scanned in memory with `scan_bytes` against a disposable copy of the bundled rules (85 rules,
no vendor packs), Python 3.12.3, YARA-X 1.23.0. Verdicts are default / agent-ingest /
agent-document. The last column is the same bytes under `agent-ingest` at `4b5b949`, before
#167, with that revision's 84 rules.

| Scenario | Name | This branch | `4b5b949` |
| --- | --- | --- | --- |
| Zip with the override, then an invoice zip | `invoice.zip` | advisory / block / advisory; `agent_prompt_injection_phrases` (note) in `zip:1`, raw | clean |
| Twin: receipt zip, then the invoice zip | `invoice.zip` | clean / clean / clean | clean |
| CI log, bold escape glued to the override | `build.log` | advisory / block / advisory; `agent_prompt_injection_phrases` (note) in `text-folded` | clean |
| Twin: same log, ordinary bold summary | `build.log` | clean / clean / clean | clean |
| Override split by `<b>` | `release-notes.html` | advisory / block / advisory; `agent_prompt_injection_phrases` (note) in `html-text` | clean |
| Twin: bold, emphasis, and a link around ordinary words | `release-notes.html` | clean / clean / clean | clean |
| Excel cell, two runs and a zero for `o` | `totals.xlsx` | advisory / block / advisory; `agent_prompt_injection_phrases` (note) in `zip:1`, `ooxml-cell+text-folded` | clean |
| Twin: rich-text cell with a percentage and a version | `totals.xlsx` | clean / clean / clean | clean |
| SVG `onbegin` handler | `logo.svg` | advisory / block / block; `doc_svg_event_handler` (advisory) in raw and `text-folded` | clean |
| Twin: `begin="0s"` | `logo.svg` | clean / clean / clean | clean |
| Override as variation selectors after an emoji | `extension.js` | block / block / block; `heuristic_variation_selector_run` (block) | clean |
| Twin: U+2764 U+FE0F and U+845B U+E0100 | `extension.js` | clean / clean / clean | clean |

A first draft put the override in the second zip. That archive is the one `zipfile` reads,
so it would have been caught before #167 too; the member ordinal (`zip:0`) showed it. The
override now sits in the first archive, the one 7-Zip opens, and is reported at `zip:1`.

The SVG finding appears twice because the leet fold rewrites two unrelated tokens in the file
(`w3` in the namespace URL to `we`, and `dur="1s"` to `dur="is"`; the handler's `void 0` is
unchanged), so the folded view differs from the raw text and is scanned as well, and the
handler matches in both. That is the scanner's current behaviour, recorded as it is.

All 17 twins scanned clean, with no findings, under `agent-ingest` at `4b5b949`. The 17
scenarios carried over from the previous baseline recorded the same verdicts, findings,
views, and input fingerprints; only the `pair` of the six attacks that gained a twin changed.

## Checks

Branch `docs/sync-demo-detection-gaps` from `main` at `9214510`; recordings captured at
`ea184f9`.

- `record_pages_demo.py` asserted all 105 expected verdicts and wrote the recordings;
  `build_pages.py` validated 35 scenarios / 105 policy recordings and built four files:

  | File | SHA-256 |
  | --- | --- |
  | `index.html` | `80c1921c8c5569028d344dc3325828316cb4a52b4015db00bfc92b43384bb17b` |
  | `style.css` | `16e94a303f6806ef09640b0d97d79af7943443eeb63263f407bb7a16649dd7b0` |
  | `app.mjs` | `a159095d762887adbb5d181aa03163f41d9219e161438882323278c3a637beb1` |
  | `recordings.mjs` | `5fa526dc3bac5e2fab56be7be16d7020cbf02576c508752769d4a358f04d28ec` (this capture; each deploy refreshes provenance) |

- **Pages, real browser** (Playwright Chromium against the built artifact on `127.0.0.1`):
  all 105 card and policy combinations showed the recorded verdict and finding ids, and every
  finding's view had a plain-language name. The twin panel appeared for every paired
  scenario and its button opened the twin. Each of the nine channel filters showed only its
  rows. The scoreboard read 17 / 17 attacks held, 17 / 17 twins clean, 1 / 1 failure held,
  85 rules. No console errors, page errors, or requests outside the page's own origin. An
  iPhone 13 viewport had no horizontal overflow.
- **Workbench, real browser** (`yara-gate demo --rules <disposable copy>`): all 25 samples
  under all three policies. Each attack was held under `agent-ingest` by its intended rule,
  and each of the ten twins and the plain note was clean with no findings under every policy.
  No page errors.
- `measure_precision.py --fail-over`: 324 files, 81 of 85 rules at 0 files, the four
  documented shortcut collisions at one file each.
- `tests/test_pages_build.py` gains tests that an attack without a twin and a failure given a
  twin are refused; `tests/test_demo.py` checks the six new pairs with the earlier four.
- `ruff check`, `ruff format --check`, `mypy --strict src`, `check_text_controls.py`,
  `lint_rules.py`, `check_rules_lock.py`, `check_rule_pairs.py`, `check_added_rules.py`,
  `check_scan_only.py`, `check_intake.py`, `probe_rule_coverage.py --verify`,
  `probe_detection_gaps.py --verify`, and the two focused test files pass. The full suite was
  left to hosted CI.

## Limits

- The twins show that these specific near-misses stay clean. They and the precision figures
  on the page (generated, test-suite, published-package, and host files) are not a production
  false-positive rate; no operator upload traffic was measured.
- No 7-Zip, terminal, browser SVG renderer, or Excel was used to confirm what a reader
  sees; that behaviour comes from the sources cited in the detection-gaps record.
- Screenshots were taken for review only and are not committed.
