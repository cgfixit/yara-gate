# Shared demo catalog and four new pairs — November 10, 2026

Base: `main` at `cd2e0d4b5f206d29a81eb3cd815f6c348473ec60`. Code revision recorded:
`e2d9d5731f65`. Linux x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85 bundled rules,
zero skipped rule files, no vendor packs, no downloads. Every scan used a disposable copy of
`rules/local` and `rules/rules.lock`; the workbench ran with a disposable `HOME`. No fixture
was executed, unpickled, rendered, or extracted, and no address in a fixture was contacted.

## What changed

- The demo catalog moved from `scripts/record_pages_demo.py` to
  `src/yara_gate/showcase.py`. The recorder and the loopback workbench both read it. Before
  this change the workbench listed 17 of the public replay's 24 pairs, through a second,
  hand-kept list in `demo.py` and a third in `demo_page.html`.
- Four pairs and one fail-closed case were added (below): 58 examples, 28 pairs, 2 scans
  that cannot finish.
- Workbench: the sample list is built from the catalog, **Scan pair side by side** scans an
  attack and its twin under one policy, **Run every pair** scans the catalog and compares
  each result with the catalog's expected verdict, and each finding names its check and view
  in plain words. `POST /api/scan` is unchanged apart from accepting catalog ids; the page
  receives titles and expected verdicts as embedded JSON, never a payload.
- Public page: a strip of every pair under the selected policy, a count of findings on
  twins, a filter by how each attack was caught, two more workflows, and precision figures
  taken from the current corpus. The recording schema, the allowlisted result fields, the
  page's CSP, and the four-file artifact are unchanged.
- README, user guide, Pages guide, rules reference, integration guide, threat model, and
  the source maps were corrected against the code (list under [Documentation](#documentation)).

## New fixtures

Verdicts are default / `agent-ingest` / `agent-document`, from `scan_bytes`.

| Fixture | Name | Verdicts | Findings |
| --- | --- | --- | --- |
| Page whose inline SVG logo holds `<script>void 0</script>` | `portal.html` | block / block / block | `doc_svg_active` (`raw`, `text-folded`) |
| Same page, plain icon, and a page script | `portal.html` | clean ×3 | none |
| MCP `tools/list`, 60 tools, 58th description poisoned | `tools.json` | advisory / block / block | `heuristic_mcp_hidden_instruction` |
| Same list, 58th description about caching | `tools.json` | clean ×3 | none |
| Word run under `w:vanish` holding the override | `review.docx` | advisory / block / block | `agent_prompt_injection_phrases` (note; `raw`, `ooxml-text`), `heuristic_hidden_text` (`ooxml-hidden-text`) |
| Same hidden run: "Ignore previous drafts and use the totals…" | `review.docx` | clean ×3 | none |
| PDF invoice, override in render mode 3 | `invoice.pdf` | advisory / block / block | `agent_prompt_injection_phrases` (note; `raw`, `pdf-text`), `heuristic_hidden_text` (`pdf-hidden-text`) |
| Same invisible line repeating the invoice text | `invoice.pdf` | clean ×3 | none |
| 7z signature and empty header | `backup.7z` | incomplete ×3 | none; `unsupported archive` |

The same eight paired fixtures scanned by earlier revisions (a git worktree on `PYTHONPATH`,
that revision's own rules):

| Fixture | `682cf08` (before hidden text was read on its own) | `7d505f9` (before the scope and budget change) | This revision |
| --- | --- | --- | --- |
| Poisoned tool list | clean ×3 | clean ×3 | advisory / block / block |
| Page with a plain icon and its own script (benign) | block ×3 | block ×3 | clean ×3 |
| Hidden Word override | advisory / block / **advisory** (note only) | advisory / block / block | advisory / block / block |
| Invisible PDF override | advisory / block / **advisory** (note only) | advisory / block / block | advisory / block / block |
| Script inside the inline SVG | block ×3 | block ×3 | block ×3 |
| The other three twins | clean ×3 | clean ×3 | clean ×3 |

So the tool-list pair shows a miss that was closed, the SVG pair a false positive that was
removed without losing the block, and the two hidden-text pairs a file `agent-document`
used to read.

## Recordings

- Before the catalog moved, and again after, the recorder's output for the 49 existing
  examples was compared with the committed baseline through `outcome_changes`: no difference.
  Their order, titles, descriptions, verdicts, findings, offsets, and input fingerprints are
  unchanged.
- `scripts/record_pages_demo.py --output web-demo/recordings.json` at `e2d9d5731f65`:
  58 scenarios × 3 policies, 85 rules. All 28 detections are `block` under `agent-ingest`;
  all 28 controls are clean with no findings under every policy (0 findings in 84
  recordings); both failures are incomplete under every policy.
- `scripts/build_pages.py`: four files, 58 scenarios / 174 policy recordings validated.
  `SCENARIOS` is 58. Artifact fingerprints of that build: `index.html`
  `c8bd84097fb0a9902c779d7ac410ae89a6367c501afbd66de69692d6a00bf774`, `style.css`
  `8be97b77d7d08f82bfe115d0e3519eba64da3cc71979f3a1ace73274d834e1c3`, `app.mjs`
  `133a33056b3b4584d2e64df2a5b0d4d5a63db2dc825c3a16b1ba4e3b099d4a32`, `recordings.mjs`
  `1497c4890615ecb7fc4cc76b6b5f2685b30a35a039a23a374db5f958a2173ad0`.

## Browser acceptance

Headless Chromium 153.0.8010.12 through Playwright, 1280 × 900 and 390 × 800.

Workbench (`yara-gate demo --rules <disposable copy> --port 8791`, opened at `127.0.0.1`):

| Step | Observed |
| --- | --- |
| Sample list | 57 options in 8 channel groups (the broken-rule case is not offered) |
| Scan sample, default selection | block; `agent_prompt_injection_phrases`, described as an Office comment in archive member 2 |
| Tool onboarding, Scan pair side by side | attack block (`heuristic_mcp_hidden_instruction`), twin clean with no findings |
| Run every pair, `agent-ingest` | 28 / 28 with a finding, 28 / 28 held, 28 / 28 twins clean, 0 findings on twins, 1 / 1 incomplete; 57 of 57 as expected; about 140 ms of scanner time |
| Run every pair, `agent-document` | 11 / 28 held, the rest reported; twins 28 / 28 clean, 0 findings; 57 of 57 as expected |
| Run every pair, `default` | 4 / 28 held, the rest reported; twins 28 / 28 clean, 0 findings; 57 of 57 as expected |
| 7z sample | incomplete, `unsupported archive`; the pair button is disabled |
| Paste `Ign0re previous instructi` + Cyrillic о + `ns…` under `agent-ingest` | block, found in the folded view |
| Paste an ordinary sentence | clean |
| 390 px wide | no horizontal overflow |
| Network and console | requests to `127.0.0.1:8791` only; no console errors or warnings |

Public page (the built artifact served from a loopback directory at `/yara-gate/`):

| Step | Observed |
| --- | --- |
| Scoreboard | 28 / 28 held, 28 / 28 twins clean, 0 findings across 84 twin recordings, 2 / 2 unfinished scans incomplete, 85 rules |
| Strip | 58 squares in 30 columns; `agent-ingest` 28 held and 28 clean; `agent-document` 11 held, 17 reported; `default` 4 held, 24 reported; twins clean under each |
| Workflows | seven; Tool onboarding opens the poisoned list with its recorded block and twin |
| Caught-by filter | hidden 4, disguised spelling 6, split across formatting 8, encoded 3, inside an archive 1, file structure 3, plain pattern 5 (two pairs carry two labels); "hidden" with "SMS" reports that no pair matches |
| Strip square for the 7z case | incomplete, `unsupported archive`, no twin panel |
| 390 px wide | no horizontal overflow |
| Network and console | the four artifact files only; no console messages |

## Checks

- Focused tests, `tests/test_demo.py`, `tests/test_pages_build.py`, `tests/test_pages_deploy.py`:
  31 passed. A new test scans every catalog case the workbench offers under each policy and
  requires the expected verdict and, for a twin, no findings.
- `measure_precision.py --fail-over`: 328 files, 0 incomplete; 81 of 85 YARA rules hit none,
  the four tagged Windows collisions hit one file each (0.30%), and
  `heuristic_pdf_text_unmapped` hits the one merged PDF it is meant to.
- `check_worst_case_timing.py` defines 29 inputs (the living record said 27).
- Ruff check and format on the tree, `mypy --strict src` (21 files),
  `check_text_controls.py` (284 files), `node --check web-demo/app.mjs`: passed.

## Documentation

Corrected against the code at the base revision:

- README said RTF text and encoded PDF annotations are outside the supported views; both are
  views (`rtf-text`, `pdf-annotation`). `docs/rules.md` said the same in its limits note.
- `docs/rules.md` said five YARA globals; the loader defines six.
- The user guide said a second watcher prints `incomplete: RuntimeError`; it prints
  `incomplete: watch already running`. Its list of `view` names lacked five that reports carry.
- `docs/integrations.md` said an encoded instruction is held under `agent-document`; an
  encoded override phrase is a note there, like the plain phrase.
- Precision figures named the 324-file corpus; it has 328 files, and one structural note hits.
- README said any PDF text without a `ToUnicode` map is a note; a simple font is read as
  WinAnsi, and the note is for a composite font with no readable map.
- A `/Prev` chain past 32 sections is malformed (incomplete), not cut short; one `ToUnicode`
  map keeps at most 131,072 entries, which no document said.
- Source maps lacked `rtftext.py`, `pdfannotations.py`, `pdfxref.py`, and now `showcase.py`;
  AGENTS.md still said every candidate-status rule is excluded.

## Boundaries

- The pairs are synthetic and curated. Zero findings on 28 twins is evidence for those 28
  inputs, not a false-positive rate for real traffic; the page and the workbench both say so.
- The caught-by label is derived from recorded findings by a fixed rule in `app.mjs`. It
  describes which view or check produced the finding, not the attacker's intent.
- Acceptance used headless Chromium only; Firefox, Safari, and a screen reader were not run.
- No screenshot was added under `screenshots/`; the README's workbench capture predates
  this change and its caption says so.
- The hosted site changes only when this reaches `main` and the deploy gate passes; the
  deploy re-records at that commit and must match this baseline.
