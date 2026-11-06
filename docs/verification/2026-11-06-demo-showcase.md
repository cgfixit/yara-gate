# Demo showcase: attacks beside benign twins (2026-11-06)

## What changed

The public Pages demo and the local workbench now show the detections added in
#158–#162 next to a benign near-twin of the same shape, so a visitor sees both what
is held and what still passes.

- `src/yara_gate/samples.py` gains four inert attacks and their twins. Zip entries are
  stored with a fixed timestamp and PDF streams are uncompressed, so the bytes and their
  SHA-256 are the same on every machine. The pickle is assembled by hand, because
  `pickle.dumps` would record `posix` or `nt`.
- `scripts/record_pages_demo.py` records 17 scenarios (schema 2). Each has a `kind`
  (`detection`, `control`, or `failure`), a `channel`, and a `pair`.
- `scripts/build_pages.py` enforces what each kind claims: a control is clean with no
  findings under every policy, a detection is held by `agent-ingest`, the failure is
  incomplete, and a pair joins one detection and one control that name each other.
- `web-demo/` computes its scoreboard from the recordings, groups the gallery by kind,
  sets each attack beside its twin under the selected policy, and names the check,
  archive member, and derived view behind each finding. A static section summarizes the
  measured false-positive evidence.
- `yara-gate demo` offers the same eight samples, grouped as attacks and twins.
- The README, user guide, and Pages guide describe the demos; the README now names
  YARA-X 1.23.0, and `docs/rules.md` describes the reader the pickle walker uses since
  #158 instead of `pickletools.genops`.

## Fixtures

Scanned in memory with `scan_bytes` and a disposable copy of the bundled rules (84 rules,
no vendor packs), Python 3.12.3, YARA-X 1.23.0. Verdicts are default / agent-ingest /
agent-document.

| Scenario | Name | This branch | `main` at `7f9934c` (agent-ingest) |
| --- | --- | --- | --- |
| Base64 field in a tool result | `tool-result.json` | advisory / block / advisory; `agent_override_imperative` (note) in `base64-decoded` | clean |
| Twin: ordinary base64 (JWT, PNG data URI, sentence) | `tool-result.json` | clean / clean / clean | clean |
| Glyph-id PDF, bold word | `checklist.pdf` | advisory / block / advisory; `agent_override_imperative` (note) in `pdf-paragraph` | clean |
| Twin: same PDF, ordinary sentence | `checklist.pdf` | clean / clean / clean | clean |
| Pickle checkpoint calling `os.system` | `model.pt` | block / block / block; `heuristic_pickle_reduce` at `zip:0` | clean |
| Twin: checkpoint via `collections.OrderedDict` | `model.pt` | clean / clean / clean | clean |
| Dev container downloading on the host | `devcontainer.json` | advisory / block / block; `dev_devcontainer_lifecycle` | clean |
| Twin: host `mkdir`, installs in the container | `devcontainer.json` | clean / clean / clean | clean |

Each attack was a silent miss before #158–#162, and each twin is clean on both
revisions. The nine scenarios carried over from the schema 1 dataset kept identical
results apart from provenance (82 rules on YARA-X 1.22.1 before, 84 on 1.23.0 now).

## Checks

Branch `docs/sync-demo-showcase` from `main` at `16fcf21`; recordings captured at
`5059d03`.

- `record_pages_demo.py` asserted all 51 expected verdicts and wrote the recordings;
  `build_pages.py` validated 17 scenarios / 51 policy recordings and built four files:

  | File | SHA-256 |
  | --- | --- |
  | `index.html` | `a4360a6e528c061fd9a85860f05099e9e0b135eb58a42f770ccbd8c72f49e847` |
  | `style.css` | `445b32c7048699e95617223708d24416f6b91caa9ece483b74792ae38ea859d0` |
  | `app.mjs` | `adfa6854d9f4efc689600439cea8250a4e068a679054071565596b02eeeec3b1` |
  | `recordings.mjs` | `e39682526b3ad931cfe3a21056f271e78e13784f8b25c794142838c7e36b6dd2` (this capture; each deploy refreshes provenance) |

- `node --check` passed on both scripts.
- **Pages, real browser** (Playwright Chromium against the built artifact on
  `127.0.0.1`): every card under every policy (51 combinations) showed the recorded
  verdict and finding ids; the twin panel appeared exactly for paired scenarios, and its
  button switched to the twin. The scoreboard read 11/11 attacks held, 5/5 twins clean,
  1/1 failure held, 84 rules. No console errors, page errors, or requests outside the
  page's own origin. An iPhone 13 viewport had no horizontal overflow.
- **Workbench, real browser** (`yara-gate demo --rules <disposable copy>`, agent-ingest):
  each of the 13 samples returned its expected verdict; the four attacks were held by
  their intended rule and the four twins were clean. No page errors.
- `tests/test_pages_build.py` gains tests that a twin with a finding, a detection that
  `agent-ingest` lets through, and a broken pair are refused; `tests/test_demo.py` checks
  the four attacks and their twins under every policy through the HTTP server.
- `ruff check`, `ruff format --check`, `mypy --strict src`, `lint_rules.py`,
  `check_rules_lock.py`, `check_rule_pairs.py`, `check_added_rules.py`,
  `check_text_controls.py`, `check_scan_only.py`, `check_intake.py`,
  `measure_precision.py --fail-over`, `probe_rule_coverage.py --verify`, selftest, and
  the full pytest suite in one run (420 passed, 5 skipped) pass.

## Limits

- The twins show that these specific near-misses stay clean. They and the precision
  figures on the page (the 324-file generated corpus, 132 third-party test PDFs, 65
  joblib pickles, 112 published `devcontainer.json` files) are not a production
  false-positive rate; no operator upload traffic was measured.
- Screenshots were taken for review only and are not committed.
- The root `demo.html` stays a limited JavaScript illustration; it now points to the two
  demos that show these detections.
