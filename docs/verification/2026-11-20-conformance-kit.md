# Conformance kit: `yara-gate conform`

Date: 2026-11-20. Base: `main` at `353746b`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container with 4 cores. Rules: the shipped `rules/local` (89 rules), no vendor packs.
Issue: [#227](https://github.com/cgfixit/yara-gate/issues/227), with the owner decisions of
2026-11-16 recorded there. Everything below is a direct run on this container unless it says
otherwise.

## What changed

- `yara-gate conform` and `yara_gate.conform`: the kit described in the
  [guide](../conformance.md). Fixtures are built from the installed package, checked against
  the packaged manifest, and scanned under three policies with the bundled rules alone.
- `src/yara_gate/conformance.json`: the generated manifest (92 fixtures, 276 expectations),
  written by `scripts/build_conformance.py`.
- `--export` and `--agreement`: a consumer's extracted text beside the file scan, through
  the replay core of [#293](https://github.com/cgfixit/yara-gate/pull/293).
- `samples.pdf_unread_content` and `samples.pdf_read_content`: the kit's own PDF pair.
- A `Conformance kit` step in the macOS and the Windows CI jobs.

No rule, reader, heuristic, severity, verdict, or report field changed. `scan`, `watch`,
`scan_bytes`, `replay`, and the demo catalog are untouched; the Pages recordings were not
regenerated.

## How the owner decisions were applied

| Decision | In this change |
| --- | --- |
| A CLI command generates the fixtures; the pinned package is the kit version | `conform` builds them from `showcase.py` and `samples.py`; no attack bytes are committed. The manifest ships in the wheel |
| Hard on verdict and exit, diff on ids | `mismatch` fails with exit 1; `difference` (rule ids, views, the unread count) is printed and exits 0 |
| Bundled rules gate; vendor is optional and never gates | The gating pass loads a disposable copy of the shipped local rules. An `installed` section runs only when the tree records a vendor inventory, and cannot change the exit code |
| Vendor expectations keyed to the `rules.lock` pin | **Not built.** No vendor pack was installed for this change, so no vendor expectation exists to ship. The installed section compares with the bundled expectations and prints the tree's `ruleset_sha256` |
| Agreement mode reuses the replay core | Capture lines are parsed and scanned by `replay.replay_capture`; decisions are `replay.proposed_decision` |
| A manifest change needs a changelog entry | A test fails a manifest whose SHA-256 has no row under Changes in the guide |

Two choices here are mine: the kit takes the whole catalog (90 of its 91 cases; the
broken-rule case needs a deliberately broken tree) instead of a hand-picked subset, so there
is no second list to keep; and a run stops at the first scan that is incomplete where an
answer is recorded.

## The plain run

| Run | Result |
| --- | --- |
| Checkout, compiled rules cached | exit 0, 92 fixtures, 276 checks, 0 mismatches, 0 differences, 1.4 s |
| Checkout, empty cache | exit 0, 2.8 s |
| A wheel built from this tree, installed in a new environment, run from another directory | exit 0, the same manifest SHA-256. That environment resolved YARA-X 1.24.0, so the 276 verdicts also hold on the next engine release |
| `scripts/build_conformance.py --check` | current |
| Manifest rebuilt with [#310](https://github.com/cgfixit/yara-gate/pull/310) merged in a scratch worktree | byte-identical: that change moves offsets, which the manifest does not record |

## What fails it, and how

Each row was run through the CLI.

| Case | Exit | Output |
| --- | --- | --- |
| A bundled rule that blocks the benign note | 1 | three `mismatch` records for `plain`, expected `clean`/0, observed `block`/1, `rule_ids_added` naming the rule |
| A second advisory rule on a fixture that is already advisory | 0 | `difference` records only; `result: "pass"` |
| A rule file that does not compile | 2 | one `mismatch` with `local rule compile failed`, then `result: "incomplete"`. The pass stops at that scan |
| No bundled rules | 2 | `incomplete: bundled rules missing` |
| A fixture that builds one more byte; a fixture missing from the build | 2 | `incomplete: fixture changed: plain`; `fixture list changed: …` |
| A manifest that is empty, not an object, or another schema version | 2 | `incomplete: manifest …` |
| A vendor rule that blocks the benign note, without and with a recorded inventory | 0 and 0 | no section; then three `mismatch` records under `"section": "installed"` and `result: "pass"` |
| `--export` into a directory that is not empty | 2 | `incomplete: export directory is not empty` |
| An agreement line for an unknown fixture, one whose `original_sha256` is not the fixture's, one that is not JSON | 2 | three `failed` records with the reason; the valid line after them is still compared |

No record in any of these runs holds fixture text.

## Agreement with two real readers

`yara-gate conform --export` wrote 92 files. [`conform_agreement.py`](../examples/conform_agreement.py)
read the 14 PDFs with `pdftotext` (poppler) and the 13 HTML pages with a text-node reader
that drops `script`, `style`, `template`, and elements carrying `hidden`, and never reads
`style`. That is the shape of the CG-agent-harness extractor as described on #227; it is a
stand-in, not that code. The 27 lines were compared under `agent-document`.

| Result | Lines |
| --- | ---: |
| `same` | 18 |
| `file-holds-only` | 5 |
| `findings-differ` | 4 |
| `extraction-holds-only`, `failed` | 0 |

| Fixture | Reader | File | Extraction |
| --- | --- | --- | --- |
| `hidden_html` | text nodes | block, `agent_hidden_html` | advisory: the order is kept as visible text and reads as a quoted note |
| `html_white_override` | text nodes | block, `heuristic_hidden_text` | advisory, for the same reason |
| `html_data_override` | text nodes | block | clean: the `data-*` value is not a text node |
| `html_svg_script` | text nodes | block, `doc_svg_active` | clean: the script is dropped |
| `pdf_invisible_override` | poppler | block, `heuristic_hidden_text` | advisory: invisible text is extracted as ordinary text |
| `pdf_glyph`, `pdf_glyph_folded`, `pdf_annotation_override` | poppler | advisory | clean: poppler printed no order for these files |
| `kit_pdf_unread` | poppler | advisory, `heuristic_pdf_content_unread` | clean |

The first two rows are the divergence #227 was opened for: a reader that keeps hidden text
and drops the markup hands its model an instruction the gate would have held, and a scan of
the extraction alone admits it under `agent-document`. Two runs over the same capture
printed the same bytes (one SHA-256), and the run took 8 s for 27 child scans.

## The live workbench, in a browser

`samples.py` gained two builders, so the demo was driven once to show nothing else moved:
`yara-gate demo --rules <disposable copy> --port 8793` with Playwright and Chromium, **Run
every pair** under `agent-ingest`: "90 of 90 results as expected, 0 finding(s) on benign
twins", no console errors.

## Other checks

- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts`: clean.
- `actionlint` v1.7.12 and `zizmor --offline --pedantic .github`: no findings.
- `check_doc_links.py`, `check_text_controls.py`: pass.
- `yara-gate selftest`: pass.
- `pytest tests/test_conform.py tests/test_cli.py`: 22 passed, 1 skipped. The 14 kit tests
  are in `tests/test_conform.py`.

## What the first hosted run found

The first Windows run of the new step stopped with `incomplete: fixture changed: word_split`
(head `6ad2048`). `samples._stored_zip` built each entry with `zipfile.ZipInfo`, which
records the system that wrote it from `sys.platform`: 0 on Windows, 3 elsewhere. Every
fixture made from a zip (the Office files, the checkpoints, the archives) therefore had
another SHA-256 on Windows, although a comment beside the builder said the bytes were the
same on every machine. The builder now pins that field to 3, which is what Linux and macOS
already wrote, so no recorded hash moved and the manifest is unchanged. A test builds two
zip fixtures with `sys.platform` set to `win32` and fails on the old builder. This is the
drift the owner named on #227 as the main risk of generating fixtures, and the step caught
it on its first run.

## Limits

- **Linux is covered by this run only.** Hosted CI has macOS and Windows jobs and no Linux
  job. The manifest was generated here on Linux; the two hosted jobs are what show the same
  bytes and verdicts elsewhere, and they had not run when this was written.
- The vendor section was exercised with one synthetic vendor rule and a hand-written
  inventory. No real pack was installed.
- The Harness CI step, and a capture from the real Harness extractor, are Harness work.
- The fixtures are the demo catalog: synthetic, written beside the rules. A passing kit says
  the gate still answers these inputs as recorded. It is not a detection rate.
