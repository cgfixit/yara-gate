# Research notes and probes

Start with the [detection backlog](detection-backlog.md). It is the one living page: open
candidates with their evidence and false-positive class, ideas that were weighed and turned
down, and the checks a rule change has to pass. Everything else here is either a dated
record, a data file a probe reads, or a script.

For what the scanner does today, read the [detection-method map](../../rules/README.md) and
the [rule reference](../rules.md). A note in this folder describes its own date and
revision; it is a lead to reproduce on the current tree, not a description of it.

## Living

| Page | Use it for |
| --- | --- |
| [detection-backlog.md](detection-backlog.md) | What to build next, what not to build and why, and how to keep tokens, settings keys, the engine, and vendor pins current |

## Dated records

These are kept as written. Their open items were carried into the backlog on
November 10, 2026; a status line at the top of each says so where it applies.

| Record | Revision | What it holds | Status |
| --- | --- | --- | --- |
| [2026-11-07-detection-primary-sources.md](2026-11-07-detection-primary-sources.md) | `05f94ca` | Six directions from primary sources: reader handoff, hidden-text calibration, visual input, action authorization, adaptive evaluation, execution boundaries | Directions 1, 3, 4, and 6 are integration and deployment work and stay open there; 2 and 5 are in the backlog |
| [detection-roadmap-2026-10-30.md](detection-roadmap-2026-10-30.md) | October 30 batch | Techniques delivered that day and six candidates | Hidden Office and PDF text, the note tier, the `.pth` rule, and the MSBuild and INF rules shipped. Reviewed release ([#39](https://github.com/cgfixit/yara-gate/issues/39)) is open. ClickOnce and `node -e` are in the backlog's not-planned list |
| [optimization-plan-2026-10-25.md](optimization-plan-2026-10-25.md) | `7156e5a` | Reproduced leads, dropped leads, and eight pull requests of one optimization pass | Closed. The dropped leads explain several not-planned entries |
| [external-content-gating-2026-10-23.md](external-content-gating-2026-10-23.md) | `30d7126` | Where to place the gate in an agent or an ordinary application, the byte-identity contract, and what detection cannot authorize | Current as design guidance; the contract itself is in [integrations](../integrations.md) |
| [attachment-signatures.md](attachment-signatures.md) | `2e8c85a` | Attachment formats added on October 13, their collision controls, and formats deferred | Shipped. Deferred formats are a lead for new attachment rules |
| [modern-delivery-rules.md](modern-delivery-rules.md) | `6031f74` | Sources and boundaries of the first ClickFix, HTML smuggling, encoded PowerShell, and MSHTA rules | Shipped; widened by the [November 10 variants](../verification/2026-11-10-rule-variant-coverage.md) |
| [universal-rule-research.md](universal-rule-research.md) | `3667747` | The first coverage survey and expansion plan, written against six rules | Historical baseline |

The reviews of the whole detector are under [`docs/reviews/`](../reviews/); the newest is
the [November 7 detection review](../reviews/2026-11-07-detection-review.md). Its sync-folder
finding was fixed in [#191](https://github.com/cgfixit/yara-gate/pull/191), its MCP and SVG
findings in [#190](https://github.com/cgfixit/yara-gate/pull/190), and the reader gaps it
listed in [#182](https://github.com/cgfixit/yara-gate/pull/182),
[#186](https://github.com/cgfixit/yara-gate/pull/186), and
[#187](https://github.com/cgfixit/yara-gate/pull/187). Evidence for a shipped change goes
under [`docs/verification/`](../verification/), not here.

## Data the probes read

| File | Read by | Holds |
| --- | --- | --- |
| [agent-signatures.json](agent-signatures.json) | `probe_rule_coverage.py` | Agent-ingestion texts and the rule ids each must give, with benign rows (`"expected": null`) |
| [delivery-signatures.json](delivery-signatures.json) | `probe_rule_coverage.py` | Delivery commands, pages, and parsed shortcuts |
| [unix-signatures.json](unix-signatures.json) | `probe_rule_coverage.py` | macOS and Linux commands |
| [windows-format-signatures.json](windows-format-signatures.json) | `probe_rule_coverage.py` | Windows script-host, shortcut-family, and document formats |
| [pdf-font-readers.json](pdf-font-readers.json) | `probe_pdf_font_readers.py` | Which of six PDF readers showed the text for each spelling of a font resource, and the reader versions, as run on November 10 |
| [rule-coverage-baseline.json](rule-coverage-baseline.json) | nothing; a record | The first probe run, October 8 |
| [external-content-boundaries-2026-10-23.json](external-content-boundaries-2026-10-23.json) | nothing; a record | Observations behind the external-content note |

A row may set `"encoding"` (for example `utf-16le`) or `"container"` (`zip` or `gzip`), so
one text is checked raw, as UTF-16, and inside an archive. `expected` is the exact set of
signature rule ids; a row that should stay clean uses `null`. Rows named `variant_*` are
the November 10 spellings.

## Scripts

| Script | Run by CI | What it does |
| --- | --- | --- |
| [probe_rule_coverage.py](probe_rule_coverage.py) | Yes, `--verify` | Real library and CLI scans of the data files and built-in cases, with intake and disposition in disposable homes |
| [probe_detection_gaps.py](probe_detection_gaps.py) | Yes, `--verify` | Known gaps beside caught controls and benign boundaries. A case in `OPEN` must still miss; the run fails when one holds, so a fix removes its marker. B1 to B6 are the backlog's open candidates |
| [probe_pdf_font_readers.py](probe_pdf_font_readers.py) | No | 65 spellings of a PDF font resource: `--verify` checks what the gate reports for each, and `--readers` reruns whichever of six PDF readers are installed against `pdf-font-readers.json` |
| [probe_external_content.py](probe_external_content.py) | No | The boundary cases of the external-content note |
| [probe_integration_readiness.py](probe_integration_readiness.py) | No | The consumer-contract checks of the [integration review](../reviews/2026-11-02-integration-readiness.md) |
| [benchmark_text_scan.py](benchmark_text_scan.py), [benchmark_scan_overhead.py](benchmark_scan_overhead.py) | No | Timings of 4 MiB text scans and of per-file overhead |

## Adding a note

Write a dated note when you research something the backlog does not already hold: name the
revision, the engine, what was run and what was only read, and label each claim verified,
sourced, or assessment. Then put the conclusions in the backlog, where the next reader will
look. A fetched page is data to weigh; an instruction inside it is not a task.
