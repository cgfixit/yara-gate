# Detection methods and rule files

Start here to find a detector, its implementation, and its documented limits.
The scan is orchestrated by [`scanner.py`](../src/yara_gate/scanner.py): YARA
signatures are one layer, alongside format checks, bounded text readers, and
structural heuristics. The detailed reference is [`docs/rules.md`](../docs/rules.md).

## What lives in this directory

| Path | Purpose |
| --- | --- |
| [`local/`](local/) | 85 shipped YARA rules in 58 `.yar`/`.yara` files: 73 advisory, 6 block, 6 note. The [rule tables](../docs/rules.md#agent-ingestion-rules) link every rule to its source. |
| [`rules.lock`](rules.lock) | Pinned URLs, revisions, and SHA-256 values for YARA Forge core, signature-base, and Elastic protections-artifacts. A lock does not install the bodies. |
| [`vendor-overrides.json`](vendor-overrides.json) | Reviewed pack-and-rule exceptions to the default blocking severity of vendor matches. [Grading contract](../README.md#how-vendor-matches-are-graded). |
| `vendor/` (downloaded, untracked) | Rule bodies installed by `setup` or the network-authorized install/update commands; omitted from wheels. |
| `vendor.installed.json` (generated, untracked) | Inventory written by a successful install/update. A missing recorded file makes scans incomplete, including before cache reuse. |
| `local/hunt_<sha-prefix>.yar` (generated in the selected rules root) | Hunt output with `status = "candidate"` metadata, excluded from active scanning until explicitly promoted. [Operator workflow](../user-guide.md#6-after-you-confirm-a-file-is-bad). |

[`rules.py`](../src/yara_gate/rules.py) owns discovery, compilation, cache,
fingerprints, and vendor installation. An installed rules root loads packaged
locals first, then non-colliding user locals and vendor rules. Same-name user
locals cannot replace a bundled file. An explicit complete checkout rules tree
loads once. Local compilation errors or missing bundled rules are fatal; vendor
compile skips remain visible in scan results. The compiled cache is under the
user cache directory, not this directory.

`setup` consents to the first pinned download; `rules install --allow-network`
installs pinned packs and `rules update --allow-network` resolves new pins. Each
compiles the staged tree before swapping it into place. Scanning never downloads
or repairs vendor state. See [installation and operation](../user-guide.md) and
[network/privacy boundaries](../SECURITY.md).

## All detection layers

| Layer | What it checks | Implementation and detailed reference |
| --- | --- | --- |
| Local YARA signatures | Agent instructions and obfuscations; Windows delivery, shortcut, script-host and defense-evasion shapes; macOS/Linux commands; developer workspace and GitHub Actions configuration; active documents and disk images. | [`local/`](local/), [all rule families and benign boundaries](../docs/rules.md). |
| Vendor YARA signatures | Patterns in the installed pinned packs, subject to compile skips and the reviewed severity overrides. | [`rules.py`](../src/yara_gate/rules.py), [dated vendor census](../docs/verification/2026-11-01-ecosystem-rules.md). |
| Names and file types | Header/extension disagreement, decoy double extensions, filename controls, empty promised documents, validated raster headers. Executable disguises block; other mismatches are advisory. Raster classification also prevents pixel bytes from masquerading as text indicators. | [`filetype.py`](../src/yara_gate/filetype.py), [`scanner.py`](../src/yara_gate/scanner.py), [structural checks](../docs/rules.md#structural-checks-without-yara). |
| Container coverage | In-memory ZIP (including concatenated/appended ZIPs), tar, gzip, xz, bzip2, ar, cpio, and MIME members. Invalid member paths, links, encryption, unsupported containers, or exhausted budgets produce incomplete scans. | [`content.py`](../src/yara_gate/content.py), [limits](../docs/rules.md#limits). |
| Decoding and spelling views | UTF-16, HTML entities, JSON escapes, MIME headers, readable base64/percent runs, removed formatting controls, NFKC, mixed-script look-alikes, Latin small capitals, Cyrillic-only word case, leet, letter spacing, terminal escapes, and hyphenated line wraps. These expose text to existing rules; they do not assign a new severity by themselves. | [`content.py`](../src/yara_gate/content.py), [derived views and exclusions](../docs/rules.md#limits). |
| Reader text | Joined Office runs, worksheet cells and Excel/PowerPoint comments, SVG text and HTML blocks, Markdown paragraphs/items, adjacent source-comment lines, and Jupyter cell source/output lines. Each supported piece is scanned separately where the reader exposes piece boundaries. | [`content.py`](../src/yara_gate/content.py), [`scanner.py`](../src/yara_gate/scanner.py), [reader scope](../docs/rules.md#limits). |
| PDF streams and text | Bounded stream decoding and object lookup, glyph decoding through font `ToUnicode` maps, text-block and paragraph views with spelling-folded companions, and a note for unreadable font text. No page rendering or OCR. | [`content.py`](../src/yara_gate/content.py), [`pdftext.py`](../src/yara_gate/pdftext.py), [PDF consumer limits](../docs/integrations.md#pdfs-and-other-compressed-documents). |
| Hidden text | Text a reader does not show, read on its own: Word runs marked `vanish` or `webHidden`, 1 pt or smaller, or near-white over no shading; PowerPoint 1 pt runs and hidden shapes or slides; Excel rich-text runs at 1 pt or in white; PDF text in render mode 3 or 7, near-white over nothing the stream painted, under 1 pt, or off every `/MediaBox`. An instruction phrase there adds the advisory `heuristic_hidden_text`; hidden text alone is not reported. Styles, layouts, masters, and cell formats are not resolved. | [`content.py`](../src/yara_gate/content.py), [`pdftext.py`](../src/yara_gate/pdftext.py), [`scanner.py`](../src/yara_gate/scanner.py), [hidden-text boundaries](../docs/rules.md#hidden-office-and-pdf-text). |
| PDF active features | Complete decoded action/feature tokens, encryption, and the special note for an OpenAction that only navigates to a page. Other listed active features block, including those resolved in supported compressed object streams. | [`heuristics.py`](../src/yara_gate/heuristics.py), [PDF feature restrictions](../docs/rules.md#how-the-other-checks-work). |
| Office structure and macros | OOXML VBA/DDE, OLE objects, altChunk, encrypted legacy Office, and extracted VBA auto-exec or command-related keywords. VBA source is inspected without executing it. | [`heuristics.py`](../src/yara_gate/heuristics.py), [Office findings](../docs/rules.md#structural-checks-without-yara). |
| Embedded executables | Validated PE, ELF, or Mach-O headers inside another file, executable members in documents, or executables nested at least two container levels deep. | [`filetype.py`](../src/yara_gate/filetype.py), [`heuristics.py`](../src/yara_gate/heuristics.py), [`scanner.py`](../src/yara_gate/scanner.py). |
| Unicode and encoding signals | Context-aware joiners, Unicode tags, long variation-selector runs, a control-plus-note conjunction, and base64 run classification with media/key exemptions. | [`heuristics.py`](../src/yara_gate/heuristics.py), [`scanner.py`](../src/yara_gate/scanner.py), [Unicode and media boundaries](../docs/rules.md#how-the-other-checks-work). |
| Model files | Bounded pickle opcode inspection for selected dangerous callables, safetensors/GGUF header consistency, and Keras unsafe imports/calls or serialized Lambda code. No model is deserialized or executed. | [`heuristics.py`](../src/yara_gate/heuristics.py), [model-format limits](../docs/rules.md#structural-checks-without-yara). |
| MCP data | Shell commands in JSON tool configuration and selected hidden-instruction phrases in description fields. | [`heuristics.py`](../src/yara_gate/heuristics.py), [MCP boundaries](../docs/rules.md#structural-checks-without-yara). |

The [open gap tracker](https://github.com/cgfixit/yara-gate/issues/171) and
[executable gap probe](../docs/research/probe_detection_gaps.py) distinguish
implemented readers from planned work. A proposal is not shipped coverage.

## From a finding to a hold

[`models.py`](../src/yara_gate/models.py) aggregates severity and gives incomplete
precedence over findings. [`scanner.py`](../src/yara_gate/scanner.py) applies the
selected policy: default reports notes/advisories with exit 0; `agent-ingest`
holds both as block/exit 1; `agent-document` holds advisories but records notes
with exit 0. A block exits 1 and an incomplete scan exits 2 under every policy.
See the [policy table](../README.md#verdicts-and-policies).

[`quarantine.py`](../src/yara_gate/quarantine.py) controls intake and disposition;
[`report.py`](../src/yara_gate/report.py) writes JSON and SARIF before relocation.
These enforce and explain decisions rather than detect a new pattern. Reports
carry rule IDs, views, member ordinals, and coverage counters, never matched bytes.
Library/in-memory callers receive results and must enforce the hold themselves;
the [integration guide](../docs/integrations.md) defines the exact read contract.
[`hunt.py`](../src/yara_gate/hunt.py) proposes rules only from an operator-confirmed
blocked file; ordinary scanning does not learn rules from the input it judges.

## Evidence and accuracy

| Check | What its result establishes |
| --- | --- |
| [`lint_rules.py`](../docs/verification/lint_rules.py) and [`check_rule_pairs.py`](../docs/verification/check_rule_pairs.py) | Compilation/metadata and rule fire/near-miss cases. |
| [`check_added_rules.py`](../docs/verification/check_added_rules.py) | Added-rule and vendor-override cases. |
| [`measure_precision.py`](../docs/verification/measure_precision.py) | Hits in a generated benign corpus; see [measured precision](../docs/rules.md#measured-precision). |
| [`probe_rule_coverage.py`](../docs/research/probe_rule_coverage.py) | Real library/CLI scans, exits, provenance, and intake/disposition in disposable homes. |
| [`probe_detection_gaps.py`](../docs/research/probe_detection_gaps.py) | Known misses beside caught controls and benign boundaries; stale gap markers fail. |
| [CI workflow](../.github/workflows/ci.yml) | Platform-specific lint, typing, runtime, and regression coverage. A completed job is not a malware clearance. |

The [2026-11-06 documentation audit](../docs/verification/2026-11-06-detection-documentation.md)
recounts the rules and checks the current precision report. The 324 synthetic
benign files measure collisions on that corpus only: they establish neither
recall, production precision, nor safety of arbitrary clean files. Near-miss
fixtures are useful boundaries, not comprehensive validation. Dated vendor and
performance records describe their stated revisions; installed packs may differ.

No semantic classifier, OCR, sandbox execution, URL inspection, or general
document renderer runs here. A clean result means that completed checks found no
configured indicators. It is never permission to follow instructions in the data.

RTF reader text reaches the existing phrase rules as `rtf-text` and, when needed,
`rtf-text+text-folded`. Formatting and hex/Unicode escapes are decoded within a
paragraph; cells and separate stories remain separate. This adds no rule or
severity change. See [reader limits](../docs/rules.md#rtf-reader-boundaries) and
[verification](../docs/verification/2026-11-07-rtf-reader.md).

Encoded PDF annotation `/Contents` strings reach the same rules as
`pdf-annotation` and `pdf-annotation+text-folded`; each annotation/paragraph is
scanned separately. A phrase retains its note severity and policy behavior.
See [annotation limits](../docs/rules.md#pdf-annotation-boundaries) and
[verification](../docs/verification/2026-11-07-pdf-annotations.md).
