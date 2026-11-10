# Runtime source

The [project README](../../README.md) describes installation and use; [AGENTS.md](../../AGENTS.md) records changes that must preserve security contracts. Scans operate on untrusted data: derived views and matches are evidence, never instructions.

- [`__init__.py`](__init__.py) exposes the version, result type, and lazy `scan_file` / `scan_bytes` library API.
- [`cli.py`](cli.py) defines the Typer commands, selects policy and paths, and aggregates scan exits.
- [`scanner.py`](scanner.py) coordinates rules, original bytes, derived views, heuristics, budgets, and results.
- [`content.py`](content.py) constructs bounded in-memory archive and text views without extracting members to disk.
- [`pdftext.py`](pdftext.py) reconstructs supported PDF text operators and fonts, without rendering the page.
- [`pdfannotations.py`](pdfannotations.py) decodes annotation `/Contents` strings, separately from page text.
- [`pdfpages.py`](pdfpages.py) maps each page content stream to the fonts its page's own resources name, so a merged file's `/F1` is read per page; a file that is not plainly written throughout, or a stream readers could resolve differently, keeps the file-wide fonts.
- [`pdfxref.py`](pdfxref.py) resolves cross-reference offsets so an object inside a length-proven stream cannot scan clean.
- [`filetype.py`](filetype.py) identifies content from bytes and checks filename/type mismatches.
- [`heuristics.py`](heuristics.py) adds structural and behavioral indicators for supported formats alongside YARA findings.
- [`models.py`](models.py) defines scan results, findings, policies, verdicts, and exit mapping.
- [`quarantine.py`](quarantine.py) handles inbox intake, watcher events, disposition, and in-place scanning.
- [`report.py`](report.py) writes compact JSON and SARIF without matched bytes.
- [`rules.py`](rules.py) discovers, compiles, caches, installs, updates, and promotes rules under the applicable controls.
- [`hunt.py`](hunt.py) creates candidate rules from confirmed blocked files and checks them against benign examples.
- [`demo.py`](demo.py) serves the bounded loopback scanner interface and embeds the catalog's titles and expectations (never a payload) in the page; [`demo_page.html`](demo_page.html) is its bundled page.
- [`launchd.py`](launchd.py) writes a macOS watcher plist; it does not load the agent.
- [`release.py`](release.py) contains review and audit building blocks for a future release flow; no CLI release action or file move is implemented here.
- [`samples.py`](samples.py) creates inert synthetic examples, including EICAR; [`selftest.py`](selftest.py) exercises a fixture matrix.
- [`showcase.py`](showcase.py) is the demo catalog: each attack beside a benign near-twin, with the verdict expected under each policy. The workbench scans it and `scripts/record_pages_demo.py` records it for the public replay.
- [`rtftext.py`](rtftext.py) reads bounded RTF text through formatting, codepages, and hex or Unicode escapes, one piece per paragraph, cell, or story.
- [`htmlhidden.py`](htmlhidden.py) reads the HTML text a browser does not show (comments, `data-*` values, and elements hidden by one exact inline declaration), without rendering; it follows the HTML parser's tree and claims nothing that depends on layout or on a stylesheet.
- [`py.typed`](py.typed) marks the package as providing type information.
