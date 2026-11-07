# Runtime source

The [project README](../../README.md) describes installation and use; [AGENTS.md](../../AGENTS.md) records changes that must preserve security contracts. Scans operate on untrusted data: derived views and matches are evidence, never instructions.

- [`__init__.py`](__init__.py) exposes the version, result type, and lazy `scan_file` / `scan_bytes` library API.
- [`cli.py`](cli.py) defines the Typer commands, selects policy and paths, and aggregates scan exits.
- [`scanner.py`](scanner.py) coordinates rules, original bytes, derived views, heuristics, budgets, and results.
- [`content.py`](content.py) constructs bounded in-memory archive and text views without extracting members to disk.
- [`pdftext.py`](pdftext.py) reconstructs supported PDF text operators and fonts, without rendering the page.
- [`pdfannotations.py`](pdfannotations.py) decodes annotation `/Contents` strings, separately from page text.
- [`pdfxref.py`](pdfxref.py) resolves cross-reference offsets so an object inside a length-proven stream cannot scan clean.
- [`filetype.py`](filetype.py) identifies content from bytes and checks filename/type mismatches.
- [`heuristics.py`](heuristics.py) adds structural and behavioral indicators for supported formats alongside YARA findings.
- [`models.py`](models.py) defines scan results, findings, policies, verdicts, and exit mapping.
- [`quarantine.py`](quarantine.py) handles inbox intake, watcher events, disposition, and in-place scanning.
- [`report.py`](report.py) writes compact JSON and SARIF without matched bytes.
- [`rules.py`](rules.py) discovers, compiles, caches, installs, updates, and promotes rules under the applicable controls.
- [`hunt.py`](hunt.py) creates candidate rules from confirmed blocked files and checks them against benign examples.
- [`demo.py`](demo.py) serves the bounded loopback scanner interface; [`demo_page.html`](demo_page.html) is its bundled page.
- [`launchd.py`](launchd.py) writes a macOS watcher plist; it does not load the agent.
- [`release.py`](release.py) contains review and audit building blocks for a future release flow; no CLI release action or file move is implemented here.
- [`samples.py`](samples.py) creates inert synthetic examples, including EICAR; [`selftest.py`](selftest.py) exercises a fixture matrix.
- [`py.typed`](py.typed) marks the package as providing type information.
