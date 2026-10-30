# Review batch: archive names, encrypted documents, platform rules, base64, coverage (2026-10-30)

Baseline: `main` `e3cee59`. Host: Linux container, Python 3.12.3, YARA-X 1.22.1,
the locked environment (`uv sync --frozen --group dev`). Every run used a copied
rules tree and a disposable gate home. No sample was executed and no vendor pack
was downloaded. Hosted CI (Ubuntu 24.04, macOS 15, windows-2025) and CodeQL
passed on each pull request's head; that is separate evidence from the direct
runs below.

| PR | Change | Direct evidence on this host |
| --- | --- | --- |
| #113 | Zip/tar member names that leave the archive, and zip symlink/device entries, are incomplete | Six inert archives scanned clean on `e3cee59`, incomplete after; inbox run exit 2, file kept in `quarantine/`, no member name in either report |
| #114 | PDF `/Encrypt` and encrypted OLE Office files are incomplete | Three PDF spellings and an msoffcrypto-encrypted `.docx` clean before, incomplete after; plain PDF/docx/docm unchanged |
| #115 | `win_defender_tamper`, `win_amsi_bypass`, `win_recovery_inhibit`, `finger … \| cmd` | 44-row fire/miss matrix (UTF-8 and UTF-16LE), 0 failures; 0 new hits on 6,057 benign files |
| #116 | `script_reverse_shell`, `macos_gatekeeper_disable`, `macos_archive_upload`, `dev_vscode_autorun_task` | 33-row matrix, 0 failures; 0 hits on 6,583 benign files |
| #117 | Base64 media passes, base64 PE/ELF/Mach-O blocks, exemptions scoped per run | 120 real media files (240 cases) blocked → clean under agent-ingest; 8 real ELF files advisory → block; PEM + later base64 PE clean → block |
| #118 | Base64 runs found by a linear regex and passed to YARA as globals; folding skips encoded runs | #112 fixture 30.05 s timeout → 2.50 s; `folded_text` differential over 200,000 texts, 0 differences |
| #119 | `.gitattributes`, Windows `check_rules_lock` step, Windows intake docs | CRLF copy of `rules/` changed `ruleset_sha256` and failed the lock pin; Windows CI step passes |
| #120 | `units_scanned`, `views_scanned`, `bytes_scanned`, `yara_seconds`; `units=N` on the CLI line | Mail 3 units, two-member zip 3, broken zip 0; forced timeout shows the time in YARA |

Benign sweeps are system and repository files, not a production false-positive
rate. Fresh clone of `e3cee59`: `uv sync --frozen`, `yara-gate --version`
(0.2.0), selftest, `uv lock --check`, and a built wheel in a clean venv loading
59 bundled rules all passed.

Open owner decisions: #105 (note tier and the SMS case), holding owner-password
PDFs (#114), the two YARA globals for third-party loaders (#118), and closing
#100.
