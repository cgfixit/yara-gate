# yara-gate user guide

Use this when you want to scan a file on this Mac before anything else reads it. The tool is a command-line program. There is no application window.

The project lives at `~/Projects/yara-gate`. The holding folders live at `~/YaraGate`.

## 1. Install once

```bash
cd ~/Projects/yara-gate
uv sync
uv run yara-gate --version
```

You should see `yara-gate 0.2.0`.

The file `.python-version` contains `3.12`. `uv.lock` is the dependency pin. There is no `requirements.txt`.

To copy this folder to another machine, copy the source, `pyproject.toml`, `uv.lock`, `.python-version`, and `rules/local/`. Leave out `.venv/`, `rules/.cache/`, and the downloaded files under `rules/vendor/`. Keep `rules/vendor/SKIPPED.md` when you want the list of rules the last update could not compile.

Check the install with the built-in fixture run:

```bash
uv run yara-gate selftest
```

The last line is `SELFTEST PASS` and the exit code is 0. That command uses a temporary folder. It does not change `~/YaraGate`. An installed copy takes its rules from the packaged set. An unexpected error prints `incomplete: <Type>` and exits 2.

## 2. Download the curated rules once

Scanning works offline with the 16 shipped local rules before this optional step. Update your repository checkout to receive changes to those rules. An installed copy keeps those packaged rules even after `hunt` creates `<user-data>/local/`. A file there with the same name as a packaged rule is skipped (`local/<name>: shadowed by bundled`). If the packaged rules cannot be read, scans exit 2 with `bundled rules missing`. `rules install` downloads the packs named in `rules.lock`. `rules update` resolves newer vendor packs and does not update `rules/local/`. If the download or the compile fails, the vendor tree you already had stays in place. The curated packs add known-malware signatures.

```bash
uv run yara-gate rules update
```

That exits 2 and prints `refusing: pass --allow-network`. The scan path itself never downloads anything. When you want the packs:

```bash
uv run yara-gate rules update --allow-network
```

The command prints one line per pack (`pin` and `sha256`) and then `compiled_rules=... skipped_rules=...`. A later run on 2026-10-04 printed `compiled_rules=13535 skipped_rules=13`. The 13 names are in `rules/vendor/SKIPPED.md`. Most of those signature-base files need external variables that yara-x does not have here, so they are skipped instead of failing the whole scan.

Run the update again when you want newer pins. It replaces the vendor files and rewrites `rules/rules.lock`.

## 3. Watch the inbox

```bash
uv run yara-gate watch
```

Leave that process running. Copy or save untrusted files into:

```text
~/YaraGate/inbox/
```

Watch also scans files that were already in the inbox when it started. When it finishes a file it prints a line like:

```text
clean sha256=<64 hex chars>
block sha256=<64 hex chars>
advisory sha256=<64 hex chars>
incomplete sha256=<64 hex chars>
```

Then look up that hash:

| Printed verdict | Folder | Exit code you would get from `scan` |
| --- | --- | --- |
| `clean` | `~/YaraGate/clean/<sha256>/` | 0 |
| `advisory` | `~/YaraGate/clean/<sha256>/` | 0 |
| `block` | `~/YaraGate/blocked/<sha256>/` | 1 |
| `incomplete` | `~/YaraGate/quarantine/<sha256>/` | 2 |

Only open files from `clean/` in an editor, an indexer, or an agent. `advisory` means a rule fired and the report explains which one, and the file was still allowed through. Read that report before you treat the file as ordinary.

For an agent or indexer that must hold every advisory, use `yara-gate scan <path> --policy agent-ingest` or `yara-gate watch --policy agent-ingest`. Advisory findings then produce `block`, exit 1, and `blocked/` for inbox files; their original finding severity remains advisory in the report. Use a dedicated `--home` for that consumer. Existing files are not automatically rescanned when a policy changes. A repeated inbox submission returns the existing slot to quarantine before it is scanned and relocated again.

Stop watch with Control-C. If a previous watch crashed, the next start takes over a dead pid in `~/YaraGate/.watch.pid`.

The first scan creates `~/YaraGate` and its five folders at mode `0700`. Another account on this Mac cannot list them.

To leave watch running after you log in, write a plist and load it yourself.

```bash
mkdir -p ~/Library/Logs/yara-gate
uv run yara-gate install-agent --dest ~/Library/LaunchAgents/com.cgfixit.yaragate.watch.plist --home ~/YaraGate
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.cgfixit.yaragate.watch.plist
```

`install-agent` does not run `launchctl`. The plist has no secrets in it. Unload with `launchctl bootout gui/$(id -u)/com.cgfixit.yaragate.watch` when you want watch to stop.

## 4. Scan one file without moving it

```bash
uv run yara-gate scan ~/Downloads/notes.txt --home ~/YaraGate
echo $?
```

Exit codes are 0, 1, and 2 as in the table above. This does not relocate `~/Downloads/notes.txt`. The report still appears in `~/YaraGate/reports/`.

To run the same check from Python, without moving the file and without a network call:

```python
from yara_gate import scan_file

result = scan_file("/path/to/file", timeout_s=30)
print(result.verdict, result.incomplete_reason)
```

`result.verdict` is `clean`, `advisory`, `block`, or `incomplete`.

`scan_file(path, policy="agent-ingest")` applies the same conservative advisory policy as the CLI. Without that argument, the default policy retains advisory/exit 0 behavior.

## 5. Read a report

Reports are `~/YaraGate/reports/<sha256>.json` and the matching `.sarif` file. Open the JSON. You will see the verdict, the exit code, and a list of findings. Each finding has `rule_id`, `offset`, `length`, `severity`, and `source`. It does not include the bytes that matched.

A home-directory path is shown as `~/...`. The path is where the file was while it was scanned, which is the quarantine slot, even if the file was then moved to `clean/` or `blocked/`.

Reports include policy, engine version, ruleset fingerprint, and skipped vendor-file count. Finding `member_path` entries identify archive members by ordinal, without disclosing their names; `view` identifies raw bytes or derived text. Offsets belong to that view. SARIF stores member/derived offsets in properties rather than mislabeling them as positions in the outer file.

For a delivery-pattern finding, compare its `rule_id` with the [README rule table](README.md#what-this-catches-and-what-it-does-not) and the [documented match boundaries](docs/research/modern-delivery-rules.md#rule-boundaries-and-benign-collisions). All four new rules have advisory severity. After a complete scan with advisory findings and no block finding, default policy moves inbox files to `clean/`; `agent-ingest` holds them in `blocked/`. Files outside the inbox stay in place. A legitimate administration script or security example can contain the same indicators, so the rule ID alone does not establish that the file is malicious.

If the verdict is `incomplete`, read `incomplete_reason`. Typical reasons are `file exceeds 100MB`, `archive depth exceeds 3`, `timeout`, `no rules compiled`, `yara-x missing`, and `unreadable file`. Leave that file in quarantine. Do not copy it to `clean/` yourself.

## 6. After you confirm a file is bad

Do this only when you have already decided the blocked file is malicious or unwanted. The command builds a rule that looks for similar strings elsewhere. It does not decide that the file is bad.

```bash
uv run yara-gate hunt \
  --confirmed <sha256 from the block line> \
  --reason "confirmed malicious document" \
  --scope ~/Documents
```

`--reason` is required. The sha256 must be a directory under `~/YaraGate/blocked/`. The new rule is `<rules-root>/local/hunt_<12 hex chars>.yar` and its status is `candidate`. Candidates do not block. On an installed copy that folder is the user-data directory, and the packaged rules still load.

When you want that rule to block later scans:

```bash
uv run yara-gate rules promote <those 12 hex chars>
```

Promote compiles the edited rule before it writes the file. If the compile fails, the candidate is left unchanged and the command exits 2.

## 7. What a normal file will and will not trip

Expect a block on the EICAR test string, on an Office file with an auto-run macro, on a PDF that contains `/OpenAction` or `/JavaScript`, on a PE/ELF/Mach-O header pasted into another file, and on explicit left/right bidi overrides. Common emoji/language joiners are allowed. Other invisible indicators and directional isolates are advisory.

Expect an advisory, exit 0, on a long base64 blob in a text file, on phrases such as "ignore previous instructions", and on hidden HTML that contains those phrases. A file named `.pdf` whose bytes are a zip is also an advisory type mismatch.

The default policy also reports authority/action spoofing, secret-transfer requests, selected encoded instructions, external templates, and download/execute chains as advisory. Agent-ingest turns every advisory into a block, including benign security examples. ZIP/tar/gzip members receive the same rules and document heuristics; recognized unsupported or encrypted archives remain incomplete. See the README for exact resource and decoding limits.

The local pack also reports combined ClickFix verification/clipboard/shell instructions, HTML payload assembly with a script/archive download name, encoded PowerShell with concealment or policy-bypass flags, and HTTP(S) `mshta` launches. An ordinary CAPTCHA, copy widget, or encoded command alone is insufficient for these new rules. Legitimate code using the full combination can still be advisory. The [delivery-rule notes](docs/research/modern-delivery-rules.md) list the supported spellings, benign collisions, and source references.

Do not expect a block on a brand-new payload that no rule mentions. Updating the packs helps for signatures that have been published. It does not make YARA understand a file.

## 8. When something looks wrong

- Exit 2 and the file still in `quarantine/` is the fail-closed result. Fix the cause (install `yara-x`, raise nothing past the size cap, or remove a broken rules directory) and scan again.
- `rules update` without `--allow-network` is supposed to exit 2.
- Two watches at once: the second exits 2 with `incomplete: RuntimeError`.
- Vendor files that fail to compile are skipped. The scan still runs if at least one rule compiled. Read `rules/vendor/SKIPPED.md` before treating a quiet scan as full coverage.

## 9. Try a verdict in the browser

Open `demo.html` for a limited JavaScript illustration, or run `yara-gate demo` to exercise the actual scanner and policy selector. Choose **Scan plain note**, **Scan base64 text**, or **Scan PE saved as PDF**, or paste text and choose **Scan paste**. The result shows the verdict and exit code without echoing matched bytes. Neither demo moves files into `~/YaraGate`. The standalone file does not implement the full current scanner.

The full yara-x scan is still the loopback command.

```bash
uv run yara-gate demo --port 8765 --rules ~/Projects/yara-gate/rules
```

Open the printed `http://127.0.0.1:8765/` URL. Stop the server with Control-C. The server refuses any bind other than `127.0.0.1`.

## Verification already done on this machine

The [October 8 delivery-rule verification](docs/research/modern-delivery-rules.md#executed-verification) covers the 16-rule pack with 70 direct library cases, 16 CLI intake/rescan operations, and three compilation/deadline checks. Those runs used inert inputs and disposable gate homes. The [earlier intake record](docs/verification/intake-coverage.md) includes browser evidence and the observed macOS watcher shutdown limitation; it predates the four delivery rules.

A run on 2026-10-04 created `~/YaraGate` and left the local fixtures there. EICAR and the synthetic macro, PDF, and Unicode samples are under `blocked/` or `clean/` as their verdicts required. `big.bin` is a sparse file over the 100 MB cap and it stayed in `quarantine/`. Those are test files, not documents you dropped. Delete `~/YaraGate` if you want the folders empty before you start using them. Deleting it does not remove the rules in `~/Projects/yara-gate`.
