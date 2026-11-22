# yara-gate user guide

Use this when you want to scan a file on a Mac or a Linux machine before anything else reads it. The tool is a command-line program. There is no application window. On Windows, `yara-gate scan` of a file outside the inbox, inbox intake through `yara-gate scan`, and the Python `scan_file` and `scan_bytes` calls are supported; `watch` and `install-agent` need macOS or Linux. On any host, the rules inspect Windows shortcuts, scripts, and Office files before they reach a Windows machine.

The project lives at `~/Projects/yara-gate`. The holding folders live at `~/YaraGate`.

## 1. Install once

```bash
cd ~/Projects/yara-gate
uv sync --frozen
uv run yara-gate --version
```

You should see `yara-gate 0.2.0`.

The file `.python-version` contains `3.12`. `uv.lock` is the dependency pin. There is no `requirements.txt`.

To copy this folder to another machine, copy the source, `pyproject.toml`, `uv.lock`, `.python-version`, `rules/local/`, `rules/rules.lock`, and `rules/vendor-overrides.json`. `rules/templates/` and `scripts/` are needed only to change a generated rule file or rebuild the demo, not to scan. Leave out `.venv/` and the downloaded files under `rules/vendor/`; the compiled-rule cache lives in the user cache directory, not in the tree. Keep `rules/vendor/SKIPPED.md` when you want the list of rules the last install could not compile.

Check the install with the built-in fixture run:

```bash
uv run yara-gate selftest
```

The last line is `SELFTEST PASS` and the exit code is 0. That command uses a temporary folder. It does not change `~/YaraGate`. An installed copy takes its rules from the packaged set. An unexpected error prints `incomplete: <Type>` and exits 2.

## 2. Download the curated rules once

Scanning works offline with the 89 shipped local rules before this optional step. The curated packs (YARA Forge core, signature-base, and Elastic protections-artifacts) add known-malware signatures. Run this once, right after `uv sync`:

```bash
uv run yara-gate setup
```

`setup` downloads the packs pinned in `rules.lock`, checks each sha256, and compiles them before it replaces anything. Running it is the consent to use the network. Running it again prints `already set up` without touching the network while every recorded vendor file is present; `--force` downloads again. Until it has run, a scan on a terminal prints `note: vendor packs not installed; run 'yara-gate setup' once` on stderr and still scans with the shipped rules. Pipes, hooks, and `--json` callers do not see that line. The scan path itself never downloads anything.

`rules install` does the same download on demand, but only with the flag; without it, it exits 2 and prints `refusing: pass --allow-network`:

```bash
uv run yara-gate rules install --allow-network
```

Either command prints one line per pack (`pin` and `sha256`) and then `compiled_rules=... skipped_rules=...`. The November 1 [vendor setup record](docs/verification/2026-11-01-vendor-setup.md) printed `compiled_rules=13631 skipped_rules=13`; the 13 names are in `rules/vendor/SKIPPED.md`. Most of those signature-base files need external variables that yara-x does not have here, so they are skipped instead of failing the whole scan. If the lock does not match a download, the command prints `incomplete: sha256 mismatch for <pack>`, exits 2, and keeps the previous vendor tree. Set `GITHUB_TOKEN` (or `GH_TOKEN`) to raise the GitHub API limit; the token is sent only to `api.github.com` and is not printed. A rate limit, a missing URL, another HTTP status, or a network failure is printed as a sentence and the command exits 2.

After a successful install or update, `vendor.installed.json` beside `vendor/` records the installed vendor filenames. It is not tracked by git, so a checkout stays clean, and an older lock that holds the list is still read. Losing any recorded file makes scans incomplete (exit 2) and keeps inbox files in quarantine; run `yara-gate setup` again to restore the locked packs. Older installations need one successful install or update to establish this record; scans do not enroll them automatically.

An installed copy keeps the packaged rules even after `hunt` creates `<user-data>/local/`. A file there with the same name as a packaged rule is skipped (`local/<name>: shadowed by bundled`). If the packaged rules cannot be read, scans exit 2 with `bundled rules missing`. `rules update` resolves newer vendor packs and rewrites `rules.lock`; it does not update `rules/local/`, which changes only with the checkout. If the download or the compile fails, the vendor tree and `rules.lock` stay as they were. An installed copy ships `rules.lock` and copies it into the user-data directory when install succeeds.

### How vendor matches are graded

Every vendor match blocks unless `rules/vendor-overrides.json` lists that rule for the pack it came from. Each committed entry gives one rule, its pack, an action (`skip`, `note`, or `advisory`), a review date, and the reason, and applies only to that rule name in that pack's `vendor/` directory (`yara-forge-core` installs as `vendor/yara-forge`). yara-gate does not turn a vendor rule's own `score` into a severity. Today the list has two signature-base `.url` rules: one skipped as noisy (it blocked `mailto:` and `steam://` shortcuts), one lowered to advisory. When a vendor rule holds a file you trust, add an entry with a reason and check the list with `uv run python docs/verification/lint_rules.py`; do not edit the vendor rule files, which `setup --force` and `rules update` replace. A missing list makes every vendor match block. A malformed list makes every scan exit 2 with `invalid vendor-overrides.json`.

Run `uv run yara-gate rules update --allow-network` when you want newer pins. It resolves the current upstream release and commits, replaces the vendor files, and rewrites `rules/rules.lock`. Check the rules with `uv run python docs/verification/lint_rules.py` after an update; it only reads the lock and the override list.

## 3. Watch the inbox

```bash
uv run yara-gate watch
```

Leave that process running. Copy or save untrusted files into:

```text
~/YaraGate/inbox/
```

Watch also scans files that were already in the inbox when it started, including
dotfiles. Dropped directories are held intact as incomplete in
`quarantine/_rejected/`; use an explicit `scan DIRECTORY` to scan recursively.
Files over 100 MiB are held there too, without hashing or copying their contents.
These rejections print a reason and use `reports/rejected-<token>.json`; the token
is not a content hash. Write outside the inbox and rename completed files into
it; temporary dotfiles inside the inbox are not exempt. When it finishes a file it prints a line like:

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
| `advisory` (default policy, or notes only under `agent-document`) | `~/YaraGate/clean/<sha256>/` | 0 |
| `block` (including a held advisory or note under `agent-ingest`) | `~/YaraGate/blocked/<sha256>/` | 1 |
| `incomplete` | `~/YaraGate/quarantine/<sha256>/`, or `_rejected/` for intake rejections | 2 |

Only open files from `clean/` in an editor, an indexer, or an agent. `advisory` means a rule fired and the file was still allowed through; read the report before you treat it as ordinary.

For an agent or indexer that must hold every advisory and note, use `yara-gate scan <path> --policy agent-ingest` or `yara-gate watch --policy agent-ingest`. Those findings then produce `block`, exit 1, and `blocked/` for inbox files; their original severity stays in the report. `--policy agent-document` holds advisories and lets a file with notes only through; the README's [policy table](README.md#verdicts-and-policies) compares the three. Use a dedicated `--home` for each consumer. Existing files are not automatically rescanned when rules, detector code, or policy changes. Stop the watcher and downstream readers, run `yara-gate rescan --home GATE --policy agent-ingest` (with the same `--rules` used for intake), and inspect its summary before resuming. If the rules cannot scan at all, it exits 2 before touching any copy; fix the rules and run it again. `--dry-run` previews the pass without changing reports or copies. See the [rescan contract](docs/integrations.md#revalidating-admitted-files) for recovery and exit codes. A repeated inbox submission returns the existing slot to quarantine before it is scanned and relocated again, under the name it was submitted with this time.

For a reviewed `agent-document` hold, inspect the file and its report, then run
`yara-gate release SHA256 --home GATE --reason "review rationale"` with the rules
used for the scan. The command rechecks the bytes and findings before moving
a blocked inbox copy. See [reviewed document releases](docs/integrations.md#reviewed-document-releases)
for in-place files, audit records, and rescan behavior.

Stop watch with Control-C. One watch runs per gate home: it holds an operating-system lock on `~/YaraGate/.watch.lock`, so a second start exits 2 with `watch already running`. The lock is released when the watcher exits or crashes, so a stale file or a reused process ID never keeps the next start out. A `.watch.pid` left by an earlier release is ignored and removed.

On startup, watch finishes a recorded pending intake using its original policy,
rules root, and timeout before accepting new drops. If the scan is incomplete,
the file remains in quarantine with a new report. If the pending record itself
is invalid, intake stops and leaves the copy held. Inspect the gate's
`.intake-pending.json` and quarantine before resubmitting anything. Files held
before pending records were introduced stay available for manual review.

An explicit scan of the same original still in the inbox uses the new request's
policy and rules. An interrupted copy cannot grant that request an earlier verdict.

The first scan creates `~/YaraGate` and its five folders at mode `0700`. Another account on this Mac cannot list them.

To leave watch running after you log in, write a plist and load it yourself.

```bash
uv run yara-gate install-agent --dest ~/Library/LaunchAgents/com.cgfixit.yaragate.watch.plist --home ~/YaraGate
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.cgfixit.yaragate.watch.plist
```

`install-agent` does not run `launchctl`. It creates `~/Library/Logs/yara-gate` for the log, and the plist has no secrets in it. launchd restarts watch after a crash or a non-zero exit (at most every 10 seconds), including a start refused because another watch holds the gate home; a clean exit stays stopped. Unload with `launchctl bootout gui/$(id -u)/com.cgfixit.yaragate.watch` when you want watch to stop.

## 4. Scan one file without moving it

```bash
uv run yara-gate scan ~/Downloads/notes.txt --home ~/YaraGate
echo $?
```

Exit codes are 0, 1, and 2 as in the table above. This does not relocate `~/Downloads/notes.txt`. The report still appears in `~/YaraGate/reports/`. You can name several files or folders at once, or feed a list with `--paths-from list.txt` (or `--paths-from - --null` after `find ... -print0`); the exit code is the worst one, and a missing path is reported without stopping the others. A symlinked file outside the inbox is `symlink not followed` (exit 2) unless you pass `--follow-symlinks`; a symlinked directory is never followed. `--timeout` (default 30 seconds) is the deadline for one file.

To run the same check from Python, without moving the file and without a network call:

```python
from yara_gate import scan_file

result = scan_file("/path/to/file", timeout_s=30)
print(result.verdict, result.incomplete_reason)
```

`result.verdict` is `clean`, `advisory`, `block`, or `incomplete`.

To check a message or other text you already have in memory, without writing a file, pipe it to `yara-gate scan - --name message.txt`, or call `scan_bytes(data, name="message.txt")` from Python. The exit codes are the same.

To make an agent runtime refuse to read a file that has not scanned clean, register the [snapshot pre-read hook](docs/integrations.md#a-pre-read-hook-that-fails-closed)
and make the runtime honor its rewritten path. Consumers that can take bytes
directly should use the hook's `--bytes PATH` mode and consume stdout only after exit 0.

`scan_file(path, policy="agent-ingest")` and `scan_bytes(data, name=..., policy="agent-ingest")` apply the same policy as the CLI flag. Without that argument, the default policy retains advisory/exit 0 behavior.

To see what the gate would decide about text an agent already received, without admitting,
holding, or moving anything, use `yara-gate replay CAPTURE.jsonl`. It reads a capture of
the exact text handed to a model, prints one record per item, and exits 0 or 2, never 1.
The capture format is in
[replaying captured model input](docs/integrations.md#replaying-captured-model-input).

## 5. Read a report

Start with the current held queue:

```sh
yara-gate held --home ~/YaraGate
yara-gate held --home ~/YaraGate --since 7d --json
```

This lists entries still in `blocked/`, `quarantine/`, or `quarantine/_rejected/`.
It reads directory metadata and reports, never held bytes, and makes no changes.
Each line gives the current path, identifier, disposition, report age, policy,
reasons, finding IDs/severities, and provisional release eligibility. Strings are
JSON-escaped so a filename or report cannot send control sequences to the terminal.
`--json` wraps the rows in the [versioned index](docs/integrations.md#listing-held-items).
Unreadable or missing reports remain visible; a rejection without an associated
readable report has an unknown identifier. Unknown ages remain visible with `--since`.
An empty queue exits 0, as does a nonempty queue; an unavailable home, an invalid option,
or output that cannot be written (a pipe into `head` closes early) exits 2. In-place scans are not held copies and are not included.

An eligible row is a review candidate, not permission to read or move its bytes.
Use the [reviewed release command](docs/integrations.md#reviewed-document-releases)
after review; it performs the fresh scan and audit checks.

The latest report for a digest is `~/YaraGate/reports/<sha256>.json` and the matching `.sarif` file. The JSON includes the verdict, exit code, and findings. Each finding has `rule_id`, `offset`, `length`, `severity`, and `source`. The offset names a match that made the rule fire, not one an exemption covered ([reported offsets](docs/rules.md#reported-offsets)). It omits matched bytes.

Use `reports/events/<scan-id>.json` to compare individual scans of the same bytes under different names or policies. Each event contains the compact report plus `schema_version`, `scan_id`, and a UTC `recorded_at` timestamp. A record describes the scan, and can be present before its file moves. Release actions are recorded in `releases.jsonl`. Event files accumulate until the operator archives or removes them.

A home-directory path is shown as `~/...`. For inbox scans, the path is the quarantine slot used during scanning, even after relocation to `clean/` or `blocked/`. An in-place scan retains its input path; stdin and `scan_bytes` use the final component of `--name`/`name`. Path shortening does not anonymize other filenames or directories.

Reports include policy and `policy_reason`, engine version, ruleset fingerprint, skipped vendor-file count, compiled rule count, the tool version, `detector_sha256` (a digest of the scanner's own sources and parser versions, which changes when a reader or heuristic does even if the tool version and ruleset fingerprint do not; key cached admissions on it), the scan time in seconds, and coverage counts (`units_scanned`, `views_scanned`, `bytes_scanned`, `yara_seconds`, and `pdf_content_unread`: PDF page-content streams no view could decode, keyed by filter name or `other`, each also the note `heuristic_pdf_content_unread`), `match_rescan_limit` (the per-string match limit of a second scan, when a view filled YARA-X's list of 1,000,000 matches; otherwise `null`), and `unguarded_rule_files` (rule files loaded without that check). Finding `member_path` entries identify archive and mail members by ordinal (`zip:0`, `mime:2`), without disclosing their names; `view` identifies raw bytes or derived text: `decoded-utf16`, `decoded-charset` (text read through the legacy charset a page declares), `html-unescaped`, `json-unescaped`, `format-controls-removed`, `text-folded` (look-alike spellings folded to plain letters and Cyrillic-only words lowercased), `base64-decoded` and `percent-decoded` (encoded runs that spell readable text), `mime-headers-decoded`, `pdf-flate` (inflated PDF streams), `pdf-text` and `pdf-paragraph` (the text a PDF shows, per text block and per paragraph), `ooxml-text` (joined runs of supported Office parts), `ooxml-cell` (one inline-string worksheet cell, or one cell value that markup split), `ooxml-header` (one section of a worksheet page header or footer), `ooxml-comment` (one Excel or PowerPoint comment), `rtf-text` (one RTF paragraph, cell, or story), `pdf-annotation` (one annotation text string), `pdf-string` (one form field value, document information string, or outline title), `pdf-actual-text` (one marked-content `/ActualText` string, inline or named from a page's `/Properties`, which poppler and PDFium show in place of the glyphs), `ooxml-hidden-text`, `pdf-hidden-text`, and `html-hidden-text` (text a reader or browser hides), `html-text` (one block from a bounded lexical HTML reader), `feed-text` (one joined RSS or Atom text node or one block of declared HTML or XHTML), `xml-text` (one node of other XML that a comment, CDATA section, or entity split), `odf-text` (joined OpenDocument paragraphs), `config-unescaped` (one escaped YAML or TOML string), `markdown-text` (one paragraph or list item), `comment-text` (one adjacent comment block), or `notebook-text` (one cell source/output piece). A `+text-folded` suffix records an additional spelling fold, including `pdf-text+text-folded` and `pdf-paragraph+text-folded` after glyph decoding. The [view reference](docs/rules.md#limits) defines the boundaries. Offsets belong to that view. SARIF stores member/derived offsets in properties rather than mislabeling them as positions in the outer file.

Atom fields with `type="text"` or no type keep literal angle brackets after XML decoding.
Fields declared as HTML are read as escaped markup. XHTML fields are read a block at a
time. RSS descriptions and `content:encoded` can carry HTML. The scanner keeps titles,
descriptions, and neighboring entries separate. It checks the scan deadline during
long HTML comment reads and treats more than 256 nested feed namespace scopes as incomplete.

For any finding, start with the [detection-method map](rules/README.md) or look up its `rule_id` in [docs/rules.md](docs/rules.md), which gives the indicators each rule needs and its known benign collisions. Most rules are advisory. After a complete scan with advisory findings and no block finding, default policy moves inbox files to `clean/`; `agent-ingest` holds them in `blocked/`. Files outside the inbox stay in place. A legitimate administration script or security example can contain the same indicators, so the rule ID alone does not establish that the file is malicious.

MCP, notebook, and Keras readers also enforce a [JSON structure budget](docs/rules.md#json-parsing-limits) before allocating their object trees. Dense or deeply nested candidates are incomplete even when they have no findings.

If the verdict is `incomplete`, read `incomplete_reason`. Typical reasons are `file exceeds 100MB`, `archive depth exceeds 3`, `archive members exceed 1000`, `archive unreadable or encrypted`, `encrypted pdf`, `encrypted office file`, `pickle exceeds walk limit`, `mcp json exceeds walk limit` (MCP-shaped JSON too large or deep to walk whole), `pdf cmap entries exceed 524288`, `pdf cmap tokens exceed 1572864`, `timeout`, `match cap reached` (a string had more matches than YARA-X records, so a match after them may be unread; [limits](docs/rules.md#limits)), `no rules compiled`, `yara-x missing`, and `unreadable file`. A folder scan also reports `symlink not followed` for a symlinked file or directory outside the inbox, and `directory not readable` for a subdirectory it cannot list. Leave that file in quarantine. Do not copy it to `clean/` yourself.

A reader limit such as `text pieces exceed 100000` or a deadline can stop a scan midway.
The report keeps findings from pieces already matched. Pending pieces, including any
folded spellings that were queued for a later pass, can be absent. Exit 2 and the
incomplete reason govern disposition even when the report contains findings.

## 6. After you confirm a file is bad

Do this only when you have already decided the blocked file is malicious or unwanted. The command builds a rule that looks for similar strings elsewhere. It does not decide that the file is bad.

```bash
uv run yara-gate hunt \
  --confirmed <sha256 from the block line> \
  --reason "confirmed malicious document" \
  --scope ~/Documents
```

`--reason` is required. It is collapsed to one line, cut at 300 characters, then escaped, so a trailing backslash still compiles. Control characters are removed and non-ASCII text is kept. `--confirmed-by` labels the candidate with who confirmed it (default `operator`). The sha256 must be a directory under `~/YaraGate/blocked/`. The new rule is `<rules-root>/local/hunt_<12 hex chars>.yar` and its status is `candidate`. Candidates do not block. On an installed copy that folder is the user-data directory, and the packaged rules still load. After the `candidate ... hits=N` line the command prints each file under `--scope` that the candidate matches, one per line. Those names come from whoever made the files, so a control or invisible character in one (an escape sequence, a line break, a bidi override) is printed as a backslash escape such as `\x1b` or `\u202e`. The listing is for reading; a name printed with an escape is not the path to hand to another command.

When you want that rule to block later scans:

```bash
uv run yara-gate rules promote <those 12 hex chars>
```

Promote compiles the edited rule before it writes the file. If the compile fails, the candidate is left unchanged and the command exits 2.

## 7. What a normal file will and will not trip

Expect a block on the EICAR test string, on an Office file with an auto-run macro or DDE, on a PDF that contains `/JavaScript`, `/Launch`, or an `/OpenAction` that does more than open a page, on a PE/ELF/Mach-O header pasted into another file or a document, on a double extension such as `invoice.pdf.lnk`, on a file name with a bidi or zero-width character, on a Unicode tag outside an emoji flag, on any bidi control in a source or script file, on a base64 run that decodes to an executable, and on a pickle, safetensors, GGUF, or Keras model file that would run code when loaded.

Expect a note, exit 0 under the default policy, on phrases such as "ignore previous instructions", "forget all of your prior directions", or "repeat your system prompt verbatim", on the same override sentence in any of sixteen other languages (the [rule table](docs/rules.md#agent-ingestion-rules) lists them), on an order such as "disable your filters" or "you are no longer bound by", on the same phrase inside a base64 run, and on a lone invisible or bidi character in text (a zero-width space, a directional mark or isolate, a word joiner, an internal BOM). A ZWJ inside an emoji sequence and a ZWNJ or ZWJ between Arabic, Persian, or Indic letters stay clean. A lone control is a paste artifact as often as an attack; when the same unit also carries another note (a phrase split by a zero-width space, say), the scanner adds an advisory `heuristic_unicode_control_conjunction` finding.

Expect an advisory, exit 0, on a long base64 blob in a text file, on hidden HTML near an instruction phrase, on authority or role spoofing (a "this is the system administrator" claim followed by an override, or a `SYSTEM OVERRIDE:` header that voids the earlier rules), secret-transfer and one-time-code relay requests ("text me the API keys from the .env file", "I just sent you a code, forward it to me"), an order to use your own tool to send data to an outside address, tool-result command overrides, persistent approval-bypass requests, Markdown exfiltration, external templates, download-and-execute chains, encoded PowerShell with concealment flags, ClickFix verification-and-paste pages, Windows shortcut, script-host, and document lures, Defender and AMSI tampering, reverse shells, macOS stealer bootstraps, credential uploads, and project files that turn off a coding agent's approvals or run a command when a folder is opened. A file named `.pdf` whose bytes are a zip is also an advisory type mismatch. A bare "you are now" status message stays clean; an accompanying override, unrestricted-role, or jailbreak-persona term (`DAN`, `developer mode`) still matches. An ordinary CAPTCHA, copy widget, or encoded command alone is not enough for the delivery rules, and legitimate administration code using the full combination can still be advisory.

`agent-ingest` holds every advisory and note as block, including benign security examples; `agent-document` holds the advisories and records the notes. ZIP, tar, gzip, and MIME members receive the same rules and document heuristics; recognized unsupported or encrypted containers remain incomplete. [docs/rules.md](docs/rules.md) lists every rule's required indicators, its benign collisions, and the resource and decoding limits.

Do not expect a block on a brand-new payload that no rule mentions. Updating the packs helps for signatures that have been published. It does not make YARA understand a file.

## 8. When something looks wrong

- Exit 2 and the file still in `quarantine/` is the fail-closed result. Fix the cause (run `uv sync --frozen` again, remove a broken user rule, run `setup` to restore a missing vendor file) and scan again. A file over the size cap or an encrypted document stays incomplete by design.
- `rules install` or `rules update` without `--allow-network` is supposed to exit 2.
- Two watches at once: the second exits 2 with `incomplete: watch already running`.
- Vendor files that fail to compile are skipped and counted in the report's `skipped_rule_files`. A local rule file that fails to compile, shipped or your own, is fatal: every scan is incomplete with `local rule compile failed` and exits 2. The report does not name the file. `scan` and `rescan` print it on stderr once per run, with the line and the cause (`rule file failed: local/legacy.yar line 6: E009 unknown identifier ...`); from a checkout, `uv run python docs/research/probe_yara_compat.py RULES_ROOT/local` checks every file before you add it ([rules written for classic YARA](rules/README.md#rules-written-for-classic-yara)). Read `rules/vendor/SKIPPED.md` before treating a quiet scan as full coverage.

After you upgrade `yara-gate`, `yara-gate conform` checks the new install against fixtures
and expected verdicts shipped inside it: exit 0 when nothing changed, 1 when a verdict
did, 2 when it could not run. See the [conformance kit](docs/conformance.md).

## 9. Try a verdict in the browser

Run `yara-gate demo` for the local scan workbench backed by the real scanner.
Without a checkout, the [public recorded demo](https://cgfixit.github.io/yara-gate/)
replays saved results for 93 inert examples, each of 45 attacks beside a benign
near-twin that scans clean; it scans nothing and accepts no content ([how it is built and published](docs/pages-demo.md)).

```bash
uv run yara-gate demo --port 8765 --rules ~/Projects/yara-gate/rules
```

Open the printed `http://127.0.0.1:8765/` URL. Stop the server with Control-C. The server refuses any bind other than `127.0.0.1`.

1. Choose what the agent will read. **Message or tool result** selects
   `agent-ingest` and holds notes and advisories. **Retrieved document** selects
   `agent-document` and permits notes alone. **Manual inspection** uses default
   policy, whose exit 0 can include advisories.
2. Choose an inert example and **Scan sample**, or paste text and **Scan text**
   (Command/Ctrl + Enter). The counter measures UTF-8 bytes, not characters;
   the paste limit is 64 KiB. Pastes use the name `paste.txt`. Use the CLI/library
   with the original type/name for files, model inputs, and larger content.
   The list holds the catalog the public demo records, grouped by intake channel:
   45 attacks, including a vendor ranking directive recovered from RSS, each directly above its benign twin, and two scans that
   cannot finish: a 7z archive the scanner cannot open and a tool document past the JSON
   depth budget (incomplete under every policy). Other pairs include a PDF line in a
   plain font beside another font's map, a workbook written with the Open XML SDK's
   `x:` prefix, and an email whose quoted-printable body sits past 8 KiB of relay
   headers; each twin has the same layout around an ordinary sentence. **Scan pair side by side** scans the selected example
   and its twin under the same policy. **Run every pair** scans the whole catalog
   and counts the attacks held, the twins that stayed clean, and the findings on
   twins; a result that differs from the reviewed expectation is marked, which is
   what you would see after adding rules that hit a twin. A table under the totals
   breaks the same run down by how each attack was caught, read from its findings:
   hidden from the reader, invisible characters, disguised spelling, split across
   formatting, encoded, inside an archive or message, file structure, or a plain pattern. Under
   `agent-ingest` every attack is held and every twin is clean; `agent-document`
   holds 21 of the 45 and records the rest as notes, and the default policy holds 4.
3. Read the decision and original finding severities. Each finding says which
   check found it and in which view, in plain words. **Coverage & provenance**
   shows the loaded-rule count, skipped files, derived views, and the ruleset and
   detector fingerprints; a
   completed bundled-only scan does not mean vendor packs were installed. **Demo
   response JSON** shows preview fields without the input or matched bytes; it is
   not the full CLI integration record.
4. Changing input, example, or policy clears the old result, as do connection
   failures and rejected requests (HTTP 400 `bad json`, which are not scanned).

No input, scan reports, or history are saved by the app, and no file is moved or
released. The page has no external assets, analytics, browser storage, or cloud
calls; compiled rules may be cached locally. Clear does not erase the clipboard or
guarantee memory erasure. Review fingerprints before sharing them. Use the
[integration guide](docs/integrations.md#previewing-policies-in-the-local-workbench)
for actual CyClaw/Harness callers; a preview never authorizes following content.

## Verification records

Every change ships with a dated record under [docs/verification/](docs/verification/) that names the source revision, engine version, rule count, commands, and observed outcomes. The most recent, as of this guide: the November 22 [whole-file walk bounds](docs/verification/2026-11-22-heuristic-walk-bounds.md), [classic YARA rules](docs/verification/2026-11-22-classic-yara-rules.md), and [failing rule file named](docs/verification/2026-11-22-name-failing-rule-file.md) records, the November 21 [replay and conform exit codes](docs/verification/2026-11-21-replay-conform-exit-codes.md), [held, rescan, and release exit codes](docs/verification/2026-11-21-held-rescan-release-exit-codes.md), [rescan with rules that cannot scan](docs/verification/2026-11-21-rescan-broken-rules.md), [failed agreement lines](docs/verification/2026-11-21-conform-failed-hold.md), [demo request bounds](docs/verification/2026-11-21-demo-request-bounds.md), [replay worker provenance](docs/verification/2026-11-21-replay-worker-provenance.md), [HTML backdrops and terminal redraw](docs/verification/2026-11-21-html-terminal-boundaries.md), and [chat-template demo pair](docs/verification/2026-11-21-demo-chat-template-pair.md) records, the November 20 [ingress replay](docs/verification/2026-11-20-ingress-replay.md), [chat-template openers](docs/verification/2026-11-20-chat-template-openers.md), and [Typer 0.29.1](docs/verification/2026-11-20-typer-0.29.1.md) records, the November 19 [PrinterSetup files from other writers](docs/verification/2026-11-19-printer-setup-other-writers.md) record and [rescan memory](docs/verification/2026-11-19-rescan-memory.md) measurement, the [November 18 unlisted zip entries and V7 tars](docs/verification/2026-11-18-hidden-members-printer-setup.md) record, the November 17 [match-cap scanner](docs/verification/2026-11-17-match-cap-scanner.md), [match-cap rules](docs/verification/2026-11-17-match-cap-rules.md), and [reported offsets](docs/verification/2026-11-17-finding-witness.md) records, the [November 16 held index](docs/verification/2026-11-16-held-index.md) record, the [November 12 reader boundaries](docs/verification/2026-11-12-reader-boundaries.md) record (a PDF font read through its own dictionary, Office parts known by what they are, and mail opened as mail), the [November 10 shared demo catalog](docs/verification/2026-11-10-demo-catalog.md) record, the [November 8 rule and watcher integrity](docs/verification/2026-11-08-rule-and-watch-integrity.md) and [base64 and PDF hex strings](docs/verification/2026-11-08-base64-hex-strings.md) records, the [November 7 consumer enforcement](docs/verification/2026-11-07-consumer-enforcement.md) and [detection scope and budgets](docs/verification/2026-11-07-detection-scope-and-budgets.md) records, the [November 7 normalized-reader comparison](docs/verification/2026-11-07-normalized-reader-text.md), [RTF reader](docs/verification/2026-11-07-rtf-reader.md), [PDF annotations](docs/verification/2026-11-07-pdf-annotations.md), [PDF font readings](docs/verification/2026-11-07-pdf-font-readings.md), and [CMap budget](docs/verification/2026-11-07-cmap-entry-budget.md) records, the [November 6 demo showcase](docs/verification/2026-11-06-demo-showcase.md), the [YARA-X 1.23.0 upgrade](docs/verification/2026-11-06-yara-x-1.23.0.md), the [PDF text view](docs/verification/2026-11-05-pdf-text-view.md), the [encoded-text views](docs/verification/2026-11-05-encoded-text-views.md), the [pickle walker](docs/verification/2026-11-05-pickle-walker.md), and the [intake resubmission](docs/verification/2026-11-02-intake-resubmission.md) records. Older records describe smaller rule trees and earlier engines; read their revision line before relying on a number. `uv run yara-gate selftest` and `uv run python docs/research/probe_rule_coverage.py --verify` reproduce the library and CLI behavior on your machine with disposable homes, so `~/YaraGate` is never touched by verification.
