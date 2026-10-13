# yara-gate

yara-gate is a local intake gate for untrusted files before document processing, search indexing, or AI-agent ingestion. Its CLI and Python library combine YARA-X rules with bounded archive and document checks, then return a verdict that a downstream reader can act on.

Use it to make the handoff from an incoming file to a reader explicit:

- **Hold files until inspection finishes.** Inbox files stay in `quarantine/` while scanning. Blocked files go to `blocked/`; unfinished scans stay quarantined. Readers should consume files only from `clean/`.
- **Choose how to handle suspicious patterns.** Default policy allows completed clean or advisory scans into `clean/`. The `agent-ingest` policy also blocks advisories for review, including the new delivery-pattern rules shown below.
- **Keep evidence for review and automation.** JSON/SARIF reports record rule IDs, severity, policy, content views, and scan completeness without copying matched bytes into the report. Stable exit codes let a caller distinguish allowed, blocked, and incomplete results.

The scan doesn't use the network. Curated rule packs are downloaded only when you run `rules install --allow-network` or `rules update --allow-network`. A rule is generated only after you confirm a file that is already in `blocked/`, and that candidate does not block anything until you promote it.

The private repository is [cgfixit/yara-gate](https://github.com/cgfixit/yara-gate).

## See the policy decision

The live loopback demo below calls the real scanner. Both captures scan the same inert ClickFix example with the 16-rule local pack. The rule detects a verification lure combined with clipboard-copy and shell/paste instructions; the selected policy determines whether that advisory is allowed or held.

| Default policy: report the advisory | Agent ingest: hold it for review |
| --- | --- |
| ![Default policy reports web_clickfix_lure as advisory with exit 0](screenshots/yara-gate-clickfix-advisory.jpg) | ![Agent-ingest policy returns block with exit 1 while preserving advisory finding severity](screenshots/yara-gate-clickfix-agent-ingest.jpg) |
| `advisory`, exit **0**: a complete inbox scan with no blocking finding can enter `clean/`; the report still identifies the pattern. | `block`, exit **1**: the same advisory is held in `blocked/` during inbox intake. Its finding severity remains advisory. |

This makes the value concrete: a consumer can review a suspicious pattern or require it to be held, using the same detection evidence. Legitimate security examples can match, so an advisory is a review signal. These October 8 captures show verdicts and policy behavior; the demo itself does not move files. See [capture provenance and full-size images](screenshots/README.md#clickfix-detection-and-consumer-policy), or [run the live demo](#demo).

## Install

From the project directory, on macOS or Linux, with [uv](https://docs.astral.sh/uv/) and Python 3.12:

```bash
cd ~/Projects/yara-gate
uv sync
uv run yara-gate --version
```

`yara-gate 0.2.0` is the version this tree prints. The scanner imports the `yara-x` package (the lock resolves 1.21.0). It does not call the Homebrew `yara` binary.

`uv run yara-gate selftest` rebuilds the local fixtures and exits 0 only when every expected verdict matches. A fresh copy of this directory can run the same two commands. An installed copy copies the packaged local rules, not a checkout path that is not on disk. An unexpected selftest error prints `incomplete: <Type>` and exits 2. Selftest does not download malware. It writes the EICAR test string and small synthetic documents at run time.

## Drop folder

The default root is `~/YaraGate/`. Pass `--home` to use another directory. `ensure` creates the root and the five folders at mode `0700`, so other accounts on the Mac cannot list them. File bytes copied in stay mode `0644` with the executable bit removed.

| Directory | Role |
| --- | --- |
| `inbox/` | Drop files here |
| `quarantine/<sha256>/` | File is being scanned, or the scan did not finish |
| `clean/<sha256>/` | Clean, or advisory under the default policy. Readers must check the report |
| `blocked/<sha256>/` | A block rule or block heuristic matched |
| `reports/<sha256>.sarif` | SARIF 2.1.0 report, written for every scan |
| `reports/<sha256>.json` | The same verdict in compact JSON |

```bash
uv run yara-gate watch
```

Watch scans files already sitting in the inbox, then keeps scanning new ones. A second watch exits 2 while the first process is alive. The lock file is `~/YaraGate/.watch.pid`.

```bash
uv run yara-gate scan path/to/file
uv run yara-gate scan path/to/folder
```

A path inside the inbox is quarantined and then moved. Any other path stays where it is. The report is still written under the gate root. A folder scan uses the worst exit code in the folder.

On intake the tool hashes the file, copies it into `quarantine/<sha256>/`, strips the executable bit, and removes the inbox copy. Dropping the same bytes again reuses that slot and returns it to quarantine for a fresh scan under the selected policy.

```mermaid
flowchart TD
    drop["inbox/ file"] --> watch["watch or yara-gate scan"]
    watch --> settle["skip dotfiles; size stable 0.2s"]
    settle --> intake["intake: sha256 copy into quarantine/sha/"]
    intake --> known{"same sha already in clean, blocked, or quarantine?"}
    known -->|yes| reuse["return existing slot to quarantine; delete the new inbox copy"]
    known -->|no| slot["quarantine/sha/name, exec bit stripped"]
    reuse --> scan
    slot --> scan["scan_file: yara-x, heuristics, filetype"]
    scan --> report["write reports/sha.sarif and reports/sha.json"]
    report --> verdict{"verdict"}
    verdict -->|incomplete| stay["stay in quarantine/"]
    verdict -->|block| blocked["blocked/sha/"]
    verdict -->|clean or advisory| clean["clean/sha/"]
    outside["path outside inbox/"] --> inplace["scan_in_place: file stays put"]
    inplace --> report
```

## Exit codes

| Code | Verdict | Where the file goes |
| --- | --- | --- |
| 0 | `clean`, or `advisory` only | `clean/` |
| 1 | `block` | `blocked/` |
| 2 | `incomplete` | stays in `quarantine/` |

Advisory matches are listed in the report and set `"advisory": true`. They still exit 0. An unreadable file, a timeout, a size limit, a rules compile failure, or a missing `yara-x` import exits 2. An unhandled exception exits 2 and the message is the exception class name.

The default policy keeps the table above. For ingestion that must hold every advisory for review, select `agent-ingest`:

```bash
uv run yara-gate scan path/to/file --policy agent-ingest
uv run yara-gate watch --policy agent-ingest
```

Under `agent-ingest`, advisory findings produce a `block` verdict, exit 1, and `blocked/` for inbox files. Reports preserve each finding's original severity and include `policy` and `policy_reason`. Incomplete scans remain exit 2 in quarantine. This policy also holds benign advisory cases, such as security documentation quoting an instruction. CyClaw and other agent consumers should pass `policy="agent-ingest"`. The scan default stays `default`. Use a separate gate home for each consumer policy; changing policies does not rescan files already on disk until they are submitted again.

## Reports

Every scan writes both report files, including a clean scan. A finding stores the rule id, byte offset, and byte length. It does not store the matched bytes. Paths under your home directory are written as `~/...`. The path in the report is the quarantine path at scan time. The file is moved to `clean/` or `blocked/` after the report is written.

For automation, `yara-gate scan path/to/file --json` emits the same report schema
as one JSON object per file on stdout. Directory scans use JSON Lines and keep
the aggregate exit code. Diagnostics go to stderr. See the [integration contract
and ingestion example](docs/integrations.md); consumers must check both the
process exit and the returned records.

Findings also identify their YARA namespace, content `view`, and archive `member_path` as container ordinals such as `zip:0` (including directory entries in the numbering). Member names and decoded text are not copied into reports. Offsets refer to that member/view, not to the enclosing archive. SARIF keeps derived/member offsets in result properties instead of attaching them to the outer file's physical region. Scan records include the engine version, ruleset fingerprint, and skipped vendor-file count.

## Rule packs

`rules install` and `rules update` refuse to run unless you pass `--allow-network`. Those are the only commands that open a network connection. `rules install` downloads the URLs already in `rules.lock` and checks each sha256. `rules update` resolves current pins and writes a new lock only after the new vendor tree compiles. If either command fails, the previous vendor tree and lock stay as they were. The download allows only `https` URLs on `github.com`, `api.github.com`, `codeload.github.com`, and `release-assets.githubusercontent.com`, re-checks every redirect, and ignores `HTTP_PROXY`. If `GITHUB_TOKEN` is set, or else `GH_TOKEN`, it is sent only to `api.github.com` and removed when a redirect changes host. The token is not printed. A rate limit says `rate limited by api.github.com until <local time>; set GITHUB_TOKEN`. A missing URL says `not found: <url>`. Any other HTTP status says `HTTP <code> from <host>`. A network failure says `network unreachable`. Those failures still exit 2 and leave the vendor tree and lock unchanged. An installed copy includes `rules.lock`. `rules install` uses the root's lock when it exists, otherwise that packaged lock, and writes a copy into the rules root on success. Vendor rule bodies are still not packaged.

```bash
uv run yara-gate rules install --allow-network
uv run yara-gate rules update --allow-network
```

`rules/rules.lock` records the URL, pinned tag or commit, and sha256 of each download. The packs are YARA Forge core, Florian Roth's signature-base (`yara/` files), and Elastic protections-artifacts (`yara/` files). Rules that do not compile under yara-x are skipped and listed in `rules/vendor/SKIPPED.md`. If nothing compiles, scans exit 2.

The update run on 2026-10-04 pinned:

| Pack | Pin | Download sha256 |
| --- | --- | --- |
| yara-forge-core | `20261004` | `0b548dff76139b7a041d20923ccfddfa614db6b6ee8710c181ff037a753ffe69` |
| signature-base | `94a1c48d7ab499879287ff611dfe7f9c56376030` | `13895e9219e844beeba1f5d7d3e3261a81e4e8f69cf18cc823d3abcc16e601a3` |
| elastic | `83e227669df8a13a2a2fee52c14b742c0d5f17cc` | `ed1d0e2a11f5deab2de5c8978cf6667d1a53202b5bdb5c11b96c30cdb153ef8a` |

That compile produced 13535 rules and skipped 13. The compiled cache now lives in the user cache directory, not in `rules/.cache/`. A scan does not modify the rules tree. Vendor rule bodies are not committed. Elastic's rules are under the Elastic License 2.0. They stay in this local tree and are not packaged for redistribution.

The 20 local rules in `rules/local/` ship with the tool and need no download. Local-rule changes arrive with repository updates; `rules install` restores the packs recorded in `rules.lock`, and `rules update` refreshes vendor packs only. A fresh checkout has the local rules only until you install from the lock. `agent_eicar` matches the EICAR test marker. A compile failure in an active local rule makes scans incomplete even when other rules compile. Vendor compile skips remain permitted and are counted in reports.

An installed copy (wheel, `uv tool`, or pipx) reads those same rules from package data. The platform user-data directory, and a `YARA_GATE_RULES` directory that does not already contain every shipped rule name, loads the packaged rules first, then `<root>/local/` rules (`.yar` and `.yara`), then `<root>/vendor/`. A user file with the same name as a packaged file is not compiled. `rules install` and `rules update` print `local/<name>: shadowed by bundled` and count it in `skipped_rule_files`. Candidates are never loaded. If the packaged rules are missing or unreadable, the scan exits 2 with `bundled rules missing` and does not run on user or vendor rules alone. A checkout, or an explicit `--rules` directory whose `local/` contains every shipped name, is loaded once so those files are not compiled twice.

## What this catches, and what it does not

Installed curated packs add known malware signatures. Local heuristics check Office auto-exec macros (`olevba`), risky PDF tokens (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`), and embedded executable headers. These checks also run on archive members. PDF token checks remain conservative feature restrictions; an ordinary navigation `/OpenAction` still blocks.

Bidi overrides, embeddings, and isolates block under both policies. A zero-width space, left-to-right or right-to-left mark, word joiner, internal BOM, or Unicode tag also blocks under both policies. A ZWJ inside an emoji sequence and a ZWNJ or ZWJ between Arabic, Persian, or Indic letters stay clean. New advisory rules cover authority/action spoofing, secret-transfer requests, selected base64 instruction phrases, external OOXML/RTF templates, and download/execute command combinations. Hidden-HTML indicators require a nearby instruction phrase. A text file's long-base64 detection survives a filename change to `.bin`.

The delivery-pattern rules report these IDs:

| Rule ID | Required indicators | Finding severity |
| --- | --- | --- |
| [`web_clickfix_lure`](rules/local/web_clickfix_lure.yar) | Verification language, clipboard-copy API, shell-opening instructions, and paste instructions near each other | Advisory |
| [`web_html_smuggling`](rules/local/web_html_smuggling.yar) | Base64 decoding, Blob/URL APIs, and a nearby literal script, executable, disk-image, or archive download filename | Advisory |
| [`script_encoded_powershell`](rules/local/script_encoded_powershell.yar) | An encoded command plus hidden-window or execution-policy-bypass flags in a bounded PowerShell command fragment | Advisory |
| [`script_mshta_remote`](rules/local/script_mshta_remote.yar) | A direct HTTP(S) target passed to `mshta` | Advisory |
| [`script_regsvr32_remote_scriptlet`](rules/local/script_regsvr32_remote_scriptlet.yara) | Regsvr32 with remote `/i:` and `scrobj.dll` in one bounded command | Advisory |
| [`script_rundll32_mshtml`](rules/local/script_rundll32_mshtml.yara) | Rundll32 JavaScript protocol invoking MSHTML `RunHTMLApplication` | Advisory |
| [`shortcut_powershell_encoded`](rules/local/shortcut_interpreter.yara) | Parsed PowerShell target plus encoded and hidden/bypass arguments | Advisory |
| [`shortcut_mshta_remote`](rules/local/shortcut_interpreter.yara) | Parsed MSHTA target with an HTTP(S) argument | Advisory |

The [October 13 attachment-signature research](docs/research/attachment-signatures.md)
records the four newest rules, their benign boundaries, packaging checks, and
remaining shortcut/parser limitations. They add no network or target execution.

These lexical combinations can also occur in legitimate administration, export code, and security documentation. See [delivery-rule sources, exact boundaries, and verification](docs/research/modern-delivery-rules.md). They do not execute or decode the referenced payload; `agent-ingest` applies its existing hold policy to their advisories. A match identifies a pattern requiring review, not confirmed malicious intent.

It does poorly against a new or targeted payload. YARA matches patterns somebody has already written down. Building a rule from the file you are judging only describes that file, so the tool never does that.

Other limits, measured in this tree:

- ZIP, tar, and gzip are inspected in memory with at most 3 container levels, 1,000 entries, 100 MiB per file/member, and a shared 500 MiB expanded/derived-content budget. Gzip counts as one level, including in `.tar.gz` or `.tgz`.
- Encrypted/unreadable archives, unsupported tar member types, and recognized 7z/RAR/bzip2/xz containers produce incomplete scans. Members are never extracted to filesystem paths.
- Raw bytes and UTF-8 derived views are scanned: BOM-marked or ASCII-heavy UTF-16, HTML entity decoding, and removal of format controls for inspection. Originals remain unchanged. No general document-text extraction, OCR, arbitrary base64 decoding, or semantic prompt-injection guarantee is provided.
- Reads are capped by remaining byte budgets. A shared deadline is checked between extraction chunks and scan/view operations, and YARA receives the remaining time. Third-party archive metadata and Office parsing are not preempted by an OS process deadline.
- A `.pdf` that is really a zip is an advisory type mismatch and exits 0. A `.pdf` that is really a PE, ELF, or Mach-O exits 1.
- A scan of a path outside the inbox does not move that file.

## Hunt

```bash
uv run yara-gate hunt --confirmed <sha256> --reason "why this file is bad" --scope ~/some/folder
uv run yara-gate rules promote <id>
```

`--confirmed` must name a file already in `blocked/`, and `--reason` is required. The reason is collapsed to one line, cut at 300 characters, then escaped. Control characters are removed. Non-ASCII text is stored as itself. The candidate keeps distinctive strings longer than 8 bytes that do not appear in `tests/fixtures/benign/`. It must hit the confirmed file and zero benign files. It is written to `<rules-root>/local/hunt_<first 12 hex of the sha>.yar` with `status = "candidate"`. In a checkout that root is `rules/`. In an installed copy it is the user-data directory. Creating `local/` there does not hide the packaged rules. Candidates are not loaded as block rules. `rules promote` rewrites the status to `promoted` and `verdict_on_match` to `block` only after the new text compiles.

## Library

```python
from yara_gate import scan_file

result = scan_file("attachment.bin", timeout_s=30)
result.verdict  # "clean", "advisory", "block", or "incomplete"
```

Pass `policy="agent-ingest"` to hold all advisory findings as a block. CyClaw and other agent consumers should pass that policy. The default remains `policy="default"`.

`scan_file` does not move files and does not open a socket. Pass `rules_dir` to point at a different rules tree. The default is this project's `rules/` directory. A later caller, including CyClaw before chunking, can use this function without taking the drop folder.

## Demo

`demo.html` is a limited standalone JavaScript illustration. It does not implement the full current rule pack, decoded views, archives, or policy. Use the live demo below to exercise the current scanner.

`yara-gate demo` is the full scan. It serves a page on `127.0.0.1` and prints the URL. Port `0` picks a free port. That page calls `scan_file` on a temporary file the server creates and deletes.

```bash
uv run yara-gate demo --rules rules
```

Pass `--rules` when you want a rules directory other than this project's `rules/`. The JSON answer has the verdict, the exit code, the sha256, and finding metadata. It does not include the file path or the pasted text.

The live page offers default and agent-ingest policies and labels the content view associated with each finding.

## Launch agent

`install-agent` writes a launchd plist and does not load it. You choose the destination. The plist runs `yara-gate watch` with the `--home` you pass. It stores no environment secrets. Logs are named under `~/Library/Logs/yara-gate/`.

```bash
uv run yara-gate install-agent --dest /tmp/com.cgfixit.yaragate.watch.plist --home ~/YaraGate
plutil -lint /tmp/com.cgfixit.yaragate.watch.plist
```

Create `~/Library/Logs/yara-gate` before you load the agent. Loading it is a separate `launchctl bootstrap` that this tree does not run for you.

## CI files

`.github/workflows/ci.yml` and `.github/workflows/codeql.yml` are in the tree. Actions are pinned to commit SHAs. The token permission is `contents: read`, except the CodeQL job which also has `security-events: write`. There is no `pull_request_target` trigger. `.github/dependabot.yml` schedules weekly updates for `uv` and GitHub Actions.

For focused runtime verification, run `uv run python docs/research/probe_rule_coverage.py --verify`. It exercises real library scans and CLI intake in disposable homes, including strict-policy rescans and incomplete coverage, without executing target content. CI runs it on macOS and Linux before the existing regression suites. The [delivery-rule verification](docs/research/modern-delivery-rules.md#executed-verification) records the 16-rule pack's 70 library cases, 16 CLI operations, and three compilation/deadline checks. The initial [research](docs/research/universal-rule-research.md) and [intake verification](docs/verification/intake-coverage.md) preserve earlier evidence and remaining work.

`origin` is `cgfixit/yara-gate`. The workflow files do not by themselves turn on secret scanning, push protection, Dependabot alerts, code scanning, or branch protection. The checked-in CodeQL workflow runs Python queries with `upload: never` and `upload-database: false`; its success alone does not prove a security-dashboard upload. A separate GitHub-managed CodeQL workflow can also appear in PR checks. Repository settings and the exact workflow determine which scanning features run. `.github/dependabot.yml` schedules version updates; Dependabot alerts are a separate repository setting.

## Project files

`pyproject.toml` names the package, the `yara-gate` command, and the ruff and mypy settings. `uv.lock` is the only dependency pin. Do not add a `requirements.txt` beside it. `.python-version` contains `3.12`, which is the interpreter `uv sync` should use. `src/yara_gate/py.typed` marks the importable package as typed. `LICENSE` is the MIT license. `.editorconfig` sets UTF-8, LF, and four-space Python indents so an editor matches ruff.

`.gitignore` drops the virtualenv, caches, `.env` files, `build/`, and coverage output. `rules/vendor/` stays untracked except `rules/vendor/SKIPPED.md` and `rules/vendor/.gitkeep`. `rules/.cache/` stays untracked. The vendor bodies include Elastic rules. This tree does not redistribute those rules.

## Layout

```text
demo.html              single-file browser page for the local patterns
pyproject.toml         package metadata, the yara-gate script, ruff, mypy, pytest
uv.lock                locked dependency set
.python-version        Python 3.12 pin for uv
src/yara_gate/         cli, quarantine, scanner, filetype, heuristics, rules, hunt, report, demo, launchd
src/yara_gate/py.typed empty marker that the package ships types
rules/local/           agent rules and promoted or candidate hunt rules
rules/vendor/          curated packs after an explicit update (not committed, except SKIPPED.md)
rules/rules.lock       pins for those packs
tests/                 fixtures are generated at run time, except the small benign text corpus
```
