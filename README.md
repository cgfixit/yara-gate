# yara-gate

yara-gate holds untrusted files until a local scan finishes. Drop a document in the inbox. The file moves to `clean/` only after the scan completes with a clean or advisory verdict. A block match moves it to `blocked/`. An unfinished scan leaves it in `quarantine/`. Readers such as an indexer or an agent should open files only from `clean/`.

The scan does not use the network. Curated rule packs are downloaded only when you run `rules update --allow-network`. A rule is generated only after you confirm a file that is already in `blocked/`, and that candidate does not block anything until you promote it.

This tree is local. It is not a GitHub repo.

## Install

From the project directory, on macOS or Linux, with [uv](https://docs.astral.sh/uv/) and Python 3.12:

```bash
cd ~/Projects/yara-gate
uv sync
uv run yara-gate --version
```

`yara-gate 0.1.0` is the version this tree prints. The scanner imports the `yara-x` package (the lock resolves 1.21.0). It does not call the Homebrew `yara` binary.

`uv run yara-gate selftest` rebuilds the local fixtures and exits 0 only when every expected verdict matches. A fresh copy of this directory can run the same two commands. Selftest does not download malware. It writes the EICAR test string and small synthetic documents at run time.

## Drop folder

The default root is `~/YaraGate/`. Pass `--home` to use another directory.

| Directory | Role |
| --- | --- |
| `inbox/` | Drop files here |
| `quarantine/<sha256>/` | File is being scanned, or the scan did not finish |
| `clean/<sha256>/` | Clean or advisory. Safe for a downstream reader |
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

On intake the tool hashes the file, copies it into `quarantine/<sha256>/`, strips the executable bit, and removes the inbox copy. Dropping the same bytes again reuses that slot.

## Exit codes

| Code | Verdict | Where the file goes |
| --- | --- | --- |
| 0 | `clean`, or `advisory` only | `clean/` |
| 1 | `block` | `blocked/` |
| 2 | `incomplete` | stays in `quarantine/` |

Advisory matches are listed in the report and set `"advisory": true`. They still exit 0. An unreadable file, a timeout, a size limit, a rules compile failure, or a missing `yara-x` import exits 2. An unhandled exception exits 2 and the message is the exception class name.

## Reports

Every scan writes both report files, including a clean scan. A finding stores the rule id, byte offset, and byte length. It does not store the matched bytes. Paths under your home directory are written as `~/...`. The path in the report is the quarantine path at scan time. The file is moved to `clean/` or `blocked/` after the report is written.

## Rule packs

`rules update` refuses to run unless you pass `--allow-network`. That is the only command that opens a network connection.

```bash
uv run yara-gate rules update --allow-network
```

`rules/rules.lock` records the URL, pinned tag or commit, and sha256 of each download. The packs are YARA Forge core, Florian Roth's signature-base (`yara/` files), and Elastic protections-artifacts (`yara/` files). Rules that do not compile under yara-x are skipped and listed in `rules/vendor/SKIPPED.md`. If nothing compiles, scans exit 2.

The update run on 2026-10-04 pinned:

| Pack | Pin | Download sha256 |
| --- | --- | --- |
| yara-forge-core | `20261004` | `0b548dff76139b7a041d20923ccfddfa614db6b6ee8710c181ff037a753ffe69` |
| signature-base | `94a1c48d7ab499879287ff611dfe7f9c56376030` | `13895e9219e844beeba1f5d7d3e3261a81e4e8f69cf18cc823d3abcc16e601a3` |
| elastic | `83e227669df8a13a2a2fee52c14b742c0d5f17cc` | `ed1d0e2a11f5deab2de5c8978cf6667d1a53202b5bdb5c11b96c30cdb153ef8a` |

That compile produced 13535 rules and skipped 13. The on-disk rule-set hash is `47c2df1280a7fabf1d0110d7177b1ab215b8e2109d378f954886a44b336330c2` (`rules/.cache/<hash>.yarc`, not committed). Vendor rule bodies are not committed. Elastic's rules are under the Elastic License 2.0. They stay in this local tree and are not packaged for redistribution.

Local rules in `rules/local/agent_*.yar` ship with the tool. They do not need a download. `agent_eicar` matches the EICAR test marker so a scan can block that file before any vendor update.

## What this catches, and what it does not

It does well against common malicious documents that already have a public signature. The curated packs cover a lot of Office malware, script-in-document droppers, and known strings. The local heuristics add Office auto-exec macros (`olevba`), risky PDF tokens (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`, `/EmbeddedFile`, `/RichMedia`), and an executable header that is not the first byte of the file. The agent rules block invisible Unicode and bidirectional overrides. Long base64 runs, prompt-injection phrases, and hidden HTML are advisory.

It does poorly against a new or targeted payload. YARA matches patterns somebody has already written down. Building a rule from the file you are judging only describes that file, so the tool never does that.

Other limits, measured in this tree:

- Archives are zip and tar only, nested at most 3 levels, with a 100 MB file cap and a 500 MB extraction cap. gzip is recognized and not expanded. 7z and rar are not opened.
- Member bytes inside the cap are YARA-scanned. PDF and Office heuristics run on the outer file.
- A zip header that lies about size is stopped by a capped read, not by a full decompression of a bomb.
- A `.pdf` that is really a zip is an advisory type mismatch and exits 0. A `.pdf` that is really a PE, ELF, or Mach-O exits 1.
- A scan of a path outside the inbox does not move that file.

## Hunt

```bash
uv run yara-gate hunt --confirmed <sha256> --reason "why this file is bad" --scope ~/some/folder
uv run yara-gate rules promote <id>
```

`--confirmed` must name a file already in `blocked/`, and `--reason` is required. The candidate keeps distinctive strings longer than 8 bytes that do not appear in `tests/fixtures/benign/`. It must hit the confirmed file and zero benign files. It is written to `rules/local/hunt_<first 12 hex of the sha>.yar` with `status = "candidate"`. Candidates are not loaded as block rules. `rules promote` rewrites the status to `promoted` and `verdict_on_match` to `block` only after the new text compiles.

## Library

```python
from yara_gate import scan_file

result = scan_file("attachment.bin", timeout_s=30)
result.verdict  # "clean", "advisory", "block", or "incomplete"
```

`scan_file` does not move files and does not open a socket. Pass `rules_dir` to point at a different rules tree. The default is this project's `rules/` directory. A later caller, including CyClaw before chunking, can use this function without taking the drop folder.

## Layout

```text
src/yara_gate/    cli, quarantine, scanner, filetype, heuristics, rules, hunt, report
rules/local/      agent rules and promoted or candidate hunt rules
rules/vendor/     curated packs after an explicit update (not committed, except SKIPPED.md)
rules/rules.lock  pins for those packs
tests/            fixtures are generated at run time, except the small benign text corpus
```
