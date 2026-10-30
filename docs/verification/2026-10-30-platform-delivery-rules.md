# Build, install, and credential-store rules for Windows, macOS, and Python (2026-10-30)

Baseline: `main` `d81ec5c`. Host: Linux container, Python 3.12.3, YARA-X 1.22.1,
the locked environment (`uv sync --frozen --group dev`; `uv lock --upgrade`
resolved no changes). Every run used a copied rules tree, a disposable cache,
and a disposable gate home. No sample was executed, no URL in a fixture was
fetched, and no vendor pack was downloaded.

## Rules added

| Rule | File | Platform | Source |
| --- | --- | --- | --- |
| `win_msbuild_inline_task` | `windows_build_install.yar` | Windows | [T1127.001](https://attack.mitre.org/techniques/T1127/001/), [LOLBAS MSBuild](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/) |
| `win_inf_scriptlet_install` | `windows_build_install.yar` | Windows | [T1218.003](https://attack.mitre.org/techniques/T1218/003/), [LOLBAS Cmstp](https://lolbas-project.github.io/lolbas/Binaries/Cmstp/) |
| `win_browser_credential_decrypt` | `credential_store_theft.yar` | Windows | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) |
| `macos_stealer_password_check` | `credential_store_theft.yar` | macOS | [Elastic on Banshee](https://www.elastic.co/security-labs/beyond-the-wail), [T1555.001](https://attack.mitre.org/techniques/T1555/001/) |
| `macos_jxa_remote_exec` | `macos_jxa_lures.yar` | macOS | [T1059.007](https://attack.mitre.org/techniques/T1059/007/) |
| `dev_python_pth_exec` | `dev_package_hooks.yar` | all | [T1546.018](https://attack.mitre.org/techniques/T1546/018/), [LiteLLM 1.82.7/1.82.8](https://github.com/BerriAI/litellm/issues/24518) |

All six are advisory. Benign collision counts that set the boundaries
(`RoslynCodeTaskFactory` in about 1,900 `.targets` and `.csproj` files,
`RunPreSetupCommandsSection` in about 74 INFs including Connection Manager
templates, `deploymentProvider codebase="http` in about 5,400 `.application`
files, `dscl` authonly with a hidden-answer dialog in about 120 to 150 admin scripts)
are approximate GitHub code-search totals from October 2026, not measurements
on this host. They are why each rule needs a second signal, and why ClickOnce,
Terminal `.terminal` profiles, and `node -e` install hooks were not built.

## Direct evidence on this host

| Check | Before (`d81ec5c`) | After |
| --- | --- | --- |
| `lint_rules.py` | 67 rules | 73 rules, 0 skips |
| `check_rule_pairs.py` | 89 | 95 |
| `check_added_rules.py` | 46 | 50 (a `.pth` inside a wheel member included) |
| `measure_precision.py --fail-over` | 267 files, 63 of 67 rules at 0 | 279 files, 69 of 73 rules at 0; the same four tagged Windows collisions |
| `probe_rule_coverage.py --verify` | passed | passed: 73 compiled, 484 library cases, 44 CLI operations |
| `check_scan_only.py`, `check_text_controls.py`, `check_rules_lock.py` | pass | pass |
| Ruff check and format | clean | clean |

The probe fixtures added to `windows-format-signatures.json` and
`unix-signatures.json` cover raw, UTF-16 (BOM and BOM-less LE), zip and gzip
members, and near-misses. Member findings carry `zip:0`/`gzip:0` and UTF-16
findings `decoded-utf16`. Two correct co-fires are recorded as such: the INF
pre-setup fixture also matches `script_mshta_remote`, and the AMOS fixture also
matches `macos_password_prompt`. The MSBuild probe CLI case is advisory/exit 0
into `clean/` under the default policy and block/exit 1 into `blocked/` under
`agent-ingest`, with the original advisory severity and no input text in the
reports.

Fire/miss matrices run through `scan_file` (scratch harness, not committed):
`win_msbuild_inline_task` 9/9 (misses: an inline task that starts git, one that
formats text, one that downloads text, a plain SDK project, and prose naming the
APIs), `win_inf_scriptlet_install` 8/8 (misses: a Connection Manager profile, a
driver INF, a local scriptlet, prose), `win_browser_credential_decrypt` 6/6
(misses: a path deny-list, a threat-report sentence, a DPAPI wrapper without the
store), `macos_stealer_password_check` 5/5 (misses: a LAPS rotation script and a
password tester), `macos_jxa_remote_exec` 7/7, `dev_python_pth_exec` 9/9
(misses: `distutils-precedence.pth`, `_virtualenv.pth`, an editable-install
`.pth`, a path-only `.pth`, the same line in a `.py` file).

## Benign sweep

65,057 local files were scanned with the `d81ec5c` rules and with this branch's
rules:

- 34,440 files up to 1 MB from `/usr/share`, `/etc`, the Python 3.12 standard
  library, the project venv, the Node 22 global packages, `/opt/node-tools`
  packages, and the Ruby 3.3 library.
- The 76 files over 1 MB in the same roots.
- 30,541 files up to 1 MB from the Google Cloud SDK, including its bundled
  Python.

No file gained or lost a finding, and no incomplete reason changed.

Every `.pth`, `.targets`, `.props`, `.csproj`, `.inf`, `.scpt`, and `.jxa` file on
the host (19 files: 17 `.pth`, including setuptools, virtualenv, editable, and
path-only shapes, and 2 `.targets`) was also scanned with this branch's rules;
none matched. The host is Linux, so it holds no Windows build trees or macOS
admin scripts; the near-miss fixtures above stand in for them. This is a
system and package corpus, not a production false-positive rate.

## Public repository sweep

25,668 files up to 1 MB from shallow clones of nine public repositories were
scanned with the `d81ec5c` rules and with this branch's rules. The clones were
taken on 2026-10-30 and treated as untrusted data; nothing in them was run.

| Repository | Commit | What it covers |
| --- | --- | --- |
| dotnet/msbuild | `86743d0` | MSBuild targets and inline-task tests |
| dotnet/arcade | `c4681eb` | `eng/` build targets |
| microsoft/Windows-driver-samples | `f4c1ff8` | driver INFs |
| rtrouton/rtrouton_scripts | `aa27142` | Mac admin scripts |
| joshua-d-miller/macOSLAPS | `5dd5e59` | `dscl` password handling |
| anthropics/claude-code | `d4dfed4` | Claude Code settings, hooks, and examples |
| github/awesome-copilot | `5269f7e` | Copilot and VS Code customizations |
| openai/codex | `275a9a8` | Codex config and tests |
| pypa/setuptools | `049ae8e` | `.pth` sources |

This branch matches the baseline on all 25,668 files: no file gained or lost a
finding. The set includes real inline MSBuild tasks (dotnet/msbuild and
dotnet/arcade), real driver INFs, Mac admin scripts that run `dscl`, macOSLAPS,
and setuptools' `.pth` sources.

## Consumer corpus

The 150 files in [`agent-ingest-corpus.jsonl`](agent-ingest-corpus.jsonl) were
read at their pinned revisions (CyClaw `34b44e1`, CG-agent-harness `3301c0c`),
and every SHA-256 matched. The full trees at current HEAD (CyClaw `a5b5212`,
CG-agent-harness `ff5df3a`, 1,469 files) were also scanned. Comparing the
`d81ec5c` rules with this branch's rules, no file gained or lost a finding in
either set.

Not run: a sweep of private Windows build repositories or Mac admin script
collections. Hosted CI
(Ubuntu, macOS, Windows) and CodeQL results belong to the pull request head,
separately from this record.

## Known gaps

- An inline task that hides its API names (reflection by string, or a renamed
  import) passes `win_msbuild_inline_task`.
- `win_browser_credential_decrypt` covers the Chromium DPAPI key path; Firefox
  NSS decryption and the app-bound key's elevation-service path are not matched.
- A `.pth` whose import line hides `exec` behind `getattr` or string building
  passes; the file still runs at startup.
