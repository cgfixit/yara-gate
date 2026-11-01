# Vendor resync and the first ecosystem rules (2026-11-01)

Base revision `b663dda` (`main`). Linux container, Python 3.12.3, YARA-X 1.22.1. Disposable rules roots and gate homes under a scratch directory; `~/YaraGate` was not used. Nothing was executed and no URL from a fixture was fetched.

## Vendor resync

FACT. `yara-gate rules install --allow-network --rules <scratch copy>` downloaded the three locked packs. The sha256 values matched `rules.lock`. It compiled 13,629 rules (80 of them local at the time) and skipped the same 13 signature-base files listed in `rules/vendor/SKIPPED.md`. The rewritten skip list now prefixes each name with `vendor/signature-base/`; the committed copy predates that format. README's 13,535 figure for the same pins was not reproduced here (13,549 vendor rules); the gap was not investigated.

FACT. `rules update` stopped with `HTTP 401 from api.github.com` while the container's empty `GITHUB_TOKEN` was set, and with `rate limited by api.github.com` without it. The lock was not changed.

FACT. To see drift without the API, the current heads were taken from `git ls-remote`, a shallow clone, and the yara-forge release asset, then compiled with `compile_sources` beside the locked tree:

| Pack | Locked pin | Current upstream |
| --- | --- | --- |
| yara-forge core | `20261004` | `20261101` |
| signature-base | `94a1c48` | `36ab704` (2026-10-29) |
| elastic | `83e2276` | `c7b3b2e` (2026-10-23) |

The current heads compile 13,591 rules from 1,810 vendor files, against 13,629 from 1,809. They add `elastic/rules/MacOS_Trojan_CloudSyncD.yar` and `signature-base/hktl_adaptixc2.yar`, remove `signature-base/airbnb_binaryalert.yar`, and change no compile skip. A pin bump is a separate change made with `rules update`.

## What the packs cover

FACT. Elastic's 1,056 files are 734 `Windows_`, 248 `Linux_`, 48 `MacOS_`/`Macos_`, and 26 `Multi_` (ransomware, C2 implants, miners). signature-base and yara-forge core (5,136 rules) are mostly APT, malware-family, hack-tool, and webshell signatures for binaries and server files. A case-insensitive search of all three packs found no rule for GitHub Actions workflows (`runs-on`, `toJSON(secrets)`), Keras, ONNX, safetensors, Hugging Face, or Jupyter notebooks. signature-base has IOC rules for specific malicious npm packages (`mal_npm_supply_chain_*`) and Claude refusal magic strings.

## Ecosystems chosen (assessment)

The packs answer "is this a known malware binary on Windows, Linux, or macOS". yara-gate's intake is cloned repositories, synced corpora, and model files an agent is about to read. Three ecosystems fit that intake and have no vendor coverage:

1. **GitHub (Actions workflows).** A cloned or synced repository can carry a planted workflow. The 2025 npm worms used two shapes: Shai-Hulud's `toJSON(secrets)` dump and Shai-Hulud 2.0's self-hosted-runner `discussion.yaml`. Built as `dev_github_workflow_secrets_dump` and `dev_github_workflow_runner_backdoor` (advisory).
2. **Keras / Hugging Face model configs.** README already lists model files as an intake channel, and pickle, safetensors, and GGUF are checked. Keras `.keras`/`.h5` configs, whose `module` references run code even with `safe_mode` (CVE-2025-1550, CVE-2025-8747, CVE-2025-9906), were not. Built as `heuristic_keras_unsafe_call` (block) and `heuristic_keras_lambda` (advisory).
3. **npm (package lifecycle hooks).** Not built. signature-base already carries the campaign IOCs, and the 2026-10-30 roadmap records that `postinstall` running `node -e` is ordinary (core-js), so a behavioral rule needs a benign census first.

## Commands and outcomes

```sh
uv run python docs/verification/lint_rules.py          # local rules compiled and linted (82)
uv run python docs/verification/check_added_rules.py   # added-rule checks passed (81)
uv run python docs/verification/check_rule_pairs.py    # rule pairs passed (109 rules)
uv run python docs/verification/measure_precision.py --fail-over   # 320 files, 0 incomplete
uv run python docs/research/probe_rule_coverage.py --verify        # passed, 82 compiled, 0 skipped
uv run mypy --strict src                                # no issues in 16 files
uv run ruff check src docs/verification && uv run ruff format --check src docs/verification
uv run python docs/verification/check_text_controls.py
```

FACT. A direct probe of 18 inert fixtures under `agent-ingest` matched its expectations. The fixtures were the two Shai-Hulud workflow shapes, a block-scalar `run:`, the secrets-to-env action, one named secret in `curl`, event text on a hosted runner, a self-hosted job that reads event text only through `if:` and `env:`, `.keras` archives with `os.system`, `keras.utils.get_file`, `enable_unsafe_deserialization`, `__lambda__`, a plain and a custom-layer config, a Keras 2 `.h5` with `function_type: lambda` and a plain one, a `model.to_json()` file naming `subprocess.Popen`, and an MCP config. Keras findings inside an archive carry `member_path` `["zip:1"]` and no offset.

FACT. CLI under the default policy: workflow fixtures exit 0 with an advisory verdict, and `os.keras` exits 1. Through a scratch inbox, `os.keras` moved to `blocked/<sha256>/`, the advisory workflow and a plain `.keras` moved to `clean/<sha256>/`, and reports were written for all three. An identical resubmission of `os.keras` blocked again and left the inbox empty. `scan - --name discussion.yaml` gave the same verdict as the file.

FACT. A 2.2 MB file of repeated block-scalar `run:` steps and a 1.1 MB file of repeated `toJSON(secrets)` lines scanned in 0.57 s and 0.34 s wall time including start-up, against 0.64 s and 0.40 s with the base rules.

FACT. The 10 new benign corpus files (five workflows, five Keras files) produce no finding of any id.

## Not covered

- Event text interpolated into `run:` on GitHub-hosted runners, the common injection weakness. It is a vulnerability rather than a planted backdoor, and it occurs in many ordinary repositories.
- Workflows that send secrets one by one (GhostAction), a secret dump split across steps more than 1 KB apart, and a self-hosted label that is not first in its `runs-on` list.
- AI-agent actions that receive issue text as a prompt (the "PromptPwnd" shape).
- Keras configs inside HDF5 chunked or compressed storage, ONNX, TensorFlow SavedModel, and Jupyter notebooks.
- Hosted CI has not run on this change at the time of writing.

## First-run setup and the vendor false-positive census

`yara-gate setup` is the first-run download of the locked packs. It runs the same `install_packs` path as `rules install` (sha256 per pack, compile before swap, old tree and lock kept on failure), without the `--allow-network` flag: running it is the consent. It skips the network when the lock's `installed_vendor_files` are all present, and `--force` downloads again. A scan never downloads. When stderr is a terminal and the packs are not installed, a scan prints one `note:` line on stderr.

FACT. Against a scratch rules root copied from the checkout:

| Step | Outcome |
| --- | --- |
| `scan` on a pseudo-terminal before `setup` | the `note:` line, then the normal result, exit 0 |
| the same `scan` piped | no `note:` line |
| `setup` | three packs, sha256 matched, `compiled_rules=13631 skipped_rules=13`, exit 0, 32 s |
| `setup` again with the proxy pointed at a closed port | `already set up`, exit 0 |
| `scan` after setup with the proxy closed | normal verdict; no network |
| one recorded vendor file deleted | `scan` exits 2 `installed vendor rules missing`; `setup` reinstalls it |
| `setup --force` with a wrong sha256 in the lock | exit 2 `incomplete: ValueError`; 1,810 vendor files and the lock unchanged |

FACT. Census: the 320-file benign corpus was scanned under each policy with bundled rules only and with the locked vendor packs installed. Two vendor rules matched, both from signature-base `gen_url_persitence.yar`. Vendor rules have no `verdict_on_match`, so the scanner records every vendor match as `block`.

| Rule | Its own metadata | Files | Verdict change |
| --- | --- | --- | --- |
| `Methodology_Contains_Shortcut_OtherURIhandlers` | "Noisy rule", `score = 35` | `Mail the team.url` (`mailto:`), `Spacewar.url` (`steam://`) | clean to block under every policy |
| `Methodology_Suspicious_Shortcut_Local_URL` | `score = 50` | `Handbook.url` (a local `file:` URL, already a tagged advisory collision) | advisory to block under the default policy |

ASSESSMENT. With the packs installed, 2 of 320 ordinary files (0.6%) are newly blocked. The corpus is text, documents, and shortcuts, and it has no benign PE, ELF, or Mach-O files, where most vendor rules apply. So this census bounds the text-side risk only. AGENTS.md says metadata does not implement policy, so the scanner deliberately does not map signature-base `score` to a severity. Downgrading or skipping a vendor rule would need a reviewed, committed list; that is not built here.

## Reviewed vendor overrides, the untracked inventory, and the sha256 message

`rules/vendor-overrides.json` is a committed list of reviewed decisions. It is packaged in the wheel as `bundled_rules/vendor-overrides.json`. A YARA match whose rule declares no `verdict_on_match` takes the action the list names (`skip`, `note`, or `advisory`), and it is `block` when the list does not name it. The list starts with the two rules from the census: `Methodology_Contains_Shortcut_OtherURIhandlers` is skipped and `Methodology_Suspicious_Shortcut_Local_URL` is advisory. `lint_rules.py` parses it and rejects a local rule name. With vendor files loaded, the list's bytes enter the ruleset digest.

FACT. Census repeated with the overrides on the locked packs: under the default, `agent-ingest`, and `agent-document` policies, all 320 files get the same verdict as with the shipped rules alone. The one remaining vendor match is the advisory `Methodology_Suspicious_Shortcut_Local_URL` on `Handbook.url`, which was already a tagged advisory.

FACT. `check_added_rules.py` adds three inert stand-in vendor rules: the skipped one gives no finding, the lowered one is advisory, and an unlisted one is block. With the list removed, the first two report `block`, so the check fails. With an invalid action in the list, every scan is incomplete with `invalid vendor-overrides.json`, and `lint_rules.py` fails.

FACT. `vendor.installed.json` beside `vendor/` now holds the installed-file inventory; `.gitignore` lists it. After `setup` on a copy of the checkout lock, the lock's sha256 was unchanged (`e0edf088…`) and the inventory held 1,809 names. Removing the whole `vendor/` still exits 2 with `installed vendor rules missing`. A legacy lock that carries `installed_vendor_files`, with one listed file deleted, still exits 2; `setup` then reinstalls, moves the list to `vendor.installed.json`, and drops it from the lock. Changing the override list changes the vendor root's ruleset digest.

FACT. A wrong sha256 in the lock now prints `incomplete: sha256 mismatch for elastic` from both `setup --force` and `rules install --allow-network`, exit 2. The exception is `RuleIntegrityError`, a `RuleDownloadError` that is also a `ValueError`, as the existing test expects.

FACT. `uv run pytest -q tests/test_rules.py tests/test_cli.py`: 65 passed, 1 skipped. Run because these changes move lock and inventory behavior those tests pin.
