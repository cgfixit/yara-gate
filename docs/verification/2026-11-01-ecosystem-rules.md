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

## Review follow-up: bounded Keras walk

FACT. Codex security review on #142 reported that `_walk_keras` queued every child of a container before the 200,000-node cap applied. Reproduced on a 4,000,032-byte `model.json` holding a list of 2,000,000 inert values, measured with `tracemalloc`: `keras_config_findings` peaked at 142,842 KiB and took 4.29 s, against 20,634 KiB and 1.85 s for `mcp_tool_findings` on the same bytes (the `json.loads` both share). The walk now keeps one lazy iterator per open container. Its stack is bounded by the depth cap, and the node cap ends the walk. After the change, the Keras path peaks at 20,634 KiB and takes 2.09 s. All 18 direct fixtures still match their expectations.
