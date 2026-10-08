---
name: yara-gate-runtime-verify
description: Verify yara-gate scanner, archive, policy, quarantine, or report changes by running the affected library and installed CLI with inert inputs and disposable homes. Use for behavior and regression checks, not routine prose or image edits.
---

# Verify yara-gate behavior

Inspect `src/yara_gate/cli.py`, `scanner.py`, `content.py`, `models.py`, `quarantine.py`, and `report.py` along the affected path. Read the applicable project instructions and `docs/verification/intake-coverage.md` for dated evidence and limitations. Establish the current revision, dirty state, and locked environment before comparing behavior.

## Use real, isolated paths

Install with `uv sync --frozen --group dev` when needed. Use the resulting `uv run yara-gate` or `.venv/bin/yara-gate`, not another installed checkout. Copy local rules to a disposable rules root and create a disposable gate home. Always pass `--rules` and `--home`; never use the operator's default gate for probes. A scan must leave that rules root unchanged.

For broad changes to the supported scan/intake paths, use the maintained direct probe instead of creating a parallel harness:

```sh
uv run python docs/research/probe_rule_coverage.py --verify
```

It creates inert inputs, copies local rules, invokes the actual library and CLI, checks reports and relocation, and cleans up its temporary homes. It performs no sample execution or vendor download. For a narrower change, call the affected command/API with a positive case, a benign case, and the relevant failure boundary. Catch expected exit 1/2 explicitly rather than treating a detection as a shell failure.

## Check the contract relevant to the change

| Result | CLI exit | Inbox destination |
| --- | --- | --- |
| clean | 0 | clean |
| advisory, default policy | 0 | clean |
| advisory held by agent-ingest | 1 | blocked |
| block | 1 | blocked |
| incomplete | 2 | quarantine |

- Verify JSON verdict/policy, process exit, and physical location together. Scans outside the inbox leave the input in place. For intake/policy changes, resubmit identical bytes under default → agent-ingest → default and check relocation and reports after each operation.
- Incomplete takes precedence over findings. Exercise relevant malformed/encrypted/unsupported archives, failed local compilation, missing input, or timeout paths. Optional vendor compile skips must remain visible.
- For member/decoded findings, verify `member_path`, `view`, namespace, and view-relative offsets. SARIF must not attach member/derived offsets to the outer file's physical region. Reports should contain no matched content; home-prefix redaction does not anonymize every filename.
- For resource-limit changes, use actual bounded reads with inert compressed data and the production constants in `content.py`; do not lower limits or mock the reader and call that resource-limit evidence. Record measured values before making performance claims. Third-party parsers are not hard-preempted by the shared deadline.
- For watcher changes, separately observe initial drain, new-file processing, disposition, shutdown exit, and PID cleanup. Control only the process/home created for the probe. The prior macOS FSEvents crash is a lead to compare against the current baseline, not proof every failure is environmental.

Run relevant Ruff/type checks and lint changed workflows. Prefer focused direct execution locally; hosted CI owns broad pytest/selftest coverage unless a focused test is explicitly needed. Do not relax boundaries or remove regression coverage to make verification pass.

Report the exact revision and engine, inputs/commands, expected versus observed results, and unverified behavior. Separate local runtime from browser evidence and hosted checks. No local synthetic run establishes native Windows support, vendor-pack accuracy, or live CyClaw/Harness integration.
