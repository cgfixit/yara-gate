# Checkout configuration that runs commands (2026-11-05)

Source: `main` at `7f9934c`, branch `rules/config-surface-exec`. Linux x86_64, Python 3.12,
locked YARA-X 1.22.1, a disposable copy of the shipped rules (85 local rules after this change,
no vendor packs). Nothing was executed; every command in a fixture is inert text.

## What was missing

On `main`, a `.git/config` with `core.fsmonitor`, `sshCommand`, a pager, or a filter driver that
fetches or decodes, a `devcontainer.json` `initializeCommand` that downloads to a file and runs
it, and an `.envrc` that downloads, decodes, or opens a socket all scanned clean unless the text
also happened to hold a `curl ... | sh` pipe (`script_download_execute`).

## Change

- A `yara_gate_name` scan global: the lowercased final component of the submitted or member
  name. It is declared with the other globals in `rules.define_scan_globals`, so vendor
  validation and the cache compile it the same way.
- `rules/local/dev_config_surface.yar`, three advisory rules:
  `dev_git_config_exec` (needs a `[core]`, `[pager]`, `[filter "..."]`, or `[diff "..."]`
  section, any name), `dev_devcontainer_lifecycle` (`devcontainer.json` or
  `.devcontainer.json`), and `dev_envrc_exec` (`.envrc`).
- `npx -y <package>` is not matched: it is how MCP and dev container configs normally start a
  server.

## Outcomes

| Probe | Result |
| --- | --- |
| 10 git config hits (fsmonitor, sshCommand, pager, LFS smudge, textconv, `[pager] log`, `/tmp` and UNC `hooksPath`, encoded PowerShell, UTF-16) | advisory, `dev_git_config_exec` only of the three |
| 8 git config controls (origin remote, Git LFS, git-crypt, Watchman, `ssh -i`, delta, Husky `hooksPath`, sops `textconv`, `[alias] !sh -c`, `[color]`, a Markdown mention) | clean |
| 5 dev container hits (host download, host PowerShell array, base64 decode, `/dev/tcp`, inline Python socket) | advisory |
| 5 dev container controls (Python template, `docker network create`, `npm ci`, object form, an installer piped to `sh` inside the container, the same host command in `settings.json`) | none of the three rules |
| 5 `.envrc` hits and 5 controls (nix-direnv `source_url`, `use flake`, `layout`, `pyenv init`, `python3 -c` printing `sys.prefix`, the same download in `setup.sh`) | as expected |

The 38-case probe had one miss on the first pass: git stores a UNC `hooksPath` with each
backslash doubled. The regex now accepts the escaped form.

Zipped checkouts (`repo/.git/config`, `repo/.devcontainer/devcontainer.json`, `repo/.envrc`)
report the rule with member path `zip:0`. CLI intake of a zipped repository under `default`,
`agent-ingest`, and `default` again: exit 0 to `clean/`, exit 1 to `blocked/`, exit 0 to
`clean/`, finding severity `advisory` each time.

## Checks

- `lint_rules.py` (85 rules), `check_rule_pairs.py` (112, six new pairs),
  `check_added_rules.py` (103 cases, including zip members and the same bytes under another
  name), `check_rules_lock.py`, `check_scan_only.py`, `check_intake.py`,
  `check_text_controls.py`, `probe_rule_coverage.py --verify`, `yara-gate selftest`: pass.
- `measure_precision.py --fail-over`: exit 0 on 324 files. The four new checkout files (two git
  configs, a dev container, an `.envrc`) hit no rule under `default` or `agent-ingest`.
- `ruff check .`, `ruff format --check .`, `mypy --strict src`, and
  `pytest tests/test_scanner.py tests/test_rules.py tests/test_cli.py tests/test_pages_*.py`
  (171 passed, 1 skipped): pass. Ruff caught one regression in the first draft: the loop
  variable that sets globals shadowed the new `name` argument. The two `_invoke_scan`
  stand-ins in `selftest.py` and `tests/test_scanner.py` gained the keyword.
- The full pytest run was killed by the container (exit 137) and is left to hosted CI.

## Not established

No real-world corpus of `.git/config`, dev container, or direnv files was measured, and
`textconv = sh -c ...` is a legitimate shape some teams use; it is reported as advisory.
