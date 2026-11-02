# GitHub Actions rule precision — November 2, 2026

Source: `main` at `38e100bbc559e86e570e3361256498d3a0c23420`, plus the change to
`rules/local/dev_github_workflow.yar` on branch `claude/workflow-rule-precision`.
Python 3.12.3, YARA-X 1.22.1, 82 bundled rules, no vendor packs. Every input was
an inert YAML file scanned with `scan_bytes` against a disposable copy of
`rules/local` and `rules/rules.lock`; nothing was run or fetched.

## What was wrong on the baseline

A review of the two workflow rules produced 29 inert inputs. On the baseline,
under `agent-ingest`:

| Input | Baseline | Why it matters |
| --- | --- | --- |
| secrets-to-env action, then `npm run build` and `actions/upload-artifact` | block (`secrets_dump`) | The documented clean shape matched whenever a `curl`, `base64`, or upload sat within 1 KB |
| `toJSON(secrets)` to a local action, then `base64 -d` of a keystore | block (`secrets_dump`) | Same |
| Self-hosted `build` job, then a hosted `triage:` job whose first line is a comment (or blank) | block (`runner_backdoor`) | The job-header pattern needed a key on the very next line, so the second job was not seen |
| `runs-on: Self-Hosted` | clean | GitHub matches runner labels case-insensitively |
| `runs-on:` as a block list (`- self-hosted`) | clean | Same runner, other YAML form |
| `environment:` with `name: ops` (or `env:` with `name: x`) inside the job | clean | The loose 2–4 → 4–8 indent pattern read the map as a new job header: an easy evasion |
| `run: \| # handle` block scalar | clean | A trailing comment broke the block-scalar pattern |

## Change

- `secrets_dump` skips an expansion that is the whole value of an input under
  `with:` (after up to 16 single-line sibling inputs). The dump still matches in
  `run:`, `env:`, and a `github-script` block.
- `runner_backdoor`: `$self_hosted` is case-insensitive and accepts the block-list
  form; block scalars accept a comment after `|`/`>`; a job header is a key at
  indent 2, 3, or 4 whose first key line, after comment or blank lines, sits at
  exactly twice that indent.

## Observed after the change

All seven rows above flipped as intended (the two `secrets_dump` and the two
cross-job false positives are clean; the five evasions are advisory and held under
`agent-ingest`). Unchanged: both Shai-Hulud shapes (webhook `curl` and the
formatter artifact), a `github-script` `fetch` that embeds the dump, CRLF and
`toJson( SECRETS )` variants, 2-, 3-, and 4-space cross-job cases, and the
`if:`/`env:`/`github-script` reads of event text. Flow-style steps, `format()`,
`xxd`, `gh gist`, and other-case event fields stay unmatched, and a `$GITHUB_ENV`
export near an unrelated `curl` still matches; `docs/rules.md` lists these.

Seven fixtures were added to `docs/verification/check_added_rules.py`. Against the
baseline rule, six fail (`secrets-to-env-upload.yml`, `other-job-comment.yml`,
`environment.yaml`, `block-comment.yaml`, `label-case.yaml`, `label-list.yaml`);
`formatter.yml` passes on both and guards the `with:` exclusion.

CLI, disposable home and rules, `--policy agent-ingest`: the secrets-to-env
workflow in the inbox exited 0 and moved to `clean/`; the `environment:` backdoor
exited 1 and moved to `blocked/`; reports were written for both.

```sh
uv run python docs/verification/lint_rules.py          # 82 rules; vendor overrides (2)
uv run python docs/verification/check_rule_pairs.py    # 109 rules
uv run python docs/verification/check_added_rules.py   # 92 plus 3 vendor-override cases
uv run python docs/verification/measure_precision.py --fail-over   # exit 0
uv run python docs/research/probe_rule_coverage.py --verify        # passed
```

This is synthetic evidence, not a production false-positive rate; other YAML
spellings and real repositories were not surveyed.
