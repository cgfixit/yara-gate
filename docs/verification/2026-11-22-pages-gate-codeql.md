# The Pages deploy gate and a commit CodeQL never ran on

Date: 2026-11-22. Base: `main` at `bed66d4`. Python 3.12.3, x86_64 Linux container. The gate
was run as a library call with run and check records in the Actions API's shape; no deploy
was started and nothing was sent to GitHub. The history count below came from a delegated
read-only lookup of the Actions API and was not recounted. Nothing here is hosted CI.

## The lead

[#322](https://github.com/cgfixit/yara-gate/issues/322), item 6.
`scripts/pages_deploy_gate.py` says it deploys only when "every other check on that commit
has finished green: the ci workflow, CodeQL, and any other check suite". `evaluate` required
the `ci` run to be present. Every other check was judged only if it was there: a red one
refused, a running one waited. A commit with no CodeQL run had nothing red and nothing
running.

## Reproduced on the base

`evaluate(runs, checks, own_run_id)`. The run records use the ids, paths, events, and
`head_branch` the API returned for `bed66d4`; the check records are written by hand.

| Commit state | Base `bed66d4` | Change |
| --- | --- | --- |
| `ci` passed, CodeQL analysed and passed | green | green |
| `ci` passed, no CodeQL run on the commit | **green** | pending, `CodeQL has not passed on this commit` |
| `ci` passed, CodeQL run cancelled before it made a check | **green** | pending, the same |
| `ci` passed, an `Analyze (python)` check failed | red | red |
| `ci` passed, `Analyze (python)` still running | pending | pending |

`decide` turns a state that is still pending at the deadline into
`refusing: checks still running at the deadline: CodeQL has not passed on this commit`.

## The change

After the red and pending checks, `evaluate` requires one workflow run on the commit whose
path is `dynamic/github-code-scanning/codeql` (`CODEQL`), whose `head_branch` is `main`, and
which completed with `success`. It comes last so a failed analysis is still reported by its
own check, as red, and not as a wait.

## Does CodeQL run on every push to main?

If it did not, this change would stop deploys that go through today. Counted by a delegated
lookup of the Actions API on 2026-11-22 (`ci` push runs on `main` beside default-setup
CodeQL runs on `main`, matched by commit):

- Every `ci` push run since 2026-10-18 has a CodeQL run on the same commit: 235 of 235. The
  two runs are created within 2 s of each other in all but one case (10 s).
- Documentation-only pushes are included; three were confirmed by their file lists.
- Eight `ci` pushes from 2026-10-08 to 2026-10-13 have none. One has only the `CodeQL Setup`
  run, and the CodeQL workflow has no run of any kind between 2026-10-08 and 2026-10-18,
  so that reads as the days before default setup was on. That is an inference from the run
  numbers, not something the API states.
- Five CodeQL push runs on 2026-10-23 did not succeed (four cancelled, one failed while `ci`
  passed). All later ones are `success`.
- A commit can carry a second CodeQL run named `Scheduled`; the rule needs one success.

`ci` takes about 23 minutes on `main` and the analysis about 90 seconds, so by the time the
gate starts, the analysis has normally finished.

## Checks

`tests/test_pages_deploy.py` gained two tests. Against the base script both fail; on the
change the file gives 11 passed. `ruff check`, `ruff format --check .`,
`mypy --strict src scripts`, `docs/verification/check_doc_links.py`, and
`docs/verification/check_text_controls.py` pass. The workflow file is unchanged, so
actionlint and zizmor were not run.

## What this does not cover

- **A hosted run.** The gate was not run inside `demo-results-page` on a real commit. The
  first merge to `main` after this one is that test: its gate step should print
  `deploy <sha>: every other check passed`.
- **The `CodeQL` results check.** The gate requires the analysis run. The separate check
  that reports new alerts is read when it is present, as before; whether it appears on every
  push to `main` was not established, so it is not required.
- **CodeQL turned off or moved.** With default setup disabled, or replaced by a workflow
  file, no run has that path and every deploy stops at the 20-minute deadline until
  `CODEQL` is changed. That is the intended direction of failure, and it costs a deploy.
- **A branch other than `main`.** The rule names `main`, as the gate already does when it
  reads the head commit.
