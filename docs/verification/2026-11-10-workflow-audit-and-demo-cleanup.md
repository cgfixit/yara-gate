# Workflow audit, link check, and demo cleanup — November 10, 2026

Base: `main` at `cd2e0d4`. Exercised at `b320563` on this branch. Python 3.12, YARA-X 1.23.0,
85 bundled rules, no vendor packs, Ruff 0.17.3, mypy 2.4.1, zizmor 1.32.0, actionlint 1.7.12
built with `go install`. One pull request was open,
[#201](https://github.com/cgfixit/yara-gate/pull/201) at `ba8cc3e`; its overlap is recorded
below. No scanner, rule, policy, or intake behavior changes. One recorded value changes: a hunt
candidate's `created` date is now the UTC date.

## What changed

| Area | Before | This change |
| --- | --- | --- |
| Deploy workflow | `.github/workflows/pages-demo.yml`, `name: pages-demo` | `.github/workflows/demo-results-page.yml`, `name: demo-results-page`; job names unchanged |
| Deploy gate | `SELF` named the old path | `SELF` names the new path; a test ties the two together |
| Workflow audit | actionlint only | actionlint, then zizmor (offline, pedantic) from the lock file |
| Markdown links | Not checked | `check_doc_links.py` fails a relative link or heading anchor that does not resolve |
| Ruff | `E F I UP B S` | adds `DTZ`, `PGH004`, `PLE`, `RUF100`, `T10` |
| mypy | `--strict src` | `--strict src scripts` |
| Root `demo.html` | A launcher page repeating the README | Removed, with every reference to it |

## Reproductions

### The rename and the gate

`evaluate` was called with a successful ci run, an earlier cancelled run of the deploy workflow,
and the gate's own run in progress.

| `SELF` | Path the runs report | Result |
| --- | --- | --- |
| `demo-results-page.yml` | `demo-results-page.yml` | `green` |
| `demo-results-page.yml` | `pages-demo.yml` (the gate and the file disagree) | `red`: `Re-record and build the demo: cancelled` |

So a rename that leaves `SELF` behind refuses a deploy whenever an earlier run of the workflow
on that commit was cancelled or failed. The new test in `tests/test_pages_deploy.py` was run
against four edits, each restored afterwards, and failed on each: `SELF` on the old path, ci's
name changed under `workflow_run`, the workflow's own path removed from `paths`, and a `name`
that differs from the file name.

### What zizmor adds to actionlint

Each row is one edit to a copy of `ci.yml`, linted by both tools.

| Edit | actionlint 1.7.12 | zizmor 1.32.0 |
| --- | --- | --- |
| `actions/checkout` pinned to `v7` instead of a commit | passes | fails: `unpinned-uses` |
| `persist-credentials: false` removed | passes | fails: `artipacked` |
| `permissions: write-all` | passes | fails: `excessive-permissions` |
| `${{ github.event.pull_request.title }}` inside a `run` script | not tried | fails: `template-injection` |

On the tree before this change zizmor reported one finding at its default level, the
`workflow_run` trigger. The gate job accepts only a successful ci run for a push to `main` in
this repository whose head is `github.sha`, and it checks out `github.sha`, so that finding is
ignored inline with the reason beside it. The pedantic level also asked for a reason on each job
permission; each now has one.

### The link check

The base tree had 508 relative links, 72 of them with a heading fragment, and all resolved;
this branch has 506. The checker was then given one probe file per case:

| Probe | Result |
| --- | --- |
| A missing file, a missing image, a reference definition to a missing file | fails |
| `../README.MD` (wrong case) | fails |
| The old workflow path | fails |
| A file on disk that is not tracked | fails |
| A path that leaves the repository | fails |
| A heading that does not exist, in another file and in the same file | fails |
| A real heading, a heading with code and punctuation, the second of two equal headings | passes |
| A link inside a code block or a code span; an `https:` link | not checked |

It also caught a link this change had missed: after `demo.html` was removed it reported
`README.md:193: demo.html`, which a search cut to 220 columns had not shown.

### Ruff

Under the new selection the base tree had three findings: two `noqa` comments that suppressed
nothing (`S603` in `check_worst_case_timing.py`, which Ruff 0.17.3 does not raise for that literal
argument list, and `SIM115` in `release.py`, a rule that is not enabled) and `date.today()` in
`hunt.py`. The quarantine stamp and the release audit time already use UTC.

## Checks

Direct runs at `b320563`:

- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts` (23 files),
  `uv lock --check`, `check_text_controls.py`, `check_doc_links.py`, actionlint, and
  `zizmor --offline --pedantic .github`: passed.
- `record_pages_demo.py --baseline web-demo/recordings.json`: outcomes match, 49 examples under
  three policies. `build_pages.py`, then `node --check` on both built modules: passed.
- `check_worst_case_timing.py`: 29 inputs passed.
- `hunt._rule(...)`: `created` equals the UTC date.
- `pytest` on `test_pages_deploy.py`, `test_pages_build.py`, `test_hunt.py`, and
  `test_release.py`: 51 passed.

## Overlap with #201

A scratch merge of this branch with `ba8cc3e` conflicts in three places, each because #201
edits a line that names `demo.html`:

| File | Resolution used |
| --- | --- |
| `demo.html` | Keep it deleted |
| `README.md`, the workbench paragraph | Take #201's line and drop its last sentence, which links `demo.html` |
| `AGENTS.md`, the `demo.py` line of the source map | Take #201's lines and drop the `demo.html` sentence |

With those three resolutions the merged tree passed every static check above (24 files under
mypy, 533 links), the recorder matched #201's baseline of 58 examples, the build validated 174
recordings, and `test_pages_deploy.py`, `test_pages_build.py`, `test_demo.py`, and
`test_hunt.py` passed (40). The scratch merge was not pushed.

#201 then merged as `799848f`. `main` was merged into this branch at `f314308` with the same
three resolutions, and the checks were run again on that commit: the static checks passed (24
files under mypy, 533 links), the recorder matched the 58-example baseline, the build validated
174 recordings, and the five focused test files passed (63).

## Boundaries

- Not run here: the macOS and Windows jobs, the full pytest suite, and `selftest`.
- The lock file was written by a newer uv than the one used here (0.11.32). The zizmor entries
  were added without rewriting anything else, and `uv lock --check` passed locally. Hosted CI
  runs that check with its own uv.
- The deploy path of the renamed workflow runs only on `main`. GitHub lists a renamed workflow
  file as a new workflow, so its run history starts again and the earlier runs stay under
  `pages-demo`. A branch protection rule that requires a check is keyed to the job name, and
  the job names are unchanged; the repository's rules were not readable from here.
- zizmor runs offline, so its audits that query GitHub (a known-vulnerable action, a commit
  that is not in the action's repository) do not run.
- The link check does not fetch `https:` links and does not read links written as raw HTML.
