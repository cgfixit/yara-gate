# Exit codes of `held`, `rescan`, and `release` when output or standard input fails

Date: 2026-11-21. Base: `main` at `78e26bb`. Engine: YARA-X 1.23.0, Python 3.12.3, Typer
0.29.1, x86_64 Linux container, running as root. Rules: a disposable copy of the shipped
`rules/local` (89 rules), no vendor packs. Gate homes were disposable directories in the
session scratchpad. Every run below is a direct run on this container; nothing here is
hosted CI.

## The contracts

The module docstring of `cli.py` says unhandled errors exit 2. `held` exits 0 for an empty
or nonempty index and 2 when it cannot give one ([integrations](../integrations.md#listing-held-items)).
`rescan` exits 2 when the pass aborts, 1 only for a new block. A `release` refusal exits 2.
The [replay and conform record](2026-11-21-replay-conform-exit-codes.md) brought those two
commands to that rule through one helper that prints a line and turns a write failure into
exit 2. `held`, `rescan`, and `release` printed with `typer.echo` outside any handler, so a
write failure reached Typer, which exits 1.

The leads came from a read-only sweep of `held.py`, `rescan.py`, `release.py`, and their CLI
wiring. Each row was reproduced on the base before any edit.

## Reproduced on the base

| Input | Base | Changed |
| --- | --- | --- |
| `held --home H \| head -1`, H holding 40 blocked copies (three runs) | exit 1, 1, 1, nothing on stderr | exit 2, 2, 2, nothing on stderr |
| `held --home H >/dev/full`, and the same with `--json` | `OSError: [Errno 28]` traceback, exit 1 | `incomplete: output unwritable (OSError)`, exit 2 |
| `rescan --home H >/dev/full` (two current clean copies, so only the summary prints) | traceback, exit 1 | `incomplete: output unwritable (OSError)`, exit 2 |
| `rescan --home H \| head -0` | exit 1 | exit 2 |
| `rescan --home H --policy agent-ingest >/dev/full` (both copies stale) | one report rewritten, then the summary write fails: traceback, exit 1 | one report rewritten, exit 2, the second copy left unvalidated |
| `release DIGEST --home H --reason r <&-` | `AttributeError: 'NoneType' object has no attribute 'isatty'`, traceback, exit 1 | `release refused: release requires a terminal or --non-interactive`, exit 2 |
| `release DIGEST … --non-interactive` on a real `agent-document` hold, the confirmation line refused (`OSError` 28, patched `typer.echo`) | the copy moved to `clean/`, the entry in `releases.jsonl`, exit 1 | the same move and entry, `incomplete: output unwritable (OSError)`, exit 2 |

Already on the rule and not changed: `scan` to `/dev/full` exits 2 (`incomplete: OSError`),
with or without `--json`, and `scan -` with standard input closed exits 2
(`incomplete: AttributeError`).

## The change

- `_print_line` in `cli.py` prints one line of a command's answer and raises `_OutputLost`
  when it cannot: silently for a broken pipe, with `incomplete: output unwritable (<Type>)`
  for any other write error. `_print_record`, which `replay` and `conform` use, now calls it.
- `held` prints its rows, its `--json` index, and `No held items.` through it and exits 2
  when the output is lost.
- `rescan` prints each copy's line and the summary through it. A lost line ends the pass
  with exit 2 and no summary, the same as any other error that stops the pass.
- `release` treats `sys.stdin` set to `None` (descriptor 0 closed at start) as no terminal,
  and prints its confirmation through `_print_line`.

No output line changed. `held` rows and `--json` were byte-identical to the base apart from
`age_seconds`, and `rescan --dry-run` lines apart from `detector_sha256` (which covers
`cli.py`) and the timing fields.

## Checks

| Check | Result |
| --- | --- |
| The rows above, base then changed | as shown |
| Nine new test cases in `tests/test_held.py` and `tests/test_rescan.py` | fail on the base `cli.py`, pass on the change |
| `pytest tests/test_held.py tests/test_rescan.py tests/test_release.py` | 70 passed |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts` | pass |
| `check_doc_links.py`, `check_text_controls.py` | pass |

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.

## Left as it is

- `rescan` with a ruleset that cannot scan (a recorded vendor file missing, a local rule that
  does not compile) returns an incomplete result for every copy, and each is withdrawn to
  `quarantine/` with its report written first; the run exits 2. That is reasoned from
  `rescan.py`, not run. It fails closed, but it withdraws every copy rather than stopping at
  the first, and changing it changes what a home looks like after a bad rules update, so it
  is left to the maintainer.
- `.watch.lock` is opened with `O_CREAT` and written with the watcher's PID without refusing
  a link. Planting a link needs write access to the 0700 home, which already allows anything
  the link would, so it was not changed. Reasoned, not run.
- `held` and `release` keep their narrow exception tuples. No input was found that raises
  anything else.
