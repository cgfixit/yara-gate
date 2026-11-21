# Exit codes of `replay` and `conform` on errors they did not expect

Date: 2026-11-21. Base: `main` at `70b6b36`. Engine: YARA-X 1.23.0, Python 3.12.3, Typer
0.29.1, x86_64 Linux container with 4 cores, running as root. Rules: the shipped `rules/local`
(89 rules) or the kit's own bundled copy, no vendor packs. Every run below is a direct run on
this container; nothing here is hosted CI.

## The contracts

[AGENTS.md](../../AGENTS.md) and the CLI help give `replay` an exit of 0 or 2, never 1, and
give `conform` 1 for one meaning only: a fixture's verdict or exit code changed. Exit 2 is the
kit not running or not finishing, and the installed vendor section never changes the exit
code. The module docstring of `cli.py` says unhandled errors exit 2, and every other command
maps an unexpected exception to `incomplete: <Type>` and exit 2. `replay` and `conform` did
not. Typer exits 1 for an exception that reaches it, so on these two commands an error read
as "a fixture changed" or as the exit replay never gives.

The leads came from a read-only sweep of `replay.py`, `conform.py`, and their CLI wiring.
Each was reproduced on the base before any edit. The reproducer scripts were kept in the
session scratchpad, not in the repository.

## Reproduced on the base

| Input | Base | Changed |
| --- | --- | --- |
| `conform --agreement CAPTURE`, the first bundled scan returns `incomplete` (`timeout`), the capture names the last fixture | `KeyError: ('kit_pdf_read', 'agent-document')`, exit 1, no summary | the line is `failed` with `fixture was not scanned`, summary `incomplete`, exit 2 |
| `conform --agreement CAPTURE`, a rule that does not compile in the kit's bundled copy, the capture names `plain` (the second fixture) | `KeyError: ('plain', 'agent-document')`, exit 1 | `fixture was not scanned`, exit 2 |
| `conform --rules TREE`, TREE records an installed vendor file whose directory denies a stat (`PermissionError` from `Path.is_file` on 3.12) | bundled section passed, then `incomplete: capture unreadable (PermissionError)`, exit 2, no summary | `CONFORM PASS`, `"installed": null`, exit 0 |
| `conform --agreement FILE` with standard input closed (`<&-`) | `AttributeError` in the `finally` that closes the file, exit 1 | `CONFORM PASS`, exit 0 |
| `conform --agreement -` with standard input closed | `AttributeError`, exit 1 | `incomplete: capture unreadable (OSError)`, exit 2 |
| `conform` with the first manifest entry missing `sha256` | `KeyError`, exit 1 | `incomplete: KeyError`, exit 2 |
| `replay - </dev/null >/dev/full` | `OSError: [Errno 28]` on the summary line, exit 1 | `incomplete: output unwritable (OSError)`, exit 2 |
| `replay - </dev/null`, the reader of stdout closed before the summary (three runs) | exit 1, 1, 1 | exit 2, 2, 2 |
| `replay - <&-` | `AttributeError: 'NoneType' object has no attribute 'buffer'`, exit 1 | `incomplete: capture unreadable (OSError)`, exit 2 |
| `replay CAPTURE` with five items, the reader of stdout closed before the first item (two runs) | exit 2, 2 | exit 2, 2 |

The first two rows need one bundled scan without an answer before the fixture a capture line
names: the plain run stops there, and agreement then looked up a scan that never ran. The
first reproducer took the real result of the first fixture's first scan and set it to
`incomplete` with reason `timeout`, the record a slow machine gives; every other scan and the
agreement child were real. The second used a real compile failure, as
`test_broken_bundled_rule_is_exit_2` does, so every capture line reached it except one for the
first fixture under `default`. The third row simulates the denied stat by patching `Path.stat` for paths under the vendor
directory, because a root container can read a mode-0 directory.

## The change

- `replay` and `conform` catch an exception they did not expect, print `incomplete: <Type>`,
  and exit 2, as `scan`, `selftest`, and `demo` do.
- One helper prints each JSON Lines record. A broken pipe on standard output exits 2
  silently, as the loop already did; any other write error prints
  `incomplete: output unwritable (<Type>)` and exits 2. `replay`'s summary line now goes
  through it too, inside the block that handles those errors.
- One helper opens the capture. Standard input closed at start (`sys.stdin` is `None`) is an
  unreadable capture. `conform` closes only a capture file it opened.
- `conform`'s agreement mode gives a `failed` record, `fixture was not scanned`, for a fixture
  the plain run never reached, so every capture line still gets one record and the summary
  says `incomplete`.
- A vendor inventory or vendor file that cannot be read skips the installed section, as a
  missing recorded file already did.

No verdict, finding, envelope field, or summary field of a run that finished changed.
`conform` over the packaged kit gave `CONFORM PASS: 92 fixtures, 276 checks, 0 changed
verdicts, 0 changed findings` and exit 0 before and after, with and without an agreement
capture on standard input; `replay` over a five-item capture gave the same summary before
and after.

## Checks

| Check | Result |
| --- | --- |
| The ten rows above, base then changed | as shown |
| Seven new test cases in `tests/test_replay.py` and `tests/test_conform.py` | fail on the base source, pass on the change |
| `pytest tests/test_replay.py tests/test_conform.py` | 61 passed |
| `ruff check`, `ruff format --check` (whole tree), `mypy --strict src scripts` | pass |
| `check_doc_links.py`, `check_text_controls.py` | pass |

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.

## Left as it is

- An agreement record that `conform` marks `failed` after the extraction scanned complete
  (an unknown fixture, an extraction of other bytes, and now a fixture the plain run never
  reached) keeps the extraction's own `decision`, which can read `admit`. The record's
  `result` is `failed` and the run exits 2. Whether a failed record should carry `hold` there,
  as a failed `replay` envelope does, changes a committed agreement report, so it is left to
  the maintainer.
- `held` catches `OSError` and `ValueError` only, and prints its index outside that block.
  No input was found that raises anything else, and `held` gives exit 1 no meaning, so it was
  not changed.
- `KeyboardInterrupt` still ends `replay` the way Typer ends any command.
