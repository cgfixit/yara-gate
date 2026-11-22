# `hunt` hit names on a terminal

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container running as root. Rules: a disposable copy of the shipped `rules/local` (89
rules), no vendor packs; every gate home and scope directory was disposable and under the
session scratchpad. Every run below is a direct run on this container; nothing here is hosted
CI. The confirmed file is 49 inert bytes placed by hand in `blocked/<sha256>/`.

## The lead

[#322](https://github.com/cgfixit/yara-gate/issues/322), item 5. `yara-gate hunt` prints each
file under `--scope` that the new candidate matches with `typer.echo(hit)`. The scope is where
an operator looks for more copies of a file already confirmed bad, so those names are chosen by
whoever delivered the files. A POSIX file system accepts any byte but `/` and NUL in a name.

## Reproduced on the base

A scope directory with `ok.txt` and a second file whose name is
`a` ESC `[2J` ESC `]0;owned` BEL `b` CR `plain.txt` (clear the screen, set the window title,
return to the start of the line), both holding the confirmed bytes.

| Output goes to | Base `bed66d4` | Change |
| --- | --- | --- |
| a pipe | exit 0; the hit line holds ESC `]0;owned` BEL and a bare CR. Click removes the `[2J` sequence on a pipe and nothing else | exit 0; `<scope>/a\x1b[2J\x1b]0;owned\x07b\rplain.txt`; no ESC, BEL, or CR byte |
| a pseudo-terminal | exit 0; 2 ESC, 1 BEL, 1 bare CR reach the terminal, and the last line it is left showing is `plain.txt` | exit 0; none reach it; the line is the escaped name |

On a terminal the base lets a file name clear what the operator was reading, retitle the
window, and overwrite the start of its own line, so `a...` reads as `plain.txt`. A name with a
line break prints as two hits.

## The change

`_printable` in `cli.py` writes every character whose Unicode category starts with `C` as its
backslash escape: controls (ESC, BEL, CR, LF, tab), format characters (bidi overrides and
isolates, zero-width characters), private-use and unassigned code points, and the unpaired
surrogates that stand for bytes that are not UTF-8. `hunt` prints each hit through it. It is
the same category test `hunt.py` already applies to `--reason` before it goes into rule
metadata, with an escape in place of removal so the operator can see what was there.

Nothing else moves: the `candidate <file> hits=<n>` line, the exit codes, the rule file, and
the list `hunt()` returns to a library caller are as they were. A name without such a
character prints byte for byte as before, accents and Windows backslashes included.

## Observed after the change

- The two runs in the table above, with the same file names.
- `tests/test_hunt.py::test_hunt_prints_a_hit_name_that_cannot_control_the_terminal` runs the
  command on a name with ESC `[2J`, an OSC title, CR, LF, and U+202E, beside a name with an
  accent. It checks three output lines, no character below U+0020, the escaped spelling, and
  the accented name unchanged. `tests/test_hunt.py` gives 9 passed. On the base source the
  test cannot import `_printable`; the table above is the base observation.

Checks: `ruff check`, `ruff format --check .`, `mypy --strict src scripts`,
`docs/verification/check_doc_links.py`, and `docs/verification/check_text_controls.py` pass.

## What this does not cover

- The escape is for reading. It is not reversible: a file literally named `a\x1b` and a file
  named `a` ESC print the same line. A script that needs the paths should call `hunt()` and
  use the list it returns.
- Other lines the CLI prints. `scan`, `watch`, and `rescan` print no file name outside JSON,
  and JSON output is ASCII. `<file>: unguarded` and `local/<name>: shadowed by bundled` print
  rule file names from the operator's own rules root or a hash-pinned vendor pack; they are
  unchanged.
- Windows and macOS terminals were not run. NTFS refuses the characters below U+0020 in a
  name, so on Windows the reachable part is the format characters (U+202E and its kin).
