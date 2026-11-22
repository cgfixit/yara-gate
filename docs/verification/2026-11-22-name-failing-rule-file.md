# The rule file that stops a scan, named on stderr

Date: 2026-11-22. Base: `main` at `b96231c`. Engine: YARA-X 1.23.0 (the locked
dependency), Python 3.12.3, x86_64 Linux container, running as root. Every run below is a
direct run on this container against a disposable rules root and gate home in the session
scratchpad.

## The gap

The [classic YARA record](2026-11-22-classic-yara-rules.md) found that one file in `local/`
that does not compile makes every scan `incomplete` with `local rule compile failed`, and
that nothing an operator sees names the file. Reproduced on the base: a copy of the shipped
rules plus `local/legacy_ext.yar`, a rule that reads the classic external `filename`.

```text
$ yara-gate scan --rules ROOT t.txt
incomplete sha256=98ea6e4f... findings=0 units=0 exit=2 reason=local rule compile failed
```

The skip list inside `compile_ruleset` already held `local/legacy_ext.yar: CompileError`; the
scanner dropped it, and the YARA-X message that holds the line and the error code was
discarded.

## The change

`rules.py` keeps, for the last compile that stopped on a non-vendor file, each such file's
key with the line and error code from the YARA-X message (`last_local_failures()`), or the
error type when it has none (`local/x.yar: OSError` for a file that could not be read).
`cli.py` prints each once per process on stderr as `rule file failed: <key> line <n>: <code>
<message>`, through the same `_printable` escape as file names. It does so after `scan`
(files and stdin, text and `--json`), when `rescan` stops on the rules, and when `setup`,
`rules install`, or `rules update` end with that error.

Unchanged: the report, `incomplete_reason`, the exit code, the skip list and its count, the
ruleset digest, and the compile cache (a failed compile writes none). Vendor compile
failures stay skips and are not printed here. `watch` prints from `quarantine.py` and is not
covered.

## Runs

| Input | stderr | stdout | Exit |
| --- | --- | --- | --- |
| Two files, one bad local rule | ``rule file failed: local/legacy_ext.yar line 6: E009 unknown identifier `filename` `` once | two `incomplete ... reason=local rule compile failed` lines | 2 |
| The same with `--json` | the same line | one JSON record, no file name in it | 2 |
| stdin, two bad local files, one named `bad<ESC>[2J.yar` | both, the escape printed as `\x1b` | one `incomplete` line | 2 |
| `rescan` on a gate home with the same rules | the line, then `incomplete: rules cannot scan: local rule compile failed; ...` | the counts record | 2 |
| A local file whose read raises `PermissionError` (patched read; root reads mode-0 files), and a vendor file that does not compile | `last_local_failures()` is `['local/unreadable.yar: OSError']`; the vendor file stays a skip | | |
| The vendor file alone | nothing named, `error` is None | | |
| The shipped rules unchanged | nothing | `clean ... exit=0` | 0 |

`detector_sha256` changes, as it does with any change to the package's Python sources, so a
consumer that caches admissions by it rescans once after upgrading.

## Commands

```sh
uv run yara-gate scan --rules ROOT FILE FILE
uv run yara-gate scan --json --rules ROOT FILE
uv run yara-gate rescan --home HOME --rules ROOT
uv run python docs/research/probe_rule_coverage.py --verify
uv run pytest -q tests/test_cli_json.py::test_json_compile_failure_is_an_incomplete_record
```

The coverage probe passed. The focused test, extended to read stderr, passed with the change
and failed on the base source. `ruff check`, `ruff format --check`, `mypy --strict src
scripts`, `check_doc_links.py`, and `check_text_controls.py` passed. Not run here: the full
pytest suite and the Windows job, which hosted CI runs.
