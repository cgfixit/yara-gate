# Pickle walker reaches the call (2026-11-05)

Source: `main` at `7f9934c`, branch `fix/pickle-walker-opcodes`. Linux x86_64, Python 3.12,
locked YARA-X 1.22.1, a disposable copy of the shipped rules (82 local rules, no vendor packs).
Every fixture is built with `pickle.dumps` or by hand and walked with `pickletools`; nothing
was unpickled.

## Baseline miss (issue #145, item 1, and wider)

The old walker stopped with no finding at the first opcode it did not know. On `main`:

| Fixture | `main` | Branch |
| --- | --- | --- |
| `LONG1`, negative `LONG1`, `LONG4` before `os.system` | clean | block |
| `SHORT_BINSTRING`, `BINBYTES8`, `BYTEARRAY8` before the call | clean | block |
| `pickle.dumps([dict, set, frozenset, 2**90, bytes, call])`, protocols 2-5 | clean | block |
| The same inside a `torch.save`-style zip (`archive/data.pkl`) | clean | block |
| Two pickles back to back, the second one dangerous (legacy `torch.save`) | clean | block |
| `__builtin__.getattr` (protocol 2 spelling that `fix_imports` maps to `builtins`) | clean | block |
| Benign `ValueError("inert")`, protocols 3-5 | **block** | clean |

The wider gap: dict (`SETITEMS`), object state (`BUILD`), memo references (`BINGET`), and sets
all stopped the old walk, so a model checkpoint shaped like a real one scanned clean.

## Change

`pickletools.genops` parses opcodes; each opcode's documented stack effect is applied, with
strings and globals tracked through the memo. Benign `builtins` value constructors (set,
frozenset, bytearray, complex, range, slice, exceptions, ...) no longer block: the old
predicate blocked them whenever the walk reached them, and the deeper walk reaches more of them.
`os`, `subprocess`, `posix`, `nt`, `eval`, `exec`, and every other builtin still block.

A stream over 20,000,000 opcodes is incomplete (`pickle exceeds walk limit`); the old walker
returned clean after 100,000 steps. Measured: about 0.6 µs an opcode, 12 s at the cap.

## Commands and outcomes

- `docs/verification/check_added_rules.py`: 126 cases pass. With `heuristics.py` reverted to
  `main`, the 29 new pickle cases give 16 misses and 3 false positives.
- `check_rule_pairs.py` (109 rules), `measure_precision.py --fail-over` (exit 0),
  `check_scan_only.py`, `check_text_controls.py`, `probe_rule_coverage.py --verify`: pass.
- Direct `scan_bytes` under `default` and `agent-ingest`: the dangerous `.pt` blocks with
  member path `zip:0`, the benign one is clean, a 20,200,000-opcode list is incomplete.
- CLI inbox scans with a disposable `--home`, each file submitted twice: the dangerous `.pt`
  exits 1 and moves to `blocked/<sha256>/`, the benign one exits 0 and moves to `clean/`.
- `pytest tests/test_heuristics.py tests/test_scanner.py`: 206 pass (adds a walk-limit test).

## Not established

No real third-party checkpoint corpus was scanned. Modules outside the list (`runpy`,
`importlib`, `pty`, ...) are still not reported; that is a separate predicate change.
