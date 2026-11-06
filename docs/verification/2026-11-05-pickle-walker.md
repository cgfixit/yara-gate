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

## Codex review fix (2026-11-06)

A Codex code review of `20c56e8` found that the memo grows with each one-byte `MEMOIZE`, well
before the opcode cap. Reproduced: a 4 MB stream of `MEMOIZE` after one `None` reached a
350 MB peak RSS and returned clean; 4 MB of `None` pushes grew the stack the same way. The
Unpickler numbers a memo entry by the memo's size, so entries cannot be dropped without
misnumbering later strings; instead the memo and the stack are each capped at 1,000,000
entries, and a stream past either cap is incomplete. The same inputs now stop at the cap in
under 0.7 s (106 MB peak at the memo cap). CPython's pickler batches list and dict items 1,000
at a time, and the 65 joblib test pickles give results identical to `main`.
`tests/test_heuristics.py` gains a test for each cap; the full pytest suite in one run passes
(407 passed, 5 skipped).
