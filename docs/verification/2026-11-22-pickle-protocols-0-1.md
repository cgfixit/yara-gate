# Pickles of protocols 0 and 1

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container running as root. Rules: a disposable copy of the shipped `rules/local` (89
rules), no vendor packs. Every run below is a direct run on this container; nothing here is
hosted CI. No pickle here was ever loaded: the dangerous streams are written by hand with
the argument `true`, and `pickle.dumps` only writes.

## The lead

[#322](https://github.com/cgfixit/yara-gate/issues/322), item 2. `heuristic_pickle_reduce`
walks a stream's opcodes and blocks a call to a dangerous global. `_pickle_candidate` and the
loop in `_pickle_reduce_offset` both required the first byte of a stream to be `0x80`, the
`PROTO` opcode. Protocols 2 to 5 write it. Protocols 0 and 1 do not, and a loader reads them
all the same: `pickle.load` takes whatever protocol the bytes are in.

`cos\nsystem\n(S'...'\ntR.` is the protocol 0 spelling of a call to `os.system`. The walker
already parsed every opcode in it (`GLOBAL`, `MARK`, `STRING`, `TUPLE`, `REDUCE`, `STOP` are
in `pickletools`' table); it never started.

## Reproduced on the base

`scan_bytes`, default and `agent-ingest`, the same result under both.

| Input | Name | Base `bed66d4` | Change |
| --- | --- | --- | --- |
| `\x80\x02` + `cos\nsystem\n` ... `R.` (protocol 2, control) | `model.pkl` | block, `heuristic_pickle_reduce` | the same |
| `cos\nsystem\n(S'true'\ntR.` (protocol 0) | `model.pkl`, `.pickle`, `.pt`, `.pth`, `.ckpt` | **clean** | block, `heuristic_pickle_reduce` |
| `cos\nsystem\n(U\x04truetR.` (protocol 1) | `model.ckpt` | **clean** | block |
| `(S'true'\nios\nsystem\n.` (`INST`), `(cos\nsystem\nS'true'\no.` (`OBJ`) | `model.pkl` | **clean** | block |
| `c__builtin__\neval\n` ..., `csubprocess\nPopen\n` ..., `cposix\nsystem\n` ... | `model.pkl` | **clean** | block |
| a protocol 2 pickle of an integer, then the protocol 0 call | `legacy.pt` | **clean** | block |
| a protocol 0 list, then the protocol 0 call | `legacy.pt` | **clean** | block |

The sixth row is the legacy `torch.save` layout, where a loader calls `pickle.load` several
times on one file. The base walked the first stream, met a byte that was not `0x80`, and
stopped.

## The change

- `_pickle_candidate`: under a pickle's name (`.pkl`, `.pickle`, `.pt`, `.pth`, `.ckpt`) any
  non-empty file is walked. Under any other name the test is unchanged: `0x80` and a
  protocol number of 5 or less.
- `_pickle_reduce_offset`: after a stream ends, the next one is walked whatever its first
  byte is. A stream that does not parse still ends the walk with no finding, which is how
  the tensor bytes after the last pickle of a legacy checkpoint are left.

No rule id, severity, or limit moved. The walk limits (20,000,000 opcodes, 1,000,000 memo or
stack entries) and the deadline check apply to these streams as to any other.

## The nearest benign bytes

All stay unreported on the change (`pickle_reduce_findings` gives `([], None)`):

| Input | Name |
| --- | --- |
| `cos\nsystem\n.`: the global named and never called | `ref.pkl` |
| `cos.path\njoin\n(S'a'\nS'b'\ntR.`: a call to a module that is not on the list | `p.pkl` |
| a sentence, then the protocol 0 call quoted on its own lines | `notes.pkl` |
| `./src\n../lib\n` and `import sys; sys.path.insert(...)`: Python path files | `*.pth` |
| a torch zip checkpoint (its `archive/data.pkl` member is walked as before) | `model.pt` |
| the protocol 0 call under a name that is not a pickle's | `notes.txt`, `notes` |
| 1 MiB of random bytes; an empty file | `weights.ckpt`, `empty.pkl` |
| 32 ordinary values (containers, big integers, bytes, exceptions, dates, decimals, named tuples, 3,000-item lists) pickled in each of protocols 0 to 5: 192 streams | `state.pkl` |

## Installed files

- Every file on this machine with one of the five suffixes: 17 files (14 `.pth` path files,
  a Portuguese Vim tutor named `tutor.pt`, one `.pkl`, one `.pickle`). Scanned with the base
  source and with the change: every line (verdict, reason, rule ids) is identical, all clean.
- 101,287 files under `/usr/share`, `/usr/lib`, `/usr/bin`, `/etc`, and `/opt` (3.2 GB, each
  under 16 MiB), each walked as if it were named `as-named.pkl`: no finding, no walk limit,
  and the slowest walk took 4 ms. Ordinary text and binaries stop at their first or second
  byte, because most bytes are not opcodes and most opcodes need a stack the file has not
  built.

## Time on 4 MiB under a pickle's name

| Input | Seconds | Result |
| --- | --- | --- |
| `N` repeated (each pushes one item) | 0.82 | incomplete, `pickle exceeds walk limit` (the stack cap) |
| `]0` repeated (push, pop) | 2.99 | clean |
| `S'x'\n0` repeated | 1.38 | clean |
| `.` repeated | 0.00 | clean (the first `STOP` has nothing to return) |
| prose | 0.01 | clean |

The base does not walk these files at all. The same opcodes behind a two-byte `\x80\x02`
were already walked at this cost.

## Checks

On the change, from the repository root: `ruff check`, `ruff format --check .`,
`mypy --strict src scripts`, `docs/verification/lint_rules.py` (89 rules),
`check_rule_generator.py`, `check_rule_pairs.py` (120 rules), `check_added_rules.py` (267
cases), `measure_precision.py --fail-over`, `docs/research/probe_rule_coverage.py --verify`,
`docs/research/probe_detection_gaps.py --verify`, `check_worst_case_timing.py` (101 inputs),
`docs/research/probe_match_cap.py`, `scripts/record_pages_demo.py --baseline
web-demo/recordings.json` (outcomes match), `yara-gate conform` (94 fixtures, 282 checks, no
change), `check_doc_links.py`, and `check_text_controls.py` all exit 0.

`check_added_rules.py` gained 21 cases: the protocol 0 and 1 spellings, both legacy
layouts, the benign bytes above, and the existing shaped and benign values in protocols 0
and 1. Run against the base source, ten of them fail (`missing heuristic_pickle_reduce`).
`tests/test_heuristics.py -k pickle` gives 19 passed on the change and 6 failed on the base
source.

## What this does not cover

- **A protocol 0 or 1 pickle under another name.** `model.bin`, `model.joblib`, a file with
  no suffix: nothing in the bytes marks them, and they are not walked. The gap probe carries
  this as its one `OPEN` case (`pickle protocol 0 under another name`). Walking every file
  costs little by the measurement above. It was left out because it can turn a benign file
  that starts with a million pushing opcodes (a long run of `N`, `]`, or `)`) from complete
  to incomplete under any name, and no such file was looked for outside this machine.
- **A file the walk now holds.** A file with a pickle's name that starts with such a run is
  incomplete where the walk passed over it. On the base, 4 MiB of `]` or of `)` is clean and
  4 MiB of `N` is advisory (`agent_base64_blob` alone); with the change each is incomplete,
  and the `N` run keeps that finding. None of the 17 real files is one.
- **Modules off the list.** As before, the check names `os`, `subprocess`, `posix`, `nt`,
  `eval`, `exec`, and most of `builtins`. A protocol 0 call to `runpy` or `importlib` is not
  reported, in any protocol.
- **A loader's own limits.** The walk follows `pickletools`' opcode table, not one loader.
  Whether `torch.load` with `weights_only` refuses these streams first was not run.
