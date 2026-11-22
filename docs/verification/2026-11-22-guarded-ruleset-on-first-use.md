# The guarded ruleset is read when a long view first needs it

Date: 2026-11-22. Base: `main` at `1883d28`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container with 4 cores and 16 GB, running as root. Rules: a disposable copy of the
shipped `rules/local` (89 rules, 59 files), no vendor packs, a disposable cache directory.
Every input was synthetic and inert. Every run below is a direct run on this container;
nothing here is hosted CI, and nothing is a Mac figure.

For [#236](https://github.com/cgfixit/yara-gate/issues/236): a web search hands a model
ten short results, `yara-gate replay` scans each in its own process, and the process
start is the cost, not the scan.

## What was slow

A process's first scan reads two compiled rulesets from the cache: the ruleset, and the
same rules with a match-cap guard per file. Only a view of 1,000,000 bytes or more is
scanned with the guarded one (`MATCH_LIMIT`), because a shorter view cannot fill a match
list. A process that scans a search snippet or a page read it anyway.

`cProfile` over the first `scan_bytes` of a 107-byte text in a fresh process, cache warm:

| Step | Time |
| --- | --- |
| `scan_bytes`, whole | 157 ms |
| `compile_ruleset` | 143 ms |
| `Rules.deserialize_from`, the ruleset (1,721,629 bytes) | 58 ms |
| `Rules.deserialize_from`, the guarded ruleset (1,824,836 bytes) | 69 ms |
| The YARA pass | 3 ms |

The same scan repeated in that process takes 1.1 ms.

## The change

`compile_ruleset` no longer reads the guarded ruleset when both rulesets are in the cache.
It reads the few bytes that list the unguarded files, since every report counts them, and
keeps a `GuardedRules` whose `rules()` reads the compiled copy the first time a scan asks.
The scanner asks when it is about to scan a view of `MATCH_LIMIT` bytes or more, before it
takes the time left for that pass.

Nothing else moves. A ruleset that is not in the cache is compiled with its guards at once,
as before. A view under the limit was never scanned with the guarded ruleset. A view at or
over it still is. `guarded_ruleset(digest)` returns what it returned.

One thing happens later than it did. A guarded copy that no longer reads (cut short,
overwritten, emptied) used to be built again by the next process to start. It is now built
again by the first scan that needs it, and a process that scans only short views leaves
it as it found it. A copy that is missing, or whose list of unguarded files is missing, is
still built again at once.

## Measured

Base beside changed, 15 runs each, interleaved, each run a fresh process with a warm cache
(`PYTHONPATH` selects the source tree). Median and 95th percentile, then the peak resident
size of that process.

| Process | Base | Changed | Median | Peak RSS |
| --- | --- | --- | --- | --- |
| Library call, one 107-byte snippet | 310 / 373 ms | 236 / 323 ms | 24% less | 53.7 to 47.8 MiB |
| Library call, one 46 KB HTML page | 321 / 363 ms | 239 / 288 ms | 26% less | 53.6 to 47.7 MiB |
| Library call, 1.5 MB of text (reads the guarded ruleset) | 493 / 578 ms | 470 / 554 ms | within the spread | 56.2 to 56.3 MiB |
| `yara-gate scan snippet.txt --json` | 413 / 464 ms | 322 / 394 ms | 22% less | 63.8 to 58.0 MiB |
| `yara-gate replay` over ten snippets, one child each | 3,448 / 3,614 ms | 2,579 / 2,855 ms | 25% less | 55.0 to 49.2 MiB |

The first `scan_bytes` in a fresh process, three runs each: 144, 164, and 216 ms on the
base; 79, 83, and 84 ms on the change.

The library rows printed the same bytes on both trees. The two command rows differ only
where they must: `detector_sha256` is a digest of the scanner's sources.

What is left of a one-snippet process, by the same measurements: about 15 ms of
interpreter start, about 100 ms of imports, about 60 ms to read the ruleset, and about a
millisecond to scan. One process for a whole tool call would pay that once; that is the
batch mode the issue's plan describes, and it is not built here.

## Checks

| Check | Result |
| --- | --- |
| Two new cases in `tests/test_match_cap.py` | The first fails on the base source (the base reads the guarded cache during a 900,007-byte scan) and passes on the change. The second, a guarded copy cut to half its length and then a scan that needs it, passes on both: the verdict is `block`, the rule is the one behind the full list, and the cache file is whole again afterwards |
| `tests/test_match_cap.py` and `tests/test_rules.py`, 78 cases | pass |
| Damaged cache, each beside a 200-byte and a 1,200,000-byte scan in a fresh process: guarded copy overwritten, cut to half, emptied, deleted; the list of unguarded files deleted | Every scan returned what the base returned (`clean`, 89 rules, 0 unguarded). On the base the cache was whole again after every case. On the change it is whole again after every case but three: the overwritten, cut, and emptied copies beside the 200-byte scan, which never read them |
| `docs/research/probe_rule_coverage.py --verify` | passed. Beside the base run, only the run time, the two changed source hashes, and the digests of five archives the probe builds with the current time differ |
| `yara-gate conform` | 94 fixtures, 282 checks, 0 changed verdicts, 0 changed findings |
| `docs/verification/check_worst_case_timing.py`, 104 inputs of 4 MiB, each of which is scanned with the guarded ruleset | TRIPWIRE_RESULT |
| `docs/research/probe_match_cap.py` | MATCHCAP_RESULT |
| `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | PAGES_RESULT |
| `docs/verification/lint_rules.py`, `check_rule_pairs.py` | pass (89 rules, 120 rule pairs) |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts` | pass |
| `check_doc_links.py`, `check_text_controls.py` | pass |

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.
No browser session: the change is below the scanner's interface, and the conformance kit
and the recorded demo outcomes cover what the workbench shows.

## Left as it is

- The ruleset itself is still read by every process, about 60 ms here. It is what every
  scan uses.
- A ruleset that is not in the cache still compiles both sets before the first scan.
  Deferring the guarded build too would need the list of unguarded files, which the build
  produces, to be known without it.
- About 100 ms of imports. The readers for PDF, mail, and Office files load whether or not
  the input is one; splitting them out is a larger change with its own risks.
