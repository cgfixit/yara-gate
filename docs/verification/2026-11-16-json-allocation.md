# JSON allocation bounds — November 16, 2026

## Scope and baseline

Selected [#258](https://github.com/cgfixit/yara-gate/issues/258) after refreshing
`origin/main` at `c5afef410c92196f053d42a6e3b190ec1d17ea64`. The primary checkout
was clean and already at that revision. Work is isolated on
`cx/bounded-json-allocation`. Python 3.12.12, YARA-X 1.23.0, arm64 macOS;
89 bundled rules, zero skips, no vendor download, 30-second scan budget.

The two open PRs were #262 (`922e8f1`, Ruff) and #263 (`0a369b5`, runtime
libraries). Each changes only `uv.lock`; neither covers this issue or overlaps
this patch. Their CI and demo workflows had successful runs; superseded
independent-verdict runs were cancelled. This candidate keeps the existing lock.
Before publication, #262 merged and #263 closed without merging. Both the primary
checkout and candidate were fast-forwarded to `e6d92bc3181a2cb064ecb480eaf1d09a9f81c54c`
and synced to Ruff 0.17.4. Only the dev-tool lock changed upstream; runtime sources
and dependencies still match the measured baseline. Focused checks and installed
browser acceptance passed again on that base. No other PR was open at that refresh.

Reviewed the ten open issues against the current source and their discussions:

| Issue | Current disposition |
| --- | --- |
| #258 | Reproduced allocation before walk budgets; selected as the concrete availability follow-up to the merged reader work. |
| #257 | No held-item index command; remains useful before private review bundles. |
| #255 | All six reported inert strings still scan clean under agent-ingest on main; remains a separate detection task. |
| #236 | No shared replay/shadow adapter or classifier adapter; preserve the recorded consumer ownership, pilot budgets, and observe-only sequence. |
| #227 | No conformance command/manifest; depends on #236's shared replay core. |
| #231 | B6 is built. B3/B5 remain the two open gap-probe cases; retain measurement-first decisions and remaining B8 work. JSON allocation is now owned by #258. |
| #228 | No provenance token/key/verifier; retain the recorded defaults and correct the MAC/envelope design before building it. |
| #225 | No private context-bundle command; retain the owner-approved disclosure and audit constraints. |
| #226 | No consumer-manifest renderer; retain separate overlays and the recorded later sequencing. |
| #229 | No fragment ledger; retain the assembled-context recipe first and the measurement gate before adding state. |

These observations do not close the other issues or reopen their owner decisions.

## Change and compatibility

`jsonbounds.py` bounds structural punctuation and depth before `json.loads` or
Keras's `raw_decode`. It stores counters, skips strings/comments, and leaves
syntax and values to the existing standard decoder. It also identifies when a
potential MCP config needs JSONC decoding beyond the existing 1 MiB comment cap;
that now reports incomplete rather than silently skipping the config.
The Keras path needs the same guard because it runs before MCP and can allocate
the same tree, including when keys use Unicode escapes. Ordinary JSON without
potential MCP keys avoids that heuristic's tree altogether.

The [operator contract](../rules.md#json-parsing-limits) gives the exact limits
and reasons. Large dense configurations/notebooks can change from clean to
incomplete. No rule ID, severity, policy, lockfile, or report schema changes.
Streaming selective extraction was not introduced: retaining the existing decoder
makes duplicate keys, escapes, numbers, and supported reader behavior unchanged
within the budget. No `OPEN` marker existed for this availability issue; the
existing deep-MCP probe now expects the earlier structure-limit reason.

## Measurements

Fresh process per input, same rules and bytes before/after. Warm the rules with
an ordinary text scan, then time the complete scan with `perf_counter` and read
macOS `resource.getrusage(RUSAGE_SELF).ru_maxrss` (bytes). RSS includes the
interpreter, input, and rules; it is a process peak, not a universal upper bound.
Baseline warmed peaks ranged from 49.83 to 63.77 MiB. Each row is one measurement,
not a statistically significant latency estimate.

Fixtures are exact 1, 2, or 4 MiB ASCII buffers, filled with repeated small objects
and spaces before the closing suffix. JSON: `{"items":[` plus `{"x":0},` repeats
and `{}]}`. MCP adds `"description":"ordinary",` before `"items"`; JSONC adds
`/* comment */ ` before that object. Notebook: `{"nbformat":4,"cells":[` plus
`{"metadata":{}},` repeats and `{}]}`. These inert inputs deliberately amplify
object-tree allocations; they do not contain attack instructions.

| Input | MiB | Base peak MiB | Candidate peak MiB | Base seconds | Candidate seconds | Candidate result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| json | 1 | 86.92 | 59.97 | 0.133 | 0.088 | clean |
| json | 2 | 103.38 | 71.11 | 0.244 | 0.172 | clean |
| json | 4 | 157.53 | 93.19 | 0.486 | 0.343 | clean |
| mcp | 1 | 74.95 | 50.05 | 0.122 | 0.058 | incomplete |
| mcp | 2 | 103.27 | 52.95 | 0.246 | 0.075 | incomplete |
| mcp | 4 | 157.59 | 61.00 | 0.478 | 0.113 | incomplete |
| jsonc | 1 | 77.86 | 49.97 | 0.177 | 0.057 | incomplete |
| jsonc | 2 | 71.11 | 53.00 | 0.153 | 0.076 | incomplete |
| jsonc | 4 | 93.23 | 61.05 | 0.296 | 0.113 | incomplete |
| notebook | 1 | 68.08 | 51.91 | 0.075 | 0.108 | incomplete |
| notebook | 2 | 89.17 | 57.03 | 0.151 | 0.173 | incomplete |
| notebook | 4 | 129.48 | 65.14 | 0.300 | 0.296 | incomplete |

Every baseline result was clean. JSONC above 1 MiB was previously skipped by
its structured heuristic, so those two rows compare changed coverage as well as
memory. The candidate holds dense MCP/JSONC/notebook inputs before allocating the
tree. The ordinary JSON result stays clean. Normal MCP configs, supported poisoned
tool descriptions, ordinary notebooks, and joined notebook instructions were
checked as controls. A 4 MiB notebook of longer lines remains clean with an actual
`notebook-text` view; the timing fixture retains that coverage below the new node
budget. Tree allocation is bounded, but strings and other readers still consume
memory proportional to their own budgets.

## Runtime, compatibility, and tooling

- `probe_rule_coverage.py --verify`: 617 library observations, 9 benign observations,
  55 CLI observations, and 3 injected failure paths passed.
- `probe_detection_gaps.py --verify`: 699 cases passed; B3/B5 remain open as intended.
- Focused `pytest` for JSON bounds, MCP, and Keras: 27 passed, 111 deselected.
  The new checks prove over-budget data never reaches the allocating decoder and
  preserve escaped keys, comments, UTF-16LE/UTF-32LE, decoder-supported surrogates,
  nested entries, and notebook cell boundaries.
- Source-to-source scans of the same 557 unique installed JSON/notebook files
  (Homebrew and the locked Python environment, up to 4 MiB): zero differences in
  verdict, reason, findings including offsets/views, or view counts. This is an
  installed-file sample, not a production false-positive rate.
- Five affected 4 MiB timing cases passed the existing 10-second scan ceiling:
  notebook lines and nesting, JSON escapes, MCP descriptions, and JSONC comment
  openers. The malformed escaped-JSON fixture retains its previous complete result. Oversized
  JSONC with a leading comment, trailing comment, or trailing comma is held.
- Ruff checks/format and strict mypy passed. No workflow files changed.

Built a wheel and installed it in a disposable environment, then compared
`content.py`, `heuristics.py`, `jsonbounds.py`, `demo.py`, and `demo_page.html`
byte-for-byte with the candidate source. Wheel SHA-256:
`1b3250dcf3ad21d5e119dcc7a761a10943bc2605822c26a3a567863aa75ff688`.
Exercised detector SHA-256:
`ca3e2c19a6f607017dd072003d7d3934b6888f76f71496021b4958230dbafbd4`.

From the installed CLI, dense MCP, notebook, and Keras inputs plus an oversized
commented MCP input each returned exit 2, wrote reports, and remained quarantined
under all three policies. Identical-byte MCP resubmissions under default →
agent-ingest → default moved clean → blocked → clean with the expected exits.
Normal MCP and notebook controls stayed clean; the joined notebook instruction
blocked under agent-ingest. Rules were a disposable bundled-only copy, and every
intake used a disposable explicit home.

## Browser and delivery limits

Computer Use opened the installed wheel's real loopback workbench in the macOS
ChatGPT in-app browser. The MCP pair was block/clean under agent-ingest and
advisory/clean under default. Pasted notebook-shaped JSON reconstructed an
instruction within a cell; its ordinary twin stayed clean. A deeply nested
notebook showed INCOMPLETE, exit 2, and the exact structure-limit reason in the
painted result. Clear followed by an empty submission cleared the old verdict.
The full live catalog matched 81 of 81 expectations, including 40 clean twins
with zero findings and the unreadable-archive hold.

The static replay was rebuilt with its allowlisting builder (82 scenarios, 246
policy recordings) and opened separately in Computer Use. Its recorded MCP attack
and clean twin displayed exits 1 and 0; the painted page clearly labels the result
as a recording. This is static presentation acceptance, not another live scan.

This repository ships a Python CLI/library, a live browser demo, and a static
replay; it does not ship a native `.app`. No native app was invented for acceptance.
No production samples, vendor accuracy, live Harness/Qwen integration, Windows
runtime, or universal absence of regressions is claimed. Hosted CI owns the broad
suite/platform run. The issue can close after this fix is reviewed, checks pass,
and its PR merges; the draft alone is not a fix on main.
