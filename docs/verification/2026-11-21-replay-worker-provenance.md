# Replay worker provenance and Mac transport timing

Measured against [`main` at `a6e8143`](https://github.com/cgfixit/yara-gate/commit/a6e81437e9df5131457bc7c7e0bad367b4ef1686)
on 2026-11-21 for [#236](https://github.com/cgfixit/yara-gate/issues/236).
The timing uses an arm64 Mac with macOS 27.2.1, Python 3.12.13, yara-gate 0.2.0,
YARA-X 1.23.0, 89 shipped local rules, and zero skipped rule files. It uses
synthetic text and a disposable cache and rules directory.

## Gate before implementation

A complete replay record must identify the scanned bytes, policy, detector and
rules. To test this, obtain a clean response from the real worker and vary only
its identity fields at the parent process's response boundary. Tighten the
check only if a reply without usable identity enters the valid comparison
counts.

Compare existing replay to a reference that scans the same input in one fresh
Python process. Require identical compact records apart from scan timing.
The transport comparison is a measurement of local process overhead. A
transport decision still needs a Harness workload and an agreed integration
boundary.

## Worker receipts

On the base, all five malformed-identity variants entered the benign-admit
count: missing all provenance fields, a null detector digest, an invalid
ruleset digest, a missing engine version, and a Boolean compiled-rule count.
The compact record still carried the correct input hash and policy. For each
single-record run the summary said `mixed_identities: false`, which by itself
only means that the summary did not see two distinct identities.

Replay now requires both lowercase SHA-256 digests, both non-blank version
strings, and both nonnegative integer rule counts on a complete worker record.
The five variants above now produce `failed` with
`missing or invalid worker identity`, no gate payload, and an entry in the
failure count. The intact response still admits. An incomplete response keeps
its `truncated` status and can carry partial provenance, for example when rule
compilation fails. These checks validate the fields of the local worker
response. The digests do not authenticate an arbitrary external producer.

The focused replay test covers missing, malformed, and wrongly typed identity
fields. Seven selected replay tests passed, including established checks for
record binding and incomplete outcomes.

## Process timing

For each run, generate ten JSON search results with a numbered municipal tree
inventory title and an ordinary survey snippet. Encode each result as a
compact JSON string inside capture `text`, set `name` to `tool-result.json`,
tag it `agent-ingest`, and compute SHA-256 over the UTF-8 text. Run
`yara-gate replay - --rules RULES` over those lines. For the one-process
reference, parse each line with `parse_item` and serialize
`compact_report(scan_bytes(...))` for the same name, policy and bytes.

Time from process launch through complete stdout on the same Mac, once with a
fresh compiled-rule cache per path and 12 more times with each cache warm.
Alternate the order across warm repetitions. Report p95 by nearest rank, so
with 12 observations it equals the maximum.

| Path for ten items | Cold cache, one run | Warm p50 | Warm p95 |
| --- | ---: | ---: | ---: |
| Existing replay with a worker per item | 2.415 s | 1.419 s | 1.475 s |
| One fresh Python process, direct library reference | 0.993 s | 0.137 s | 0.143 s |

Each path produced 130 compact records. Every record matched its baseline
by input after excluding `scan_seconds` and `yara_seconds`. Every input was clean and had the expected
digest. The base rules digest was
`59bbbd226ef35eed50502802c189bd0bc394ead11de5d9a8046579b7ff4f5408` and its
detector digest was
`75bbc9bfca4f9657007736dcce0b10ba6f1485c2b8bf9e660d9a070940addd75`.

The reference does not have replay's worker isolation, deadline, or envelopes.
The results give a reason to measure one child per tool call in a future
transport evaluation. They give no active-Qwen latency, real research
completion rate, or basis for selecting a read policy. The frozen protocol
and pending Harness decisions remain the criteria for that evaluation.
[Evaluation protocol](../research/shadow-evaluation-protocol.md) ·
[Harness pilot](https://github.com/cgfixit/CG-agent-harness/issues/984)

## Installed candidate

Built a wheel with `uv build --wheel` and installed it with frozen runtime
dependencies in a disposable Python 3.12.12 environment. The installed CLI
produced byte-identical `--no-timings` replay output from a file and from stdin
for ten complete items. A malformed line and a receipt mismatch both failed,
and a following valid line still completed. The mixed capture exited 2.
A broken local rule returned `truncated` and exit 0, so it remained distinct
from a missing receipt.

Computer Use opened the fresh loopback workbench. The vendor-feed pair
returned block and clean. The visible detector SHA-256 matched the JSON and
installed wheel's detector digest
`3c544a5783b397f61fbd6efe603c38d84884606a6b85ed7ccff61d71d5d2da3f`.
The `agent-ingest` live workbench catalog reported 90 of 90 expected outcomes
and zero findings on the curated benign twins. Clearing the result restored
the empty state. Those browser checks exercise the local scanner and its
display. The isolated replay failure checks exercise the worker boundary.
