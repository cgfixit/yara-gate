# Harness capture and replay pilot, November 27, 2026

This pilot exercised real public reads and the installed local model for
[#294](https://github.com/cgfixit/yara-gate/issues/294). The frozen 200-task
cohort was unavailable. Treat the observations below as capture and scoring
verification on four benign tasks.

The isolated Harness backend was built at local candidate `a8b6e0f8` on
upstream `3a776e64`. It restored the previously verified capture hook, with
the audit call adapted to the current writer. The backend binary SHA-256 was
`5841c5abddea9c620f88c7c827d7a884c0923d3827f9b599044b15a146b034f7`.
The installed Ollama model was `qwen3.8:27b-mlx-cg`, ID `b957244f7477`,
with a verified loaded context of 32,768. The run used the authenticated HTTPS
chat endpoint and an isolated account and home per condition. The runner
verified each server's local certificate through its own TLS context.

The three fetch tasks asked for a specific fact and citation from RFCs 9110,
9111, and 8032. The public-search task asked for the W3C site. The runner
checked for the intended tool's success and the expected fact and citation
on fetches. Search-result read grants were off and the URL policy had the
three explicit RFC URLs and public Google. The same model and task sequence
ran three times with capture off and three times with capture on. The model
temperature was zero and the output limit was 512 tokens. The Harness never
enforced a yara-gate verdict. All raw capture data stayed in private local
homes.

## Harness outcomes

| Repetition | Capture off, completed | Capture on, completed | Successful captures |
| --- | ---: | ---: | ---: |
| 1 | 3 / 4 | 3 / 4 | 3 |
| 2 | 3 / 4 | 3 / 4 | 3 |
| 3 | 3 / 4 | 3 / 4 | 3 |

The three fetch tasks completed in all six runs. The intended public search
was attempted in all six runs and returned `WEB_GOOGLE_CHALLENGE` each time.
Failed searches produced no capture. The completion rate was 75% per run
and condition (95% Wilson interval, 30.1%–95.4%). These repetitions reused
the same tasks. Each capture-on run produced three distinct receipts marked
`written: true`. Every receipt matched the capture's source ID, channel, and
recomputed byte digest. The audit receipts carried no text. Each capture file
had mode `0600`. Capture-off runs produced neither capture files nor capture
receipts. Search-listing delivery remains unverified.

## Offline replay

Used `yara-gate replay --rules RULES --require-complete` with the wheel built
from the yara-gate package at `135992d`, Python 3.12.12, bundled rules, and
YARA-X 1.24.0. The wheel SHA-256 was
`5f1f796a574b26e54e081982df121654b38a5200a96f313aab5762ef458d46bd`.
All six runs exited 0, with 18 complete scans, zero failures and zero
truncations. Policy copies were verified against the raw capture and differed
only in their policy assignment. All six replays recorded one common identity
with 89 compiled rules and zero skips.

| Identity | Value |
| --- | --- |
| Tool | 0.2.0 |
| Ruleset SHA-256 | `3908ac77b20adf78c88dc40951def100f06b8c8c83dde486b37c8bb23fc5ce54` |
| Detector SHA-256 | `d1bcab59c866ec362be6cda139100ea01498730be8743060ed1d0c9aae20ebab` |

In each repetition, both policies reported findings on two of the three
items. RFC 9110 and RFC 9111 begin with UTF-8 BOMs. Each became an internal
U+FEFF in the serialized tool result and matched only
`agent_invisible_unicode` at note severity. `agent-ingest` proposed holding
those two items, 2/3 (95% Wilson interval, 20.8%–93.9%). `agent-document`
proposed holding 0/3 (0%–56.1%) and retained the notes. RFC 8032 had no
findings. The one capture per successful task made item and task-level
counts equal here.

| Run | Policy | Scan p50 / p95 (ms) | Wall p50 / p95 (ms) |
| --- | --- | ---: | ---: |
| 1 | agent-ingest | 39 / 73 | 100 / 138 |
| 1 | agent-document | 37 / 39 | 97 / 98 |
| 2 | agent-ingest | 37 / 37 | 96 / 99 |
| 2 | agent-document | 37 / 37 | 96 / 97 |
| 3 | agent-ingest | 39 / 49 | 100 / 111 |
| 3 | agent-document | 37 / 37 | 96 / 96 |

Offline wall time includes the replay worker start. The medians were below
the two-second scanner budget for these inputs. The pilot measured capture
and replay with no inline gate, so it leaves the required task-completion
budget and attack outcomes open. The observed difference supports retaining
the already selected `agent-document` policy for fetched passages in the
next observe-only run.

## Verification of the scoring command

A separate synthetic 200-task manifest exercised the complete
`check_harness_replay.py --score` path. All 1,212 installed scanner calls
completed under the same identity. Verification checked split and item
denominators, counting a task once when it had multiple items, the Wilson
intervals, and the timing order. Seven invalid variants with missing,
negative, non-finite, boolean, string, or overflowing timing, or an
unfinished scan, exited 2 and emitted no report. Reconciliation without
scoring still accepted the timing variants. The live pilot used the same
replay-validation and scoring functions on the captures actually obtained.
The full command retains the 200-task completeness requirement.

## Remaining for #294

Use the frozen, labeled 100-benign and 100-attack task manifest and reference
outcomes, and resolve the search ingress needed by that manifest. Run both
baseline conditions three times with receipt coverage, measure consumer
outcomes, and report the separate adaptive round. Publish the decision against the
agreed budgets after those measurements.
