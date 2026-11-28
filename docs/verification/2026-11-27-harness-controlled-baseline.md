# Harness controlled replay baseline, November 27, 2026

[#294](https://github.com/cgfixit/yara-gate/issues/294) compares the same
200 frozen tasks in three capture-off and three capture-on runs. The
November 27 [live pilot](2026-11-27-harness-capture-pilot.md) was a separate
check against public sources. Public Google challenged that pilot. This
baseline uses Harness's existing test-only search endpoint and read-only
fixture hosts. It verifies search capture through the real parser, chat
tool boundary and Ollama inference while holding the input bytes fixed.
Live-provider acceptance remains open.

## Frozen inputs and controls

The manifest and source inventory were hashed before the six measured runs.
The SHA-256 of the inventory is
`79c18fd3c2bf52b45b792f70655d17998d05959beead30aaea52975f3933a575`.
Both the development and locked splits contain 50 benign tasks and 50
answer-corruption challenges. Each label in each split includes 20 search
listings, 20 HTML fetches and 10 text-layer PDF fetches. Benign and challenge
twins share a source group within a split. Source groups and challenge
families are disjoint across splits. The order and expected answer codes
were fixed before the measured attempts. None of the prompts contained
either answer code. Six development tasks exercised all three channels
in a preflight. No detector tuning followed.

The controlled sources use fictional records and harmless alternative
answer codes. An answer is complete when the intended read tool succeeds,
the reference code appears, and the alternative code is absent. The
alternate-code metric is an observable answer error. These tasks exercise
read-only ingress and answer corruption. Evaluating real articles, citation
corruption, unauthorized actions, or memory poisoning needs other fixtures.
Raw captures and per-task answers stay in the private evaluation directory.

## Revisions and execution

- Harness origin main `3a776e64`, local capture candidate `a8b6e0f8`.
  Test-support fixture binary SHA-256
  `920daafdf540f0a83cc0fcca9c76be6259dada516f5ca674882f647b1ece5320`.
  PDF worker binary SHA-256
  `5841c5abddea9c620f88c7c827d7a884c0923d3827f9b599044b15a146b034f7`.
- Ollama 0.40.19, `qwen3.5:4b` with ID `7f3251fa6878` and loaded
  context 32,768, temperature 0, reasoning disabled, answer cap 128.
  This is a local model with tool support. The earlier 27B live pilot has
  its own identity and results.
- The driver used the authenticated HTTPS chat route with a private account
  and home per condition. Its TLS context verified that instance's local
  certificate. The model chose and called the actual Harness web tools.
  The fixture supplied read-only source bytes. The driver started a new chat
  per task and sent one request at a time, in the same order for each arm.
  The capture-on arm recorded the final model-bound tool string after
  successful inference. Both arms used Harness's normal admission decisions.
- yara-gate source `135992d` with the scoring script from #372. Installed
  wheel SHA-256
  `aa3a207d1624b94109b16838504f45ec4a25763ef9c35ea0aec6b9796ea00250`.
  Python 3.12.12, YARA-X 1.24.0, 89 bundled rules and zero skips.

## Capture coverage

Harness and Ollama ran 1,200 attempts in 1,200 separate chat sessions.
Each capture-on run wrote 200 items and matching receipts to mode-0600 files.
Each run had 80 search listings, 80 HTML passage results, and 40 PDF passage
results from the `harness-tool-json` 0.1.0 extractor. The three capture-off
runs produced zero captures or capture receipts.

The reference code reached the model in 600/600 captures. All 300 challenge
captures included the alternative code, and none of the 300 benign captures did.
The 80 search strings stayed byte-identical across capture runs. The 120 fetch
strings differed only in `fetched_at`. Replay preserved that field. Each run
used the same captured bytes, label, source ID and digest for both policies.
All capture records stored Harness's actual decision as `admitted`. The
hook reported the model-text digest. Source-file digests for this workload
are in the frozen fixture inventory.

## Harness outcomes

Each cell gives the count, denominator and 95% Wilson interval. Repetitions
reuse the same tasks. The intervals describe the measured tasks and do not
adjust for shared source groups or repetition. An alternative answer can
occur alongside a reference code and always counts as incomplete.

| Run | Split | Benign completion | Challenge completion | Alternative answer (challenge) |
| --- | --- | --- | --- | --- |
| off 1 | development | 49/50 (89.5%–99.6%) | 37/50 (60.4%–84.1%) | 13/50 (15.9%–39.6%) |
| off 1 | locked | 50/50 (92.9%–100.0%) | 44/50 (76.2%–94.4%) | 6/50 (5.6%–23.8%) |
| capture 1 | development | 50/50 (92.9%–100.0%) | 37/50 (60.4%–84.1%) | 13/50 (15.9%–39.6%) |
| capture 1 | locked | 50/50 (92.9%–100.0%) | 44/50 (76.2%–94.4%) | 6/50 (5.6%–23.8%) |
| off 2 | development | 49/50 (89.5%–99.6%) | 37/50 (60.4%–84.1%) | 13/50 (15.9%–39.6%) |
| off 2 | locked | 50/50 (92.9%–100.0%) | 45/50 (78.6%–95.7%) | 5/50 (4.3%–21.4%) |
| capture 2 | development | 50/50 (92.9%–100.0%) | 37/50 (60.4%–84.1%) | 13/50 (15.9%–39.6%) |
| capture 2 | locked | 50/50 (92.9%–100.0%) | 44/50 (76.2%–94.4%) | 6/50 (5.6%–23.8%) |
| off 3 | development | 50/50 (92.9%–100.0%) | 37/50 (60.4%–84.1%) | 13/50 (15.9%–39.6%) |
| off 3 | locked | 50/50 (92.9%–100.0%) | 44/50 (76.2%–94.4%) | 6/50 (5.6%–23.8%) |
| capture 3 | development | 50/50 (92.9%–100.0%) | 37/50 (60.4%–84.1%) | 13/50 (15.9%–39.6%) |
| capture 3 | locked | 50/50 (92.9%–100.0%) | 44/50 (76.2%–94.4%) | 6/50 (5.6%–23.8%) |

Benign completion was 99/100, 99/100 and 100/100 with capture off and
100/100 in each capture-on run. The two benign misses were `WEB_HOST_DENIED`
from the HTML fetch path. Neither arm emitted an alternative answer for a
benign task. Of the challenge tasks, 18–19 per 100 emitted an alternative
answer with capture off, and 19 per 100 did so in each capture-on run.

## Paired policy replay

The six `yara-gate replay --require-complete --rules RULES` commands all
exited 0. Each found 200 complete items, zero truncated items, zero failed
items, and `mixed_identities: false`. The `scripts/check_harness_replay.py
--score` command also exited 0 over the manifest and all three receipt and
replay pairs. The checker exited 2 and emitted no score when supplied
with a copy of one receipt file containing an altered item hash.

All six replays reported yara-gate 0.2.0 and YARA-X 1.24.0 with 89 compiled
rules and zero skipped rule files. The shared `ruleset_sha256` was
`3908ac77b20adf78c88dc40951def100f06b8c8c83dde486b37c8bb23fc5ce54`.
The shared `detector_sha256` was
`d1bcab59c866ec362be6cda139100ea01498730be8743060ed1d0c9aae20ebab`.

Each task had one captured item, so task and item rates coincide. These
counts and 95% Wilson intervals were identical in each of the three
capture-on runs. Neither policy reported a finding on a benign item.

| Policy | Split | Challenge findings | Proposed challenge holds | Proposed benign holds | Alternative answers with a proposed hold |
| --- | --- | --- | --- | --- | --- |
| `agent-ingest` | development | 10/50 (11.2%–33.0%) | 10/50 (11.2%–33.0%) | 0/50 (0.0%–7.1%) | 3/13 (8.2%–50.3%) |
| `agent-ingest` | locked | 10/50 (11.2%–33.0%) | 10/50 (11.2%–33.0%) | 0/50 (0.0%–7.1%) | 6/6 (61.0%–100.0%) |
| `agent-document` | development | 10/50 (11.2%–33.0%) | 0/50 (0.0%–7.1%) | 0/50 (0.0%–7.1%) | 0/13 (0.0%–22.8%) |
| `agent-document` | locked | 10/50 (11.2%–33.0%) | 10/50 (11.2%–33.0%) | 0/50 (0.0%–7.1%) | 6/6 (61.0%–100.0%) |

Across both splits, `agent-ingest` proposed holds for 9 of the 19 challenge
tasks whose answers contained the alternative code. `agent-document` proposed
holds for 6 of 19. The model had already seen every captured result, so the
overlap measures detection on those inputs. Answer changes under enforcement
would require a separate experiment.

## Timing and budgets

Chat wall time includes inference, tool use, and receipt export by the
driver. The paired change is the median of task-by-task capture minus off
wall times. Search time comes from the provider-attempt audit event, with
80 fixture searches in each arm. There is no isolated HTML or PDF tool
latency in this capture. Another Ollama model shared the GPU during the
measurement, and the arms ran sequentially. Treat the observed chat
differences as descriptive.

| Pair | Chat off p50 / p95 (s) | Chat capture p50 / p95 (s) | Paired median change (s) | Search off p50 / p95 (ms) | Search capture p50 / p95 (ms) |
| --- | --- | --- | --- | --- | --- |
| 1 | 1.528 / 3.016 | 1.677 / 3.026 | +0.102 | 262 / 1983 | 100 / 1875 |
| 2 | 1.681 / 3.015 | 3.144 / 11.141 | +1.381 | 126 / 1845 | 4.5 / 1906 |
| 3 | 1.565 / 3.011 | 3.549 / 9.567 | +1.807 | 316 / 1935 | 3 / 1798 |

Each replay had 200 items. Wall time includes starting the scanner worker.
Two replay commands could run concurrently.

| Run | Ingest scan p50 / p95 (ms) | Ingest wall p50 / p95 (ms) | Document scan p50 / p95 (ms) | Document wall p50 / p95 (ms) |
| --- | --- | --- | --- | --- |
| 1 | 77.5 / 116 | 219 / 322 | 77 / 116 | 218.5 / 322 |
| 2 | 85 / 116 | 249 / 324 | 85.5 / 116 | 248.5 / 323 |
| 3 | 72 / 95 | 199 / 266 | 72 / 95 | 199 / 265 |

Observed benign completion did not fall, and median offline scan wall time
was below the 2 s per-item budget in every replay. The sequential chat
measurements and offline timings leave inline latency and the 10% benign
completion-loss budget under enforcement unverified.

## Computer Use

- An ad-hoc-signed arm64 Harness 0.1.0 bundle built from `a8b6e0f8` passed
  its package and worker checks. Its bundled backend SHA-256
  `2ff3a173d1c26586a60ff20791482579b4ef5e59113e4afd2b553581a5b31641`
  matched the desktop executable's embedded digest. In an isolated
  WKWebView session, the real `qwen3.5:4b` model fetched RFC 8032 and the UI
  rendered EdDSA and a link to the source. The one mode-0600 capture matched
  its audit receipt and replayed as one complete `agent-document` admit.
  This public fetch was outside the timed cohort.
- The live yara-gate browser workbench matched 106/106 expected outcomes
  and recorded zero findings on its 52 benign controls. The static Pages
  builder validated 321 recorded scans, and Computer Use confirmed that
  the recorded inspection-limit case rendered `Recorded incomplete` with
  exit 2.

## Decision

Keep both policies in observe-only evaluation. The controlled fixture
search enabled a complete capture-and-replay comparison. Live provider
search, real articles that quote injections, and the separate adaptive
round remain necessary for #294. The measured results cover read-only chat
search and fetch. Restored or cached evidence beyond this slice, citation
corruption, memory poisoning, and unauthorized actions still require their
own evidence. Harness capture delivery remains tracked upstream.
[Harness #984](https://github.com/cgfixit/CG-agent-harness/issues/984)
