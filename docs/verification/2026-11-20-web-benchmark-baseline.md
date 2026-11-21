# Web-page benchmark baseline: BrowseSafe-Bench

Date: 2026-11-20. Base: `main` at `353746b`, which holds the chat-template openers of
[#309](https://github.com/cgfixit/yara-gate/pull/309). Engine: YARA-X 1.23.0, Python 3.12.3,
x86_64 Linux container with 4 cores. Rules: a disposable copy of the shipped `rules/local`
(89 rules), no vendor packs; ruleset `e11a4770…`, detector `18b4510e…`, one identity across
every scan. Issue: [#236](https://github.com/cgfixit/yara-gate/issues/236), phase 0 of the
plan of 2026-11-20 there. Everything below is a direct run on this container.

This is the first measurement of the gate on web pages that is kept in the repository with
the script that produced it. It is a **regression baseline for one ruleset on one synthetic
corpus**. It is not an attack-prevention rate, and it is not a consumer's traffic.

## Corpus

[BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench), MIT,
revision `b506fb5bc7fd4472c8738055a67a0ef6406afdc9`. The
[detection backlog](../research/detection-backlog.md#keeping-the-detector-current) already
names it as the corpus for B3. The files were fetched by hand and are not in git.

| Split | SHA-256 of the Parquet file | Pages | Attack (`yes`) | Benign (`no`) | Median page |
| --- | --- | ---: | ---: | ---: | ---: |
| `test.parquet` | `00cbad96b60fee46e016d79af6981fb221384c61f12cf28b4f04b5a6420573d0` | 3,680 | 1,824 | 1,856 | 47,028 bytes |
| `train.parquet` | `430881fa53da3898956048676f58db894fc760cfa348ab264ee8a07c44a3d9fb` | 11,039 | 5,473 | 5,566 | 47,398 bytes |

The two columns are `content` (raw HTML) and `label`. There is no column for the injection
technique, so pages cannot be sorted by how the text was hidden.

## Command

```sh
uv run --with pyarrow python docs/research/probe_web_benchmark.py test.parquet \
    --records test.records.jsonl
```

[`probe_web_benchmark.py`](../research/probe_web_benchmark.py) scans each page in memory as
`page.html` under `agent-ingest` and `agent-document` with `scan_bytes`, four workers, and
takes the hold decision from `replay.proposed_decision`. It downloads nothing. The records
file holds a digest, the label, and per policy the verdict and each finding's rule id and
severity; it holds no page text and was not committed.

## Results

No scan was incomplete in either split. Intervals are 95% Wilson.

| Read rule | Split | Attack pages held | Benign pages held | Precision |
| --- | --- | --- | --- | ---: |
| `agent-ingest` | test | 775 of 1,824, 42.5% (40.2 to 44.8) | 217 of 1,856, 11.7% (10.3 to 13.2) | 78.1% |
| `agent-ingest` | train | 2,433 of 5,473, 44.5% (43.1 to 45.8) | 635 of 5,566, 11.4% (10.6 to 12.3) | 79.3% |
| `agent-document` | test | 352 of 1,824, 19.3% (17.6 to 21.2) | 23 of 1,856, 1.2% (0.8 to 1.9) | 93.9% |
| `agent-document` | train | 1,000 of 5,473, 18.3% (17.3 to 19.3) | 45 of 5,566, 0.8% (0.6 to 1.1) | 95.7% |
| Candidate (below) | test | 661 of 1,824, 36.2% (34.1 to 38.5) | 23 of 1,856, 1.2% (0.8 to 1.9) | 96.6% |
| Candidate (below) | train | 2,097 of 5,473, 38.3% (37.0 to 39.6) | 46 of 5,566, 0.8% (0.6 to 1.1) | 97.9% |

**The candidate row is not a policy.** It is scored from the `agent-document` records with
no second scan: hold an advisory or a block finding, and also a note from
`agent_prompt_injection_phrases`, `agent_override_imperative`, or
`agent_prompt_injection_multilingual`; record every other note. It was first chosen on
#236 after looking at the test split, and the train split is the check that it was not
fitted to noise. Both splits come from one generator, so the repeat does not show it
transfers to real pages. Whether any such read rule is added is an owner decision recorded
on #236 (W3).

### What holds the benign pages (test split)

| Read rule | Benign holds | Cause |
| --- | ---: | --- |
| `agent-ingest` | 194 of 217 | Unicode-formatting notes alone: `agent_invisible_unicode`, `agent_bidi_formatting`, `heuristic_invisible_joiner`, `agent_bidi_override`, singly or together |
| `agent-ingest` | 20 of 217 | `agent_base64_blob` alone |
| `agent-document` | 20 of 23 | `agent_base64_blob` alone |
| `agent-document` | 3 of 23 | One page each: an invisible run, `script_download_execute`, and a phrase finding beside invisible characters |

One benign page in each split carries a phrase finding. The corpus therefore says almost
nothing about the false-hold class that matters most for a research agent: pages that quote
an attack.

### Hidden-HTML findings

| Split | Attack pages with `agent_hidden_html` or `heuristic_hidden_text` | Benign pages with either |
| --- | --- | --- |
| test | 224 of 1,824 | 0 of 1,856 |
| train | 621 of 5,473 | 0 of 5,566 |

That is a precision figure for the hiding the reader claims today. It says nothing about B3
recall for default backdrops or layout hiding. The later [B3 rendering record](2026-11-21-html-terminal-boundaries.md#b3-html-backdrops)
uses these same corpus files to assess the default-backdrop proposal from
[#231](https://github.com/cgfixit/yara-gate/issues/231).

### Time

In-process scan of one page under `agent-document`, four workers on four cores: median
0.063 s, 95th percentile 0.195 s, maximum 0.443 s (test); 0.059 s, 0.182 s, 0.418 s (train).

## Against the figures posted on #236

The 2026-11-20 research comment on #236 gave these numbers for `main` at `a32b63f`, ruleset
`87c81e01…`, before #309. Every count above is equal to the one posted there. #309 changed
the ruleset identity and no outcome on this corpus: none of the 14,719 pages gained or lost
a hold from the Kimi and MiniMax openers. The two runs are still separate baselines; do not
pool records across the two ruleset identities.

## Other checks

- The probe's Wilson interval for 775 of 1,824 is 40.2 to 44.8, the interval in the
  shadow-evaluation protocol's method and the one posted on #236.
- A 200-page run with `--limit` exits 0 with one identity; the script exits 2 when a scan is
  incomplete or more than one identity appears.
- `ruff check`, `ruff format --check`, `check_doc_links.py`, `check_text_controls.py`: pass.

## Limits

- **Synthetic.** Templated HTML, machine-written injections, machine labels, fixed attacks.
  An attacker who adapts is not represented.
- **Raw HTML.** CG-agent-harness hands its model extracted text. Its number can move either
  way, and only its own capture ([#294](https://github.com/cgfixit/yara-gate/issues/294))
  says which.
- **A hold is a detector match.** It does not say an attack would have succeeded, and an
  admit does not say a page is safe.
- Timings are from a shared 4-core container with no model loaded. Trust the ratios, not the
  milliseconds.
- Not done here: the second item of phase 0, compiling Veeam-era rule files with
  `yara_x.compile`. No such files are in this repository or this environment.
