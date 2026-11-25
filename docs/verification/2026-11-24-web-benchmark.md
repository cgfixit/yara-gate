# Web benchmark reporting and test-split rerun

On November 24, the two shipped policies gave the same decisions on all 3,680 BrowseSafe-Bench
test pages before and after the reporting fix. The probe now withholds rates when an unfinished
scan would count as a detection, or when the scans cannot be attributed to one detector and ruleset.
This updates phase 0 of [#236](https://github.com/cgfixit/yara-gate/issues/236).

## Reproduced reporting errors

On `7844faf`, a two-row Parquet file contained an ordinary benign page and a four-byte, truncated
ZIP header labelled `yes`. Both policy scans of the header returned incomplete. The probe exited
2 but printed 100% precision for each read rule. The candidate retains each hold and its reason
in `--records`, reports two incomplete scans and exits 2 before printing rates. In a separate
test, changing only the first policy's reported detector digest used to disappear behind the
second scan's identity. The candidate withholds the summary rates for that disagreement and for
two complete responses that both lack the detector digest.

An unknown label or empty selection exits 2. A one-class selection still reports its measured
class. The absent class and precision with no holds display as unavailable.

## Test split

macOS arm64, CPython 3.12.12, YARA-X 1.24.0, yara-gate 0.2.0 and PyArrow 26.0.1.
The [original record](2026-11-20-web-benchmark-baseline.md#corpus) identifies the pinned
public Parquet file. Its SHA-256 matched `00cbad96b60fee46e016d79af6981fb221384c61f12cf28b4f04b5a6420573d0`.
Both runs used 89 bundled rules, zero skipped files and no vendor packs.
The detector digest was `21db8ce0601b0896af7039d2908cbcc8f9b728c8d346d200177f30691ec66748`
and the ruleset digest was `9e53d1a826c753067cb2eef89d2a200944b6283aa5e5b20cf01944941a7309f1`.

Run this in the project environment with PyArrow installed, once on the base and once on the
candidate, with separate output paths. The candidate run used the installed wheel and the
checkout's probe (probe SHA-256 `d3f45d7dbfb4ffc0f652f4c850c1d6200f0e3d75c99c8ba9a750cdffa4ab9d85`).

```sh
python docs/research/probe_web_benchmark.py test.parquet --workers 6 --records rows.jsonl
```

Both runs exited 0. Every page digest, label, decision, verdict, incomplete reason and
rule/severity list agreed across the 7,360 policy scans. Neither run reported an incomplete
scan. Intervals in parentheses are 95% Wilson intervals for this test split.

| Read rule | Attack pages held (1,824) | Benign pages held (1,856) |
| --- | ---: | ---: |
| `agent-ingest` | 775 · 42.5% (40.2–44.8%) | 217 · 11.7% (10.3–13.2%) |
| `agent-document` | 352 · 19.3% (17.6–21.2%) | 23 · 1.2% (0.8–1.9%) |
| Offline candidate scored from `agent-document` findings | 661 · 36.2% (34.1–38.5%) | 23 · 1.2% (0.8–1.9%) |

These counts reproduce the earlier test-split totals under the current engine and detector.
Only one benign page carried a phrase finding. Claims about false holds on security articles,
production traffic or task completion need the consumer capture and outcome measurements in
[#294](https://github.com/cgfixit/yara-gate/issues/294). The train split was outside this rerun.

## Browser checks

Computer Use ran the installed wheel's loopback workbench under `agent-ingest`. All 45 attacks
held, all 45 benign twins stayed clean with zero findings, and both unfinished inputs stayed
incomplete. The separately built Pages artifact validated 279 saved policy records. Selecting
**Inspection limit** displayed the recorded incomplete verdict and exit 2.
