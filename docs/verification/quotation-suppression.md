# Occurrence-specific quotation suppression

Verified October 23, 2026, on macOS 27.0.1 ARM64 with Python 3.12.12 and locked YARA-X
1.22.0. Baseline: `30d7126bc8ec60fed08094accbd3c0ffc8c9cb77`. Candidate rule SHA-256:
`1e4a0538b8ebe1a66f9a241e16240de47a367623b3022bbdd730abc8007a1c86`.

## Change and boundary

The baseline phrase rule used `not $doc_phrase` over the entire content unit. A paper-style
mention could therefore suppress a separate override phrase before or after it. The candidate
exempts only a phrase occurrence whose end coincides with the nearest preceding documentary
match. The documentary regex is non-greedy so it names the first phrase following its prefix,
rather than swallowing a later directive. It checks offsets/counts without an all-pairs loop.

This retains the existing `the phrase` convention and 64-byte prefix window. It does not add
general quotation or semantic intent recognition. The rule stays advisory: default policy
returns advisory/exit 0, while `agent-ingest` returns block/exit 1 and preserves the finding's
advisory severity. Other rule branches and report/relocation policy are unchanged.

## Direct runtime evidence

The [maintained fixture data](../research/agent-signatures.json) adds 25 inert cases:
15 positive and 10 benign controls. The same updated
[library/CLI probe](../research/probe_rule_coverage.py) was executed against the unmodified
baseline rule first, then against the candidate. No targets or referenced URLs were executed.
Rules were copied and gate homes/cache directories were disposable; no vendor pack was installed.

| Check | Baseline | Candidate |
| --- | --- | --- |
| 15 positive fixtures | 14 incorrectly clean; only the already-outside-window case advisory | All 15 advisory |
| 10 benign quotation controls | All clean | All clean |
| Same-byte default → agent-ingest → default CLI resubmission | Incorrectly clean throughout | advisory/0 → block/1 → advisory/0, with clean/blocked/clean relocation |
| Benign quotation through agent-ingest CLI | clean/0 | clean/0, clean relocation |
| Full maintained direct probe | Failed on the new cases | 223 library cases, 42 CLI operations, nine shipped benign files, three failure paths; all expectations met |
| Local rule compilation/metadata lint | Existing baseline pack | All 32 rules compiled, zero skips |

Cases cover each of the three phrase spellings, directives before and after quotations,
nearby mixed phrases, distant/repeated/nested prefixes, multiple legitimate mentions,
the 64/65-byte prefix boundary, UTF-16BE, HTML entities, ZIP and gzip. The transformed/member
cases check rule ID and view/member provenance. CLI checks retain original severity, report
privacy, incomplete behavior, and report-before-relocation/disposition expectations.

Commands from the repository root, after `uv sync --frozen --group dev`:

```sh
XDG_CACHE_HOME=/tmp/yara-gate-quotation-cache uv run --frozen python docs/research/probe_rule_coverage.py --verify
XDG_CACHE_HOME=/tmp/yara-gate-quotation-cache uv run --frozen python docs/verification/lint_rules.py
uv run --frozen ruff check docs/research/probe_rule_coverage.py docs/research/probe_external_content.py
uv run --frozen ruff format --check docs/research/probe_rule_coverage.py docs/research/probe_external_content.py
```

## Same-byte consumer-document comparison

Both rulesets scanned the exact blobs from the existing
[consumer corpus manifest](agent-ingest-corpus.jsonl), verified against every recorded SHA-256.
Manifest SHA-256: `9bf6318f0eb47952e7f3323994090c345f3d4a92f7c84a927ec337b2bb2f58a4`.
The full local pack was copied twice, changing only the phrase rule between those copies.

| Pinned consumer snapshot | Files | Baseline advisory | Candidate advisory | Changed verdicts or rule IDs |
| --- | ---: | ---: | ---: | ---: |
| CyClaw `34b44e1197b24cace55194d0ac3ccc82a6815266` | 122 | 12 | 12 | 0 |
| CG-agent-harness `3301c0c7b6ca88ff498387f3aca820d56cb3b76b` | 28 | 1 | 1 | 0 |

All remaining documents were clean; none blocked or incomplete under default policy. The
unchanged advisories would still be held by `agent-ingest`. These are dated, small, English-heavy
repository snapshots, not current app acceptance or a production false-positive estimate.

## Repeated-quotation cost

Five interleaved baseline/candidate scans per size through the locked YARA-X engine, using
only this rule and inert repeated paper-style mentions, gave the following median wall times.
All inputs remained clean. Compilation was outside the measured interval; each scan had a
five-second engine timeout.

| Benign mentions | Baseline | Candidate |
| ---: | ---: | ---: |
| 1,000 | 1.482 ms | 1.708 ms |
| 10,000 | 12.673 ms | 25.636 ms |

Occurrence checking adds cost on match-heavy documents. This is a bounded synthetic probe,
not a throughput benchmark for the full scanner, large-file worst-case proof, or a speedup.
Existing scan deadlines and content limits remain in force.

## Research files and remaining limits

The [research report](../research/external-content-gating-2026-10-23.md),
[inert research probe](../research/probe_external_content.py), and
[recorded pre-fix observations](../research/external-content-boundaries-2026-10-23.json) are
included unchanged in substance. The observations intentionally retain their original baseline
revision and rule fingerprint; the quotation-plus-command row records the reproduced defect.
The report links to this follow-up rather than rewriting historical observations as fixed.

Ruff lint/format and diff whitespace checks passed. No backend API or workflow changed.
Broad pytest/selftest and cross-platform regressions remain with the existing hosted CI;
live CyClaw/harness, providers, native UI, vendor packs and model classifiers were not exercised.
Other extraction/semantic gaps from the research remain outside this fix.
