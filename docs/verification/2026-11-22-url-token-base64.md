# Tokens in links and `agent_base64_blob`: measured, and left to the consumer

Date: 2026-11-22. Base: `main` at `1883d28`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container with 4 cores, running as root. Rules: a disposable copy of the shipped
`rules/local` (89 rules), no vendor packs. Every input written for this record is inert, and
its URLs name `example.invalid`; nothing was fetched. Every run below is a direct run on
this container; nothing here is hosted CI.

For [#236](https://github.com/cgfixit/yara-gate/issues/236), second pass.

This record changes no rule and no scanner source. It measures a false-hold class, describes
a detector change that was built and measured, and records the maintainer's decision of
2026-11-22: **keep the rule as it is, and let a consumer of web text score the finding
out.**

## What holds the benign pages

[BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench), MIT,
revision `b506fb5`, the two Parquet files of the
[web baseline](2026-11-20-web-benchmark-baseline.md) (same SHA-256 values), fetched by hand
and not in git. That baseline found that 20 of the 23 benign pages `agent-document` holds
on the test split are held by `agent_base64_blob` alone. Each run behind the finding in the
raw page was looked up with what stands before it.

| Split | Pages with such a run | Runs | Runs inside an `http` or `https` URL |
| --- | --- | --- | --- |
| test, benign | 20 | 62 | 62 |
| test, attack | 8 | 59 | 59 |
| train, benign | 35 | 106 | 105 |
| train, attack | 29 | 83 | 83 |

They are click-tracking links, redirect targets, advertising parameters, and JWTs in image
URLs: `https://news.<shop>/e/c/eyJlbWFpbF9pZCI6...`, `...png?jwt=eyJ0eXAi...`,
`...&nad_track=eyJhdWN0aW9u...`, `...&target=aHR0cHM6Ly9...`. The one run outside a URL is
a protein sequence in a JSON string. The attack pages carry the same furniture: no
injection in this corpus is written in base64. None of the 309 runs inside a URL decodes
to written language at any of its four alignments. The furthest run began 1,706 bytes into
its URL.

On 15,000 files already on this machine, 17 have the finding. One is held for links alone:
`type-fest`'s `readme.md`, with eight TypeScript playground links
(`https://www.typescriptlang.org/play/#code/JYOwLgpg...`).

## The detector change that was built and not taken

A draft made a run inside a web URL a blob only when it decodes to written language: UTF-8,
or UTF-16LE with a zero after each byte, with at most 5% control bytes, at most 5% bytes
that are not valid UTF-8, and either a space in every 50 bytes or a tenth of its bytes
outside ASCII. The URL was read back from the run to the nearest white space, quote, angle
bracket, backtick, or opening parenthesis, at most 4,096 bytes, and had to begin with the
scheme. `agent_base64_executable` was untouched.

What it measured, `main` to the draft, no scan incomplete:

| Read rule | Split | Attack pages held | Benign pages held |
| --- | --- | --- | --- |
| `agent-ingest` | test | 775 to 770 of 1,824 | 217 to 199 of 1,856 (11.7% to 10.7%) |
| `agent-ingest` | train | 2,433 to 2,415 of 5,473 | 635 to 604 of 5,566 (11.4% to 10.9%) |
| `agent-document` | test | 352 to 346 | 23 to 5 (1.2% to 0.3%) |
| `agent-document` | train | 1,000 to 978 | 45 to 12 (0.8% to 0.2%) |

The records differed only by the loss of `agent_base64_blob`, on 26 test pages and 62 train
pages, and no page gained a finding. An encoded paragraph in a link kept its finding in
every position tried, in English, Russian, and Japanese.

What it gave up, each run on the draft:

- A long token in a web URL that is not language was no longer a finding: encrypted or
  compressed data, base64 of base64, a hash, JSON without spaces, words joined by hyphens.
- Base64 of UTF-16LE text in a script without ASCII letters was not known as language.
- On the test split, 6 of 352 attack pages held under `agent-document` were no longer
  held. Five had no other finding. One kept a phrase note, which `agent-document` records.
- Writing `https://x/` before a token that is not language removed the finding.

The draft is commit `b51df92` on the pull request this record came with, reverted there.

## The decision

Three options were put to the maintainer: take the change, keep the rule and score it out
for web text in the consumer, or leave it. The maintainer chose the second on 2026-11-22.

- **No detector change.** Nothing passes that was held, in a document, a message, or a
  page.
- **A consumer of web text may record `agent_base64_blob` and not hold on it.** The
  finding's rule id is in every report and in every `replay` envelope, so a read rule for
  a web channel is a function of the record, as the candidate read rule of the web
  baseline is. [Integrations](../integrations.md#web-pages-with-long-links) says how.
- **The cost stays where it was.** Every consumer has to know to do it, and under the two
  shipped agent policies a document or a message with a long link stays held.

Scored this way from the test-split records of `main`, with nothing rescanned: holding on
every `agent-document` finding but `agent_base64_blob` holds 3 of 1,856 benign pages and
346 of 1,824 attack pages, against 23 and 352. That is 2 fewer benign pages than the
draft held, because the draft kept the finding on two pages whose URLs the
`html-unescaped` view cuts at a `&lt=` parameter, and it drops the finding everywhere,
language included, which the draft did not.

## What was run

The benchmark probe on both splits for `main` and the draft, the 15,000-file sweep with
both sources, a 60,000-text differential of `base64_run_signals`, and the direct cases
above. The draft also passed the repository's bar (the timing tripwire, the coverage and
gap probes, the precision corpus, the conformance kit, the match-cap probe, and the
recorded demo outcomes); those results describe a source tree that is not being merged, so
they are not listed as checks of this one. This record's own checks are
`check_doc_links.py` and `check_text_controls.py`.
