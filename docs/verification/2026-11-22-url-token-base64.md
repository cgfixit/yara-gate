# A token inside a web URL is not a base64 blob

Date: 2026-11-22. Base: `main` at `1883d28`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container with 4 cores, running as root. Rules: a disposable copy of the shipped
`rules/local` (89 rules), no vendor packs. Every input written for this record is inert, and
its URLs name `example.invalid`; nothing was fetched. Every run below is a direct run on
this container; nothing here is hosted CI.

For [#236](https://github.com/cgfixit/yara-gate/issues/236), second pass. The issue's
constraint for web text is almost no false holds. The web baseline of November 20 found
that 20 of the 23 benign pages `agent-document` held were held by `agent_base64_blob` alone.

**This change makes some scans pass that were held.** That is the maintainer's to weigh.
The options are at the end.

## What held the benign pages

[BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench), MIT,
revision `b506fb5`, the two Parquet files of the
[web baseline](2026-11-20-web-benchmark-baseline.md) (same SHA-256 values), fetched by hand
and not in git. Each base64 run that makes `agent_base64_blob` fire in the raw page was
looked up with what stands before it.

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
injection in this corpus is written in base64. The furthest run began 1,706 bytes into its
URL.

None of the 309 runs inside a URL decodes to written language at any alignment.

## The change

`base64_run_signals` in `heuristics.py` decides whether a run of 400 or more base64
characters is a blob. A run inside a web URL is now a blob only when it decodes to
language.

- **Inside a web URL** (`_in_web_url`): the run's token is read back to the nearest white
  space, quote, angle bracket, backtick, or opening parenthesis, at most 4,096 bytes, and
  has to begin with `http://` or `https://`, or with the slashes escaped as JSON writes
  them. `data:`, `javascript:`, and `ftp:` URLs, an attribute written without quotes, and a
  run that only follows a URL are not inside one.
- **Language** (`_b64_reads_as_text`): at one of the run's four alignments it decodes to
  UTF-8, or to UTF-16LE with a zero after each byte, with at most 5% control bytes, at most
  5% bytes that are not valid UTF-8, and either a space in every 50 bytes or a tenth of its
  bytes outside ASCII. The alignments matter because a path joins a base64 segment to the
  text before it, and the bytes that prefix decodes to are tolerated.

`agent_base64_executable` is untouched: a run whose decoded head is `MZ`, ELF, or Mach-O
blocks wherever it sits. No rule id or severity changes. The rule's description and intent
say what it now leaves out.

## Reproduced on the base, and after

One page or message each, `scan_bytes`, `agent-document`. "Opaque" is 560 base64 characters
of bytes that spell nothing. "Text" is the base64 of five override sentences, 500
characters.

| Input | Base `1883d28` | Change |
| --- | --- | --- |
| Opaque, a query value in an `href` | held, `agent_base64_blob` | **clean** |
| Opaque, a path segment in an `href` | held | **clean** |
| Opaque, a URL in a JSON string, slashes plain or escaped | held | **clean** |
| Opaque, a URL in a text message, and in a Markdown link | held | **clean** |
| Opaque, alone in a paragraph (control) | held | held |
| Opaque, a JSON string value that is not a URL (control) | held | held |
| Opaque, a `javascript:` URL | held | held |
| Opaque, after a URL and a space | held | held |
| Text, a query value, a fragment, a path segment after the host, a later path segment | held, `agent_base64_blob` | held, `agent_base64_blob` |
| Text, a `data:text/html;base64,` URL | held | held |
| An executable header, a query value | block, `agent_base64_executable` and `agent_base64_blob` | block, `agent_base64_executable` |

## On the benchmark

`docs/research/probe_web_benchmark.py`, every page under both policies, base then change.
No scan was incomplete.

| Read rule | Split | Attack pages held | Benign pages held | Precision |
| --- | --- | --- | --- | --- |
| `agent-ingest` | test | 775 to 770 of 1,824 (42.5% to 42.2%) | 217 to 199 of 1,856 (11.7% to 10.7%) | 78.1% to 79.5% |
| `agent-ingest` | train | 2,433 to 2,415 of 5,473 (44.5% to 44.1%) | 635 to 604 of 5,566 (11.4% to 10.9%) | 79.3% to 80.0% |
| `agent-document` | test | 352 to 346 (19.3% to 19.0%) | 23 to 5 (1.2% to 0.3%) | 93.9% to 98.6% |
| `agent-document` | train | 1,000 to 978 (18.3% to 17.9%) | 45 to 12 (0.8% to 0.2%) | 95.7% to 98.8% |
| The candidate read rule of the baseline record | test | 661 to 656 (36.2% to 36.0%) | 23 to 5 | 96.6% to 99.2% |
| The same | train | 2,097 to 2,078 (38.3% to 38.0%) | 46 to 13 | 97.9% to 99.4% |

This branch also carries the change that reads
[base64 text in a URL path segment](2026-11-22-url-path-base64.md). That change alone moves
no page on either split, so the differences above are this change's.

Page by page on the test split, the records differ on 26 pages and only by the loss of
`agent_base64_blob`. No page gained a finding.

- 18 benign pages are no longer held, under either policy. The blob was their only finding.
- 5 attack pages are no longer held, under either policy. The blob was their only finding,
  so they were held for a tracking link and not for their injection.
- 1 attack page is no longer held under `agent-document` and still is under
  `agent-ingest`: it keeps a phrase note, which `agent-document` records and does not hold.
- 2 attack pages lose the finding and stay held by others.

Two benign pages keep the finding, in the `html-unescaped` view only. Their URLs have a
query parameter named `lt`, written `&lt=`. Python's `html.unescape` reads that as `<`,
which a browser does not do inside an attribute, and the `<` cuts the URL in that view.
That is the unescaping view's reading, older than this change, and it is left alone here.

On the train split the records differ on 62 pages, again only by the loss of
`agent_base64_blob`: 33 benign pages are no longer held under `agent-document` (31 had no
other finding, 2 keep an invisible-character note), and 22 attack pages (18 had no other
finding, 4 keep a note that `agent-document` records). Under `agent-ingest`, 31 benign and
18 attack pages are no longer held. One benign page keeps the finding: the protein
sequence.

## Checks

| Check | Result |
| --- | --- |
| The tables above, base then change | as shown |
| 19 new cases in `tests/test_heuristics.py` | 11 fail on the base source, the ones that expect a token in a URL to pass; the 8 that expect a blob pass on both. All 19 pass on the change |
| A new pair in `check_rule_pairs.py`: a paragraph, encoded, as a path segment fires; an opaque token in the same place does not | pass, with `lint_rules.py` (89 rules) |
| Sweep: 15,000 files already on this machine, scanned under `default` and `agent-ingest` with the base source and with the change | one file differs: `type-fest`'s `readme.md`, which was advisory for eight TypeScript playground links (`https://www.typescriptlang.org/play/#code/JYOwLgpg...`) and is clean. 17 files have the finding on the base and 16 keep it. No other verdict, reason, or finding moves |
| `base64_run_signals`, change against base, on random texts with no URL in them | 20,000 texts with no web URL: equal. 40,000 texts, half with URLs: 35,968 equal, 4,032 lose the blob with a web URL present and the executable flag unchanged, none differs any other way |
| `check_worst_case_timing.py` | pass, 106 inputs. The 104 inputs `main` has keep their verdict, reason, rule count, and views. The input added here, `url-token-runs.html` (9,300 links, each with a 400-character token that is not language), takes 1.35 s against 1.17 s on `main`, where the first run is a blob and the walk stops |
| `probe_rule_coverage.py --verify`, `probe_detection_gaps.py --verify`, `measure_precision.py`, `lint_rules.py`, `probe_match_cap.py` | the coverage probe passed, and beside the `main` run only the rule file's hash and the digests of five run-time archives differ; the gap probe passes with five new cases (a token alone, an encoded paragraph in a path, and a token in a `javascript:` URL are reported; a token in a link and in a search result's URL are clean); the precision table is `main`'s; 3,035 flooded texts, 0 with a cap blind spot |
| `yara-gate conform` | 94 fixtures, 282 checks, 0 changed verdicts, 0 changed findings |
| `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | PAGES_RESULT |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `check_doc_links.py`, `check_text_controls.py` | pass |

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.

## What is given up

Each was run on the change unless it says otherwise.

- **A long token in a web URL that is not language is no longer a finding**: encrypted or
  compressed data, base64 of base64, a hash, JSON written without spaces. A model cannot
  read the first three, and the last is what a tracking token is.
- **Language the check does not know.** UTF-16LE in a script without ASCII letters has no
  zero bytes to know it by, so base64 of UTF-16LE Russian in a URL is not reported. The
  decoded view has the same limit. UTF-8 Russian and Japanese are reported.
- **Words without spaces.** `Ignore-all-previous-instructions-...`, 400 characters of it
  encoded, in a URL, is not reported. Outside a URL it still is.
- **The benchmark's attack holds fall by 6 of 352** under `agent-document` on the test
  split, as listed above.
- An attacker can put `https://x/` before a token to make it part of a URL. That removes
  this finding only if the token is not language; `data:image/png;base64,` before a run has
  always done the same for any run.

What was never there: the blob finding has a floor of 400 characters and has always been
skipped by a `-` or `_` every 399 characters, by hex, and by a media prefix. It reports that
a long opaque run exists. It does not read one.

## The decision

1. **Take the change (recommended).** Why: 18 of 23 benign web holds on the test split go
   away and no language loses its finding. Cost: the list above.
2. **Keep the rule and score it out for web text in the consumer.** A read rule for web
   channels could record `agent_base64_blob` and not hold on it; the replay envelope
   already carries rule ids. Why: no detector change. Cost: every consumer has to know to
   do it, and the finding still holds documents and messages with a long link.
3. **Leave it.** Why: nothing passes that was held. Cost: about one benign page in a
   hundred on this benchmark stays held for a tracking link.
