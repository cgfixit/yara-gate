# Base64 text in a URL path segment

Date: 2026-11-22. Base: `main` at `1883d28`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container with 4 cores, running as root. Rules: a disposable copy of the shipped
`rules/local` (89 rules), no vendor packs. Every input written for this record is inert
text, and the URLs name `example.invalid`; nothing was fetched. Every run below is a direct
run on this container; nothing here is hosted CI.

For [#236](https://github.com/cgfixit/yara-gate/issues/236), second pass: what the gate
reads on a web page and in a search result, where almost every long token is part of a URL.

## The miss

A reader decodes an encoded instruction as easily as a plain one, so a base64 run that
decodes to readable text is scanned as a `base64-decoded` view. The run is found by
`_B64_TOKEN`, whose characters include `/`. In a URL path, `/` joins the segments, so a
segment that is base64 was read as one token with the path before it
(`invalid/e/c/SWdub3Jl...`). That token decodes to nothing readable, and the segment was
never read on its own.

## Reproduced on the base

`scan_bytes` of one page, `<p>Spring news.</p><a href="https://news.example.invalid...">`,
with the 99 base64 characters of an override sentence in the URL. The rule is
`agent_prompt_injection_phrases`, a note, in the `base64-decoded` view.

| Where the encoded sentence sits | Base `1883d28` | Change |
| --- | --- | --- |
| `/r?x=<run>` (control: a query value) | reported | reported |
| `/<run>` | **clean, no `base64-decoded` view** | reported |
| `/e/c/<run>` | **clean** | reported |
| `/e/c/<run>/open` | **clean** | reported |
| `/e/c/<run>` in the URL-safe alphabet | **clean** | reported |
| the same URL in a text message, not a page | **clean** | reported |
| an ordinary sentence, encoded, as a query value | clean | clean |
| an ordinary sentence, encoded, as a path segment | clean, not read | clean, read |

`docs/research/probe_detection_gaps.py` gained six cases under `G1`. With the base source
three of them fail (`want agent_prompt_injection_phrases`, `clean` under every policy)
beside the query-value control, which passes. With the change all six pass.

A run of 400 or more characters in the same places was not silent on the base: it is
`agent_base64_blob`, whatever it decodes to. The sentence itself was not read there either.

## The change

`base64_texts` in `content.py` already tried a wrapped token line by line when it did not
decode whole. A token, or a line of one, that does not decode whole and holds `/` is now
tried segment by segment as well (`_b64_segment_texts`). A segment has to be 16 characters
or more and pass the same test as any run: UTF-8 or UTF-16LE, at least 95% printable, with
white space. Segments count against the same limit of 1,024 readable runs, and the loop
looks at the scan deadline every 1,024 segments.

A token that decodes whole is read as before, so a standard-alphabet run that contains `/`
is not split.

## Checks

| Check | Result |
| --- | --- |
| The table above, base then change | as shown |
| `probe_detection_gaps.py --verify` | exit 0 on the change, 746 cases; exit 1 with the base source, on the three new cases only |
| Two new tests in `tests/test_scanner.py` | both fail on the base source and pass on the change: the five positions and two benign paths, then the 1,024 limit, the deadline looks, and a timeout |
| BrowseSafe-Bench, both splits, 14,719 pages, each under `agent-ingest` and `agent-document` | no page differs from the base run on either split in verdict, decision, or rule ids, under either policy (3,680 and 11,038 distinct pages). No scan was incomplete |
| Sweep: 15,000 files already on this machine (3,387 SVG, 1,785 JSON, 1,352 reStructuredText, 1,305 XML, 921 Markdown, 225 HTML, and source and configuration files, each at most 2 MiB), scanned under `default` and `agent-ingest` with the base source and with the change | no file differs in verdict, incomplete reason, or any finding's rule, offset, length, severity, view, or member path. 134 of the files have a finding on the base |
| `check_worst_case_timing.py`, 105 inputs of 4 MiB | pass. The 104 inputs the base has keep their verdict, reason, rule count, and views; the slowest took 6.84 s (`pdf-encrypt-tokens.pdf`) |
| The input added to it, `url-path-segments.html`: one URL path of 246,000 base64 segments that do not read as text | 2.61 s on the change and 1.65 s on the base, best of two on a quiet machine. Both are advisory: a base64 run of 4 MiB is `agent_base64_blob` |
| `probe_rule_coverage.py --verify` | passed. Beside the base run, only the source revision and the digests of five archives the probe builds with the current time differ |
| `yara-gate conform` | 94 fixtures, 282 checks, 0 changed verdicts, 0 changed findings |
| `measure_precision.py`, `check_rule_pairs.py`, `lint_rules.py`, `probe_match_cap.py` | the precision table is the base's (328 files, 0 incomplete); rule pairs pass (120 rules); 89 rules lint; 3,031 flooded texts, 0 with a cap blind spot |
| `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | PAGES_RESULT |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `check_doc_links.py`, `check_text_controls.py` | pass |

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.
No browser session: no page or demo source changed.

## What still passes

Each was run on the change.

- **A sentence split across two segments** is clean. Each piece is decoded apart, so a
  sentence that spans the cut is not read whole. A standard-alphabet run with a `/` of its
  own is cut the same way when it sits in a path; the override sentence tried here was
  still reported, because the phrase lay whole in the first piece.
- **An encoded word** is clean. A run that decodes to text without white space is an
  identifier, as in every other position: `Ignore-all-previous-instructions-...`, encoded.
- **A run of fewer than 16 characters** is clean.
- **Text nobody decodes for the reader.** The gate reads what the bytes spell. Whether a
  model decodes a path segment because the page tells it to is not something a scan of the
  page can know, and a visible instruction to do so is ordinary prose.
