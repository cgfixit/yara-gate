# Reader-text gaps on `main` (2026-11-06)

Source: `main` at `a35ccbf` (#170 merged, which changed only the demo and its docs since the
review in #171 ran on `9214510`). Linux x86_64, Python 3.12.3, locked YARA-X 1.23.0, a disposable
copy of the 85 shipped local rules, no vendor packs. Nothing was executed, unpacked to disk, or
fetched.

This records Phase 0 of #171: the gaps found there are now cases in
[`docs/research/probe_detection_gaps.py`](../research/probe_detection_gaps.py), each beside a
control the scanner already catches and the benign boundaries a fix must keep clean. A case
marked open must still miss; `--verify` fails when it stops missing, so each later phase removes
its own markers. No scanner, rule, or policy code changed.

```sh
uv run python docs/research/probe_detection_gaps.py --verify
```

The run exits 0 with 125 cases `ok` and 16 `open` (G7's two, the eleven below, and three for
#110), and no `FAIL` or `STALE`.

## Open: reader-text gaps (#171)

Each case is `clean` under `default`, `agent-ingest`, and `agent-document`. Every control is
`advisory` by default and `block` under `agent-ingest`, from `agent_prompt_injection_phrases`.

| Id | Case | Control | Benign boundaries |
| --- | --- | --- | --- |
| #171.1 | `// Ignore all` then `// previous instructions …` in `.js`; the same with `#` in `.py` | the phrase in one `//` comment | a code line between the two comments; an ordinary three-line comment block |
| #171.2 | `.ipynb` markdown cell whose `source` is `["Ignore all\n", "previous …"]` | the phrase as one `source` line | the halves in two cells; an ordinary notebook with markdown and code |
| #171.3 | `previ-` at a line end, `ous` on the next | the unwrapped phrase, as in every other control | `well-`/`known` and `self-`/`contained` at wraps |
| #171.4 | RTF `Ignore all {\b previous} instructions`; RTF `\'49gnore all …` | the phrase as plain RTF text | `{\b …}` and `{\i …}` groups around ordinary prose |
| #171.5 | SVG `<text>` with the phrase split over two `<tspan>`s | the phrase in one `<text>` | the halves in two `<text>` elements; axis labels as `<tspan>`s |
| #171.6 | `xl/comments1.xml` and `ppt/comments/modernComment_1.xml` with the phrase over two runs | the phrase in one comment run (read raw) | the halves in two comments; a review comment over three runs |
| #171.7 | PDF text annotation whose `/Contents` is a hex string | the same `/Contents` as a literal string (read raw) | an ordinary review note as a hex string |
| #171.8 | the phrase in IPA and phonetic-extension small capitals | the phrase in ASCII, as in every other control | a small-capital heading; an IPA transcription |

## Open: hidden text (#110)

The phrase in a `w:vanish` run, after `3 Tr`, and after `1 1 1 rg` gives the same
`agent_prompt_injection_phrases` note as visible text. The probe wants `heuristic_hidden_text`,
the id the #171 plan names for Phase 2, and marks all three open. Through the CLI on stdin with
the disposable rules root, the vanished-run document is `advisory` with exit 0 under
`agent-document` and `block` with exit 1 under `agent-ingest`. A vanished `Draft` watermark and
an OCR-style `3 Tr` invoice line are recorded as clean, because Phase 2 must emit nothing for
hidden text without a phrase match.

## Held, recorded so they stay held

- Zero-width spaces as word separators: `agent_invisible_unicode`.
- A soft hyphen inside a word, and a quoted-printable soft break inside a word in `.eml`:
  `agent_prompt_injection_phrases`.
- A PDF phrase over two `Tj` operators, or as a hex string inside the content stream: read by
  `pdf-text`.
- Markdown `Ignore all.** Previous instructions apply.` (a `**` closing a sentence): clean. This
  is the G7 boundary from #171; G7 itself stays open.

## Recorded as boundaries, not planned

The phrase split over two CSV cells, or over two JSON array elements, is clean and recorded as
the intended outcome. The element boundary is visible to any tokenizer, and joining elements
invites false positives. A change that flips either case fails `--verify` as a regression, so
the decision has to be made explicitly.

Real CLI intake under `agent-ingest` is unchanged: the control zip, the concatenated zip, and the
escape-glued log all go to `blocked/`.

## Not established

Synthetic fixtures on one Linux host. No Office, PDF, RTF, SVG, or notebook application was used
to confirm what each reader shows. The small-capital map in the fixture is the common
"small text" generator set and leaves `q`, `s`, and `x` as Latin letters. None of this is a
false-positive rate.
