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
  is the G7 boundary from #171; G7 itself stayed open until Phase 1b below.

## Recorded as boundaries, not planned

The phrase split over two CSV cells, or over two JSON array elements, is clean and recorded as
the intended outcome. The element boundary is visible to any tokenizer, and joining elements
invites false positives. A change that flips either case fails `--verify` as a regression, so
the decision has to be made explicitly.

Real CLI intake under `agent-ingest` is unchanged: the control zip, the concatenated zip, and the
escape-glued log all go to `blocked/`.

## Phase 1a on `claude/festive-curie-up7rx3-phase1a`: `comment-text` and `notebook-text`

Same host and toolchain, on `d64e44d`. The probe now gives 137 `ok`, 13 `open`, and no `FAIL`
or `STALE`. #171.1 and #171.2 are `ok`, and each detection is labeled with its view and stays a
note (`advisory` by default, `block` under `agent-ingest`).

- **`comment-text`** reads each block of two or more adjacent line comments with the same
  leader, or the `*` lines of a `/*` block comment, as one piece. Leaders are removed and the
  lines joined with newlines. New cases that read: a C block comment, SQL `--` lines with CRLF
  endings, and `# Ign0re all` through `comment-text+text-folded`. New boundaries that stay
  clean: Markdown `*` bullets holding the two halves, an empty `#` line between the halves, and
  commented-out code. The one-line comment control is still a single `raw` note, with no second
  `comment-text` finding.
- **`notebook-text`** reads each cell source, stream output, and `text/*` output stored as two
  or more lines as one piece. New cases that read: comment lines inside a code cell (through
  `comment-text`), a stream output, and a notebook saved as `.json`. The halves in two cells and
  an ordinary notebook stay clean.

Checks on the branch head, all exit 0: Ruff check and format, `mypy --strict src`,
`lint_rules.py` (85), `check_rule_pairs.py` (115), `check_added_rules.py` (180 plus 4),
`check_text_controls.py`, `check_scan_only.py`, `probe_rule_coverage.py --verify`, and
`yara-gate selftest`. `measure_precision.py --fail-over` gives the same report as on the Phase 0
commit, apart from its timing line. The Pages recorder matches its reviewed baseline (35
scenarios under 3 policies).

### Host sweep

91,196 source, configuration, and Markdown files on this host (Python, Go, C headers, Ruby,
YAML, JavaScript, TypeScript, Perl, assembly, SQL, shell, and others, each under 4 MiB), scanned
in memory with `scan_bytes`. The baseline is the same process with the two readers returning
nothing, which is the whole difference from the Phase 0 commit.

| Measure | Baseline | Branch |
| --- | --- | --- |
| Verdict or incomplete-reason changes | | 0 |
| Incomplete | 0 | 0 |
| Files with a finding in a new view | | 6 |
| Summed scan time, 4 worker processes | 482 s | 607 s |

The six files are three copies of Pygments' shell lexer (`script_download_execute`), two copies
of Node's `process.d.ts`, and pip's `unpacking.py` (`agent_invisible_unicode`). In each, the
same rule already fires in the raw view, so the new view only adds a second label for it. No
phrase rule fired in a new view. The host holds no notebooks, so `notebook-text` on real files is
unmeasured.

The cost is real: about a quarter more scan time across a tree of source code, from a few YARA
passes per file (a sample of 4,000 files gave 36,750 comment blocks and 10,069 folded ones).
Joining a unit's blocks into one view would be cheaper but is not equivalent:
`agent_prompt_injection_phrases` exempts a match after its nearest documentary phrase with no
distance bound, so a quotation in one comment could hide a directive in another. Scanning each
block on its own keeps the rule's reading. The benign corpus pass is unchanged (0.56 s and
0.53 s).

### Adversarial inputs

`scan_bytes` under the default policy, one run each:

| Input | Size | Baseline | Branch | Branch outcome |
| --- | --- | --- | --- | --- |
| one comment block of a million lines (`# a`, `# b`) | 4 MiB | 0.68 s | 1.73 s | clean |
| two-line comment blocks separated by blank lines | 4 MiB | 0.67 s | 0.85 s | incomplete, `text pieces exceed 100000` |
| bare `#` lines | 4 MiB | 0.61 s | 2.47 s | clean |
| an unclosed block comment of `*` lines | 4 MiB | 0.61 s | 1.66 s | clean |
| one line of `'` | 4 MiB | 0.62 s | 0.64 s | clean |
| `#`, `//`, `--`, `;` leaders alternating | 4 MiB | 0.61 s | 1.47 s | clean |
| a notebook of 60,000 two-line cells | 3.8 MiB | 1.22 s | 3.14 s | clean |
| a notebook with one 700,000-line code cell | 6.0 MiB | 1.91 s | 3.07 s | clean |
| nested `[` naming `"cells"` and `"nbformat"` | 4 MiB | 0.62 s | 0.67 s | clean, no items |
| a truncated notebook | 1.9 MiB | 0.56 s | 0.60 s | clean, no items |

The incomplete row is the shared 100,000-piece cap that `html-text` and `pdf-text` already use.
No file in the sweep came near it.

## Phase 1b on `claude/festive-curie-up7rx3-phase1b`: `markdown-text` and hyphenated wraps

Same host and toolchain, on `1408686`, stacked on Phase 1a. The probe gives 151 `ok`, 10 `open`
(the #171.4 to #171.8 and #110 cases), and no `FAIL` or `STALE`. G7 and #171.3 are `ok`, and
every detection stays a note.

- **`markdown-text`** reads each paragraph, list item, or heading that inline markup splits.
  Seven cases read, all labeled `markdown-text`: bold, a code span, strikethrough, underscore
  emphasis, link text, a phrase split over two blockquote lines, and a suffixless `README` that
  opens with a heading. These stay clean: the halves in two list items, `snake_case` with task
  checkboxes, a `**` closing a sentence, ordinary emphasis, and the phrase inside a fenced code
  block. The fenced case is recorded as a boundary, because a fence's markers are literal; a
  model reading the raw file would still see the sentence, so this is a choice, not a proof.
- **The hyphen join** in `folded_text` rejoins a letter, `-`, a line break, and a lowercase
  letter. The wrap is read through `text-folded`, with CRLF and indentation, and through
  `comment-text+text-folded` inside comment lines. `well-`/`known`, `self-`/`contained`, and
  `e-`/`mail` stay clean, and so does `previ-` before a capital, the documented limit.

Checks on the branch head, all exit 0: Ruff, `mypy --strict src`, `lint_rules.py`,
`check_rule_pairs.py`, `check_added_rules.py`, `check_text_controls.py`, `check_scan_only.py`,
both probes with `--verify`, and `yara-gate selftest`. `measure_precision.py --fail-over` gives
the same report as Phase 1a apart from its timing line. The Pages recorder matches its reviewed
baseline. The first commit wrote the Markdown opener's byte-order mark as a literal character,
which `check_text_controls.py` caught; the next commit writes it as an escape.

### Host sweep

The 91,196 files of the Phase 1a sweep plus 5,932 `.txt`, `.rst`, `.markdown`, and `README`
files: 97,128 in all. The baseline is the same process with `markdown-text` returning nothing
and the hyphen pattern unable to match, which is the Phase 1a head. Every finding was compared,
not only verdicts.

| Measure | Baseline | Branch |
| --- | --- | --- |
| Verdict or incomplete-reason changes | | 0 |
| Incomplete | 0 | 0 |
| Files whose findings changed | | 27 |
| Of those, a rule new to the file | | 4 |
| Findings added by the hyphen join | | 0 |
| Summed scan time, 4 worker processes | 607 s | 629 s |

Every added finding is in `markdown-text` or `markdown-text+text-folded`. 22 of the 27 files are
this repository's own docs, which quote attack text in code spans and emphasis. The other five
are axios's `CHANGELOG.md`, nvm's `README.md`, a plugin `README.md`, an agent skill file, and a
session copy of `docs/rules.md` saved as `.txt` that opens with a heading. In the first four, the
same rules already fired in another view. The four files with a rule new to them are
`docs/rules.md` (`win_msbuild_inline_task`), two verification records, and a session copy of
`docs/rules.md`; each was already `advisory` or `block`. 1,343 of the 1,605 Markdown files
produced 60,053 pieces; the most in one file was 4,544 (Node's `CHANGELOG.md`).

### Adversarial inputs

| Input | Size | Baseline | Branch | Branch outcome |
| --- | --- | --- | --- | --- |
| list items with emphasis, past the piece cap | 4 MiB | 0.81 s | 0.96 s | incomplete, `text pieces exceed 100000` |
| one line of `*` | 4 MiB | 0.68 s | 0.73 s | clean |
| unclosed `[` | 4 MiB | 0.71 s | 1.08 s | clean |
| unclosed link targets `[a](` | 4 MiB | 0.63 s | 1.38 s | clean |
| backtick runs | 4 MiB | 0.69 s | 1.54 s | clean |
| underscores at word edges | 4 MiB | 0.71 s | 1.90 s | clean |
| an unclosed fence, then text | 4 MiB | 1.14 s | 1.59 s | clean |
| one 4 MiB paragraph with emphasis | 4 MiB | 0.99 s | 2.43 s | clean |
| nested quote leaders | 4 MiB | 0.65 s | 1.52 s | clean |
| a hyphen at every line end | 4 MiB | 0.65 s | 0.66 s | clean |

The hyphen pattern alone takes 0.07 s to 0.15 s over 4 MiB, with or without hyphens.

### Review fixes on `a2340a9`

Codex left three findings on `d25a080` (#174). Each reproduced on `d25a080` before the fix:

- A suffixless member under a dotted archive directory (`project.v1/README`) took
  `v1/readme` as its suffix and was never read; the same text under `project/README` was.
  The suffix now comes from the final path component.
- A blockquote straight after prose, or a deeper quote, joined onto the paragraph before it,
  so `Ignore **all**` followed by `> previous instructions …` was an advisory phrase match
  assembled from two blocks. A deeper quote now starts a piece; same-depth quote lines and
  lazy continuation lines still join.
- The opening fence was cut to three characters, so a three-backtick line closed a
  four-backtick block and the real closer opened a fence that hid the rest of the file. A
  fence now closes only on its own character, at least as long, with nothing after it.

The probe gains two detections and two benign boundaries for these. All four fail on
`d25a080` and pass on `a2340a9`; the probe gives 155 `ok`, 10 `open`, and no `FAIL` or
`STALE`. Ruff, `mypy --strict src`, `check_text_controls.py`, `lint_rules.py`,
`check_rule_pairs.py`, `check_added_rules.py`, `check_scan_only.py`,
`probe_rule_coverage.py --verify`, `measure_precision.py --fail-over`, and selftest exit 0, and
the Pages recorder matches its baseline.

`markdown_texts` was run old and new over the 15,545 Markdown-gated files under `/usr`, `/opt`,
`/root`, and `/home` (base names only, so the archive-path fix is not in this count). 14
produced different pieces: suffixless Makefiles and a `vimdiff` script that open with `# `,
npm's `npm-install.md`, nvm's README, actionlint's changelog and usage page, and one record
in this repository. Scanned with each reader, all 14 have the same verdict and the same
findings. The reader took 2.82 s old and 2.67 s new over the set.

| Input | Size | Time | Outcome |
| --- | --- | --- | --- |
| one line with 2,000 nested `>` leaders, repeated | 4 MiB | 0.86 s | clean |
| alternating depth-1 and depth-2 quotes with emphasis | 4 MiB | 1.07 s | incomplete, `text pieces exceed 100000` |
| an unclosed four-backtick fence, then three-backtick lines | 4 MiB | 1.29 s | clean |
| a 5,000-backtick fence and a 4,999-backtick line, repeated | 4 MiB | 0.63 s | clean |
| a five-backtick fence, then shorter closers | 4 MiB | 1.07 s | clean |

The alternating-depth input emits a piece per quote block, as list items already do, and
stops at the same cap.

## Not established

Synthetic fixtures and one Linux host. No Office, PDF, RTF, SVG, or notebook application was used
to confirm what each reader shows, and no editor was used to confirm how it shows a comment. The small-capital map in the fixture is the common
"small text" generator set and leaves `q`, `s`, and `x` as Latin letters. None of this is a
false-positive rate.
