# HTML backdrops and terminal redraw

Measured on 2026-11-20 and 2026-11-21 against
[`main` at `a6e8143`](https://github.com/cgfixit/yara-gate/commit/a6e81437e9df5131457bc7c7e0bad367b4ef1686)
for [#231](https://github.com/cgfixit/yara-gate/issues/231). Scanner checks used
Python 3.12.13 and YARA-X 1.23.0 with shipped local rules. External pages and
captured output were kept outside the repository.

Both proposals are deferred. B3 needed an incremental `agent-document` hold on a
representative input with a determinable backdrop, with zero new benign holds in the
measured cases. B5 needed a distinction between overwritten content and ordinary
redraw that agreed with tmux 3.4 and preserved benign outcomes.

## B3. HTML backdrops

Both
[BrowseSafe-Bench files at the pinned revision](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench/tree/b506fb5bc7fd4472c8738055a67a0ef6406afdc9)
matched the digests in the [web benchmark baseline](2026-11-20-web-benchmark-baseline.md#corpus).
The local sample came from HTML and HTM files under `/Applications`,
`/Library/Documentation` and `/opt/homebrew/share`. Of 46,299 local paths, three
exceeded the 512 KiB sample cap and 30,365 repeated byte digests.

First pass each page through a lexical search for declarations beginning with
`color:` and spelling white as `#fff`, `#ffffff`, `white` or an RGB triplet of
255s. For the narrow experiment exclude pages with a style, script, link,
colour-scheme cue, declared background, image or overlay cue. The lexical
screen includes declarations outside inline styles. Confirm each survivor in
Chromium by inspecting the parsed inline and computed colours on elements with
direct non-whitespace text.

| Cohort | Pages | Lexical hits | No excluded cue | Confirmed inline white among survivors |
| --- | ---: | ---: | ---: | ---: |
| Test, benign | 1,856 | 1,389 | 0 | 0 |
| Test, attack | 1,824 | 1,349 | 0 | 0 |
| Train, benign | 5,566 | 4,183 | 0 | 0 |
| Train, attack | 5,473 | 4,055 | 1 | 0 |
| Installed, distinct | 15,931 | 38 | 0 | 0 |

The sole surviving training page (content SHA-256 starting `bcc74ba5ebe2a84f`)
had zero qualifying inline declarations and scanned clean under `agent-document`.
Chromium 158.0.8127.37 and Playwright 1.62.1 opened 329 corpus inputs in fresh
contexts. Select the lowest 72 SHA-256 digests in each lexical-hit group, or
the entire group when smaller. Then include the sole survivor and any lexical
hits with a link. This gave 72 from each test class, 73 benign and 74 attack
from train, and all 38 installed hits. A fresh context used a 1440 × 1000
viewport and blocked scripts and network loads. The linked-CSS control
intercepted only its synthetic stylesheet URL and fulfilled it locally. The
329 corpus opens and 12 control renders had zero browser errors. Among the
three lexical hits with a link, two had an explicit contrasting ancestor
background with external loads blocked. The third had no qualifying inline
white declaration. Their live stylesheet behavior was unmeasured.

Five neutral label controls were checked in light and dark mode. The bare label
and colour-scheme control were white on white in light mode and had visible
white glyphs in dark mode. Serving the known stylesheet made the linked-CSS
label visible in light mode. The dark inline background and image caption were
visible in both modes. The image caption still had a transparent computed
background through its ancestors, because it sat over a sibling image. The
painted controls show why inspecting only the ancestor background is
insufficient. The five controls scanned clean under `agent-document`.

There was no eligible positive to support an incremental hold and no eligible
benign cohort from which to estimate a false-hold rate. The prescreen is
specific to this proposal and the corpus rendering excluded live stylesheets
and scripts. The earlier [HTML reader experiment](2026-11-10-hidden-html-text.md)
covers the broader layout and clipping boundary. Revisit if a representative
input provides an incremental hold and enough context to establish what is
behind the text.

## B5. Terminal redraw

Counted bare carriage returns (excluding CRLF), backspaces, and CSI cursor,
erase and SGR operations in captures from three local producers. Ran npm
11.20.0 on an offline local package with lifecycle scripts disabled. Ran pip
26.2.2 against a throttled loopback download of a synthetic 2 MiB wheel.
Ran tqdm 4.70.1 with one bar and with nested bars, in a 100 × 30 pseudoterminal
and with output redirected. The forced redirected tqdm run kept progress enabled.

| Capture | Bytes | Bare carriage returns | Cursor up | Erase line | SGR |
| --- | ---: | ---: | ---: | ---: | ---: |
| npm, terminal | 27 | 0 | 0 | 0 | 0 |
| npm, redirected | 26 | 0 | 0 | 0 | 0 |
| pip, terminal | 2,697 | 10 | 0 | 10 | 120 |
| pip, redirected | 244 | 0 | 0 | 0 | 0 |
| tqdm, single bar, terminal | 5,364 | 37 | 0 | 0 | 0 |
| tqdm, nested bars, terminal | 6,046 | 41 | 36 | 0 | 0 |
| tqdm, redirected with auto-disable, each | 0 | 0 | 0 | 0 | 0 |
| tqdm, nested bars, forced while redirected | 3,176 | 41 | 36 | 0 | 0 |
| GitHub Actions, main export | 1,302,527 | 0 | 0 | 0 | 0 |
| GitHub Actions, #316 export | 1,567,143 | 0 | 0 | 0 | 0 |

The GitHub Actions rows are `gh run view --log` exports from
[main](https://github.com/cgfixit/yara-gate/actions/runs/44828506571) and
[#316](https://github.com/cgfixit/yara-gate/actions/runs/44865941753).
They describe the exported bytes. The runner's original terminal stream may
differ.

Replayed neutral planning labels followed by ordinary redraws, plus the pip and
nested tqdm captures, in isolated `xterm-256color` panes in
[tmux 3.4](https://github.com/tmux/tmux/releases/tag/3.4) on arm64 macOS.
The tmux build used libevent 2.1.12-stable and disabled utf8proc for this ASCII
experiment. Captured the live pane and its retained history with `capture-pane`
at widths of 20 and 100 columns, both 12 rows high. For the two line-redraw
controls, the earlier label survived in the narrow pane and was gone from both
viewport and history in the wide pane. Each control sent identical bytes at
both widths. For the screen-clear control the earlier label disappeared from
both viewports and remained in both scrollback histories.

The gate receives a byte stream without the original pane state or a contract
for what its consumer reads. Operation counts alone also flag ordinary redraw.
Revisit when an integration supplies the terminal state and specifies whether
its consumer sees the viewport, scrollback, or raw output. A candidate should
then demonstrate a representative detection gain alongside benign redraw and
quotation controls. Colour, links, and explicit conceal were outside this
experiment.

## Existing scanner behavior

The [existing probes](../research/probe_detection_gaps.py) still distinguish
HTML hidden by supported declarations from the bare-white boundary. The
bare-white and terminal-conceal probes carry only the phrase note. With shipped
local rules, each is advisory under `agent-document` and blocks under
`agent-ingest`. The display-none, data-attribute and zero-opacity controls
still block under both policies. This change records those expectations in the
probe and introduces no production detector.
