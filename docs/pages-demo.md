# Public recorded demo

GitHub Pages can host the presentation, but it cannot run yara-gate's Python and
YARA-X backend. This site therefore replays **real recorded results** for 82
inert examples under `agent-ingest`, `agent-document`, and `default`: 40
attacks, each with a benign near-twin, and two scans that could not finish. Selecting
an example does not start a scan. These are detected examples at their recorded
revision, not current bypasses. The newest pairs cover a PDF line in plain Helvetica,
spaced by kerning, whose neighbour object is another font's map; a workbook written the
Open XML SDK way, every element under `x:`; and a quoted-printable email behind 26 relay
and ARC headers. Before them come an OpenDocument file with one bold word, a Word sentence
with an XML comment inside it, and a slide deck whose only text is on its master, beside
an SVG button whose link is a
`javascript:` URL, a diagram whose `foreignObject` label frames another page, and a
message carrying zero-width characters, beside white text on its own white
background, an instruction in an HTML `data-*` attribute, an override on the last
page of an eight-source merged PDF, invisible PDF text, hidden Word text, a
poisoned MCP tool description deep in a list, a script inside an inline SVG logo, the
earlier encoded PDF annotation strings, RTF formatting,
uppercase Russian, and glyph-encoded PDF spelling. The UI labels
every result as recorded and shows the scanner revision, capture time, rule coverage,
and engine version.

The page opens on the idea the catalog rests on. Under the scoreboard, a panel sets
what six files hold beside what a reader shows: the span around a bold word, the XML
comment between two words, a sentence kept on the slide master, a PDF `TJ` array whose
words are spaced by kerning, a run of `x:` elements, and a quoted-printable body with a
soft line break inside a word. Its text is fixed in `index.html`; each card opens the
recording of that pair. The panel says which readers each was checked against (LibreOffice,
pandoc, poppler, pypdf, pdfminer.six, openpyxl, and Python's `email`) and that Microsoft
Office was not run.

The page is built to show precision as well as detection. A scoreboard counts,
from the recordings themselves, the attacks `agent-ingest` held, the twins that
were clean under every policy, the findings on twins across every policy recording
(zero in the committed baseline), and the unfinished scans that stayed incomplete.
The limits section separately gives an example of coverage the PDF reader does
not provide, LZW-compressed page streams. The scoreboard counts recorded cases.
A strip under the scoreboard shows every pair at once, the attack above its twin,
marked and coloured by the verdict under the selected policy, so switching to
`agent-document` or `default` shows which attacks that policy reports without
holding. Under the strip, **How each attack was caught** has one card for each
technique: hidden from the reader, invisible characters, disguised spelling, split
across formatting, encoded, inside an archive or message, file structure, or a plain pattern.
A card counts the attacks caught that way and held under `agent-ingest`, counts
their twins that were clean under every policy, draws both as two rows of marks,
and names the derived views that found what the original bytes did not show. An
attack caught two ways is on both cards. Selecting a card opens the gallery
filtered to its pairs. The gallery shows each attack and its twin in one row, and
can also be filtered by the channel the content arrives through. The page derives
the technique from the attack's recorded `agent-ingest` findings (the view, the
source, and the rule id of each finding that the original bytes did not already
produce); only the one-line description of each technique is fixed text. Selecting
either member sets the two side by side under the chosen policy. Each finding says which check or rule caught it, in which archive
member, and through which derived view (for example, one decoded base64 run, a
PDF paragraph rejoined across text blocks, or a spreadsheet cell rejoined and then
folded for look-alikes and digits). A static section summarizes the
measured false-positive evidence and links to its records.

The site is live at **<https://cgfixit.github.io/yara-gate/>**. The first
deployment ran on November 1, 2026
([pages-demo run 3](https://github.com/cgfixit/yara-gate/actions/runs/41347105100),
manual dispatch on `main` at `1d13547`). A merge to `main` now redeploys it
automatically once every check on the merged commit is green, re-recording the
results at that commit (see [Deployment](#deployment)).

Use `yara-gate demo` on loopback to inspect your own content. This public companion
has no paste box, file picker, upload endpoint, or localhost bridge. It does not
install a CyClaw or CG-agent-harness integration. The
[integration contract](integrations.md) still governs real callers and same-byte
checks.

## Guided workflows

Fourteen fictional tasks open directly beside their recorded outcome: supplier review
(Excel comments), build triage (terminal escapes), design handoff (SVG CDATA),
model intake (pickle calls), repository intake (dev-container host commands), tool
onboarding (an MCP tool list), invoice intake (invisible PDF text), contract bundle
(a merged PDF read through each page's own fonts), web research (white text on a
white background), diagram review (a diagram label that frames another page),
chat intake (zero-width characters in a message), proposal review (a bold word
in an OpenDocument file), inbox triage (an email behind long relay headers), and data
export (a workbook written with the `x:` prefix).
Senders use reserved example addresses; the context is illustrative, and only the
fixed synthetic fixture is scanned. Workflow buttons start with `agent-ingest`;
visitors can compare its twin and change policy without leaving the evidence.
The full 40-pair catalog and the two unfinished scans remain under an expandable section.
The source revision and recording date are visible above the workflows.

The local workbench offers the same fourteen shortcuts and the same catalog: both read
[`src/yara_gate/showcase.py`](../src/yara_gate/showcase.py), so the two demos cannot
list different pairs. Selecting a shortcut clears the previous result and prepares a
sample with `agent-ingest`; **Scan sample** runs the real scanner, **Scan pair side
by side** scans the attack and its twin under the same policy, and **Run every pair**
scans the whole catalog and counts the attacks held, the twins clean, and the
findings on twins, marking any result that differs from the catalog's expected
verdict. The workbench omits the broken-rule failure, which needs a rules tree of its
own. These controls connect to no external workflow or service. This demo makes no
measured production false-positive claim.

## Public artifact and privacy

`scripts/build_pages.py` builds exactly four files into a new output directory:

| Output | Source/purpose |
| --- | --- |
| `index.html` | `web-demo/index.html`: accessible static shell and local-use guidance |
| `style.css` | Local stylesheet, with no external fonts or assets |
| `app.mjs` | Local rendering, the computed scoreboard, the per-policy strip of every pair, the card for each way an attack was caught, the pair rows with their channel and caught-by filters, scenario/policy selection, and the twin comparison |
| `recordings.mjs` | Module generated from the curated `web-demo/recordings.json` |

`scripts/record_pages_demo.py` produces `recordings.json` from real scans, and
`scripts/pages_deploy_gate.py` decides whether a `main` commit may deploy (see
[Deployment](#deployment)); neither is part of the artifact.
The builder never recursively copies the repository: rule bodies, sample files,
screenshots, docs, logs, and credentials are excluded. It rejects linked source
files, extra recording fields, content-entry elements, unexpected assets, changes
to the browser policy, and a dataset that mixes rulesets or runtimes, records
different inputs for one scenario, or carries severity flags that disagree with its
findings. It holds each scenario to its `kind`: a `control` (benign twin) must be
clean with no findings under every policy, a `detection` must be held by
`agent-ingest`, a `failure` must be incomplete under every policy, every detection and
control must name a `pair`, and a pair must join one detection and one control that
name each other. These checks catch
accidental regressions; review the actual public strings before publishing.

The page has no analytics, cookies, browser storage, service worker, remote
dependencies, or API calls. Its early meta CSP permits only same-origin scripts
and styles and sets `connect-src 'none'`, `form-action 'none'`,
`default-src 'none'`, `base-uri 'none'`, and `object-src 'none'`. It renders records
as text. Documentation links are explicit navigations with no referrer.

This is still a public hosted website. GitHub receives page/asset requests and
[logs visitor IP addresses for security](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages#data-collection).
Do not describe it as anonymous or offline. A meta CSP
[cannot enforce `frame-ancestors`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors).
This deployment makes no framing-isolation guarantee; it has no privileged
actions or content-entry controls. Adding user content, authentication, a scanner
service, or a localhost connection would require a new design and review.

## Preview the exact artifact

From the repository root, with Python 3 available:

```sh
preview_root=$(mktemp -d)
python3 scripts/build_pages.py --output "$preview_root/yara-gate"
python3 -m http.server 8000 --bind 127.0.0.1 --directory "$preview_root"
```

Open `http://127.0.0.1:8000/yara-gate/`. Relative asset URLs work at the project
subpath. Stop your preview server when finished. Rebuild into a new directory;
the builder refuses to overwrite an existing output. The static build needs no
Python packages, scanner installation, vendor downloads, or GitHub credentials.

## Deployment

Pull requests validate the demo and never publish it. They run the same build job as a
deploy: the recorder re-records with the real scanner and must match the committed
recordings (see [below](#recordings-reviewed-baseline-and-deploy-time-refresh)), then
the builder validates the four-file artifact. Pull requests that change `src/`,
`rules/`, `pyproject.toml`, or `uv.lock` run it too, because they can change what the
page shows. All actions are SHA-pinned, and no job persists checkout credentials.

A merge to `main` publishes the demo in three jobs:

1. **Deploy gate (main only)**, job `gate` (`actions: read`, `checks: read`,
   `contents: read`). It runs on `workflow_run` when `ci` completes, and only for a
   successful `push` run of `ci` on `main` in this repository whose commit is still
   `main`'s head (`github.sha`). `workflow_run` always uses the workflow file as it
   is on `main`, and the commit it deploys is never a ref taken from the event
   payload. `scripts/pages_deploy_gate.py` lets only the newest `main` commit
   through, and only after every other check on it has finished `success`,
   `skipped`, or `neutral`: CodeQL and any other check suite included. It waits up
   to 20 minutes, skips a commit that `main` has already moved past (the newer
   commit deploys itself), and stops the deploy on any red, cancelled, or timed-out
   check, on a check still running at the deadline, or on an API error.
2. **Re-record and build the demo**, job `build` (`contents: read`). It checks out
   the default ref, confirms it is the gated commit, uses no dependency cache, syncs
   the locked environment, re-records with `--baseline`, builds, and uploads only
   `build/pages`, with one-day artifact retention.
3. **Deploy to GitHub Pages (main only)**, job `deploy` (`pages: write` and
   `id-token: write`, nothing else). It deploys through the `github-pages`
   environment. Deploys run one at a time and are never cancelled mid-deploy; a
   newer pending deploy replaces an older pending one.

**Actions → demo-results-page → Run workflow** on `main` redeploys the current `main`
through the same gate. On any other branch the workflow does nothing.

The standing repository configuration:

1. Keep **Settings → Pages → Build and deployment** set to **GitHub Actions**.
   Do not publish the repository root from a branch.
2. Keep the **github-pages** environment limited to deployments from `main`. If it
   requires reviewers, each automatic deploy waits for that approval.
3. After a deploy, follow the deployment job's `page_url`, confirm HTTPS, and
   spot-check the scenarios, policies, a narrow screen, and the browser console.
   Keep HTTPS enforcement enabled.

See GitHub's [publishing-source setup](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
and [custom-workflow requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
The workflow does not enable Pages or change environment protections itself.
To roll back, revert the change through review; the revert's merge deploys itself.
To withdraw the site, unpublish it in repository settings.

## Recordings: reviewed baseline and deploy-time refresh

`web-demo/recordings.json` is the **reviewed baseline**: the verdicts, findings,
offsets, input fingerprints, and coverage counters the page claims for each input,
plus the provenance of the capture that produced them. Each deploy re-records with the
real scanner at the deployed commit and compares the result with this baseline. Only
provenance may differ: the source revision, capture time, ruleset fingerprint,
compiled-rule count, and engine and tool versions. Any other difference (a verdict, a
finding, an offset, a title) stops the deploy, and fails the pull request check before
that, so a change to what the page claims always arrives as a reviewed commit. The
published page names the exact `main` commit it was recorded from.

The [committed baseline](../web-demo/recordings.json) (schema 2) holds 82 inert
examples, recorded with 87 bundled rules and YARA-X 1.23.0, without vendor packs.
Each deployment refreshes the revision and time. See the [40-pair verification](verification/2026-11-12-demo-40-pairs.md), the [37-pair verification](verification/2026-11-11-demo-37-pairs.md), the [34-pair verification](verification/2026-11-10-demo-34-pairs.md), the [hidden-HTML and merged-PDF pairs verification](verification/2026-11-10-demo-html-merged-pdf.md), the [shared-catalog verification](verification/2026-11-10-demo-catalog.md), the [normalized-reader verification](verification/2026-11-07-normalized-reader-text.md) and [reader-pair verification](verification/2026-11-06-demo-reader-pairs.md). Each row is one attack and
its benign twin.

| Channel | Attack (held under `agent-ingest`) | Benign twin (clean under every policy) |
| --- | --- | --- |
| Document | A PDF annotation with UTF-16BE hexadecimal instructions | The same encoded annotation with an ordinary revision note |
| Document | An RTF override split by formatting and encoded letters | The same formatted RTF with an ordinary revision note |
| Attachment | SVG text split across a CDATA section and a span | An ordinary SVG chart label in the same layout |
| Document | A directive divided across Excel comment runs | A review comment about quarterly totals |
| Message | An override disguised with Latin small capitals | Ordinary small-capital heading and request |
| Message | A Russian override written in uppercase | Uppercase Russian asking to ignore noise and review notes |
| Document | A glyph-ID PDF with digit and Cyrillic substitutions split across text objects | The same encoding, layout, and substitutions in ordinary review text |
| Message | A quoted override | An ordinary note |
| Message | A request to send `.env` to an invalid example address | A request to send a README summary to an example wiki link |
| SMS | The override with a Cyrillic look-alike letter | An ordinary Russian message naming a Latin brand |
| Tool result | A JSON field whose base64 decodes to a reworded override | A session token, a PNG data URI, and base64 of an ordinary sentence |
| Tool result | A coloured CI log with a bold escape glued to the override's first word | The same log with an ordinary bold summary |
| Web page | An override with an HTML character reference | The same reference in ordinary text |
| Web page | An override in a `display:none` block | Menu labels in the same hidden block |
| Web page | An override with a `<b>` tag between two words | The same paragraph with ordinary bold, emphasis, and a link |
| Document | A Word sentence split across three formatting runs | The same runs with an ordinary sentence |
| Document | An Excel inline-string cell split across two rich-text runs, with a zero for an `o` | A rich-text cell with a percentage, a version, and a quarter |
| Document | A glyph-id PDF with the key word in bold | The same fonts and layout with an ordinary sentence |
| Attachment | A zip holding the override, followed by an ordinary invoice zip | The same two-archive layout with a receipt first |
| Attachment | An SVG animation with an `onbegin` handler (an inert `void 0`) | The same animation started by `begin="0s"` |
| Attachment | A synthetic executable header named as a PDF | A one-page PDF with no actions |
| Model file | A torch-style checkpoint whose pickle calls `os.system` after building ordinary state | The same state rebuilt through `collections.OrderedDict` |
| Repository | A `devcontainer.json` whose `initializeCommand` downloads and runs a script on the host | A host `mkdir` and installs inside the container |
| Repository | A source file whose emoji is followed by the override as variation selectors | An emoji presentation selector and a Japanese ideographic variant |
| Web page | A page whose inline SVG logo holds a script (an inert `void 0`) | The same page and logo with no script in the SVG, and a script of the page's own |
| Tool result | An MCP `tools/list` result whose 58th description of 60 says to read a private key and not tell the user | The same 60 tools; the 58th description notes that results are cached |
| Document | A Word run formatted as hidden text holding the override | The same hidden run holding a note to ignore previous drafts |
| Document | A PDF invoice with the override drawn in the invisible text render mode | The same invisible line repeating the invoice's own text, as an OCR layer does |
| Web page | A vendor update whose last paragraph is white on its own white background and holds the override | The same white-on-white paragraph holding an ordinary reply line |
| Web page | Release notes whose `data-summary` attribute holds the override and a request for API keys | The same attribute holding an ordinary release summary, as a share widget does |
| Document | An eight-source merged PDF, each page keeping its own font named `F1`, whose last page spells an override through that page's font | The same bundle ending with an ordinary signature page |
| Attachment | An SVG button whose link target is a `javascript:` URL (an inert `void` of the page title), with no script element or handler | The same button with the do-nothing `javascript:void(0)` link |
| Attachment | A two-box diagram whose first `foreignObject` label is an `iframe` to an invalid example address | The same diagram with `div` text labels, as draw.io and Mermaid export it |
| Message | A sentence with 40 zero-width characters after one word, spelling `inert` one bit each | A Persian message with a non-joiner inside two words, and a family emoji |
| Document | A PDF line in plain Helvetica with no map, words spaced by kerning, whose next font object is a subset font with its own map | The same fonts and kerning around an ordinary revision note |
| Document | A workbook written with the Open XML SDK's `x:` prefix, an override cell in two rich-text runs | The same prefix and runs around an ordinary revision note |
| Message | A quoted-printable email with a soft line break inside one word, behind 12 relay and 14 ARC headers that run past 8 KiB | The same headers and soft break around an ordinary revision note |

The two unfinished scans are an ordinary note scanned with a deliberately broken
rule in a disposable tree, and a 7z header, a container the scanner does not open
(`unsupported archive`). Both are incomplete under every policy.

The four pairs added on November 10 show changes merged after the previous baseline.
Scanned with the scanner as it was at `7d505f9`, before the scope and budget change,
the poisoned tool list was clean under every policy (the walk stopped at list item
50) and the benign page with an icon and its own script was blocked as active SVG.
At `682cf08`, before hidden text was read on its own, the hidden Word run and the
invisible PDF line were notes only, so `agent-document` read both files. The
[shared-catalog verification](verification/2026-11-10-demo-catalog.md) records those
runs.

The three pairs added later on November 10 show #205 and #207. Scanned with the
scanner as it was at `2b6eda8`, before both, the white-text and `data-*` attacks were
notes only, so `agent-document` read them, and the merged-PDF attack and its twin
were both held under `agent-ingest` as `heuristic_pdf_text_unmapped`: the override was
never read, and the ordinary bundle was held because its font name meant eight fonts.
The [pairs verification](verification/2026-11-10-demo-html-merged-pdf.md) records
those runs.

The three pairs added on November 12 show #216. Scanned with the scanner as it was at
`2cff88f`, before it, all three attacks were clean under every policy: the PDF line was
read through its neighbour's map, the `x:` runs were not read as spreadsheet text, and the
message was read only in its first 8 KiB, where its headers were. The
[40-pair verification](verification/2026-11-12-demo-40-pairs.md) records those runs and
the readers each fixture was put to.

The three pairs added on November 11 show #213. Scanned with the scanner as it was at
`5d7ca81`, before it, all three attacks were clean under every policy; the
[37-pair verification](verification/2026-11-11-demo-37-pairs.md) records those runs.

The three pairs added on November 10 show #211. Scanned with the rules as they
were at `838b11d`, before it, both SVG attacks were clean under every policy, and the
zero-width message was a note only, so `agent-document` read it. The
[34-pair verification](verification/2026-11-10-demo-34-pairs.md) records those runs.

The look-alike, hidden-page, Word, and PDF cases show the two intake channels the
README leads with: an open SMS number, and a synced corpus where `agent-document`
reads a note-only document while `agent-ingest` holds it. The six attacks added for
#167–#169 (glued zips, terminal escape, inline HTML split, spreadsheet cell, SVG
handler, variation selectors) all scanned clean on `main` at `4b5b949`, before those
changes; the four before them scanned clean at `7f9934c`, before #158–#162. All 17
twins also scanned clean, with no findings, under `agent-ingest` at `4b5b949`. No sample was executed or unpickled,
and no referenced URL was fetched. The fixtures live in `src/yara_gate/samples.py`
and the catalog in `src/yara_gate/showcase.py`, so the local workbench scans the same
bytes. The 17 examples carried over from the
previous baseline recorded the same outcomes; only the `pair` of the six attacks
that gained a twin changed.

When a change legitimately alters an outcome, re-record in that pull request and
commit the result. Use a checkout with no uncommitted changes under `src/`,
`rules/local/`, `rules/rules.lock`, `pyproject.toml`, or `uv.lock`, and run from the
repository root:

```sh
uv sync --frozen
uv run python scripts/record_pages_demo.py --output web-demo/recordings.json
```

The recorder scans the 82 fixed inert inputs in memory with `scan_bytes`, under
all three policies, against disposable copies of `rules/local` and
`rules/rules.lock`; the broken-rule case gets its own copy with one invalid rule file.
It refuses to write when a verdict, completeness state, or skip count differs
from the reviewed expectation, or when the scanner sources differ from `HEAD`.
It keeps only the response/finding fields the builder allowlists, plus
`exit_code`: no paths, namespaces, timings, or input/matched bytes. It records
`HEAD` and the UTC capture time. Review the JSON diff and rerun the artifact checks
and browser acceptance; the merge then deploys it. To check outcomes without
writing, pass `--baseline web-demo/recordings.json` and an `--output` outside the
tree, as the workflow does. A recording never authorizes access to another input.

See the [shared-catalog verification record](verification/2026-11-10-demo-catalog.md),
the [showcase verification record](verification/2026-11-06-demo-showcase.md),
the [refresh verification record](verification/2026-11-02-pages-demo-refresh.md)
and the [first verification record](verification/2026-11-01-pages-demo.md) for the
observed outcomes, exact artifact fingerprints, screenshots, and limits.
