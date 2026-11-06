# Public recorded demo

GitHub Pages can host the presentation, but it cannot run yara-gate's Python and
YARA-X backend. This site therefore replays **real recorded results** for 17
inert examples under `agent-ingest`, `agent-document`, and `default`: eleven
attacks, five benign near-twins, and one failed scan. Selecting an example does
not start a scan. The UI labels every result as recorded and shows the scanner
revision, capture time, rule coverage, and engine version.

The page is built to show precision as well as detection. A scoreboard counts,
from the recordings themselves, the attacks `agent-ingest` held, the twins that
were clean with no findings under every policy, and the failure that stayed
incomplete. Selecting an attack that has a twin sets the two side by side under the
chosen policy. Each finding says which check or rule caught it, in which archive
member, and through which derived view (for example, one decoded base64 run, or a
PDF paragraph rejoined across text blocks). A static section summarizes the
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
checks. The root `demo.html` remains a separate, limited JavaScript illustration;
it is not the Pages entrypoint.

## Public artifact and privacy

`scripts/build_pages.py` builds exactly four files into a new output directory:

| Output | Source/purpose |
| --- | --- |
| `index.html` | `web-demo/index.html`: accessible static shell and local-use guidance |
| `style.css` | Local stylesheet, with no external fonts or assets |
| `app.mjs` | Local rendering, the computed scoreboard, scenario/policy selection, and the twin comparison |
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
`agent-ingest`, the `failure` must be incomplete under every policy, and a `pair`
must join one detection and one control that name each other. These checks catch
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

**Actions → pages-demo → Run workflow** on `main` redeploys the current `main`
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

The committed baseline (schema 2) holds 17 inert examples, recorded with the 84
bundled rules only and no vendor packs (Python 3.12.3, YARA-X 1.23.0, captured at
`5059d03` on the branch that added the twins; each deploy refreshes the revision
and time).

| Kind | Examples |
| --- | --- |
| Detection | A quoted override; the same override as an SMS with a Cyrillic look-alike letter; a secret-transfer request to an invalid example address; an HTML-encoded override; an override hidden in a web page with `display:none`; a Word file whose override sentence spans three formatting runs; a JSON tool result whose base64 field decodes to a reworded override; a browser-style PDF that stores its text as glyph ids, with the key word in bold; a torch-style checkpoint whose pickle builds a dict, a set, and a big integer before calling `os.system`; a `devcontainer.json` whose `initializeCommand` downloads and runs a script on the host; a synthetic executable header named as a PDF |
| Control (benign twin) | An ordinary note (twin of the quoted override); the same tool result with a session token, a PNG data URI, and base64 of an ordinary sentence; the same PDF fonts and layout with an ordinary sentence; the same checkpoint state rebuilt through `collections.OrderedDict`; a dev container that only creates a host folder and installs inside the container |
| Failure | An ordinary note scanned with a deliberately broken rule in a disposable tree |

The look-alike, hidden-page, Word, and PDF cases show the two intake channels the
README leads with: an open SMS number, and a synced corpus where `agent-document`
reads a note-only document while `agent-ingest` holds it. The four newest attacks
(base64 tool result, glyph-id PDF, pickle checkpoint, dev container) all scanned
clean on `main` at `7f9934c`, before #158–#162; their twins are clean on both
revisions. No sample was executed or unpickled, and no referenced URL was fetched.
The fixtures live in `src/yara_gate/samples.py`, so the local workbench scans the same
bytes. The nine examples carried over from the schema 1 dataset recorded the same
outcomes, apart from provenance.

When a change legitimately alters an outcome, re-record in that pull request and
commit the result. Use a checkout with no uncommitted changes under `src/`,
`rules/local/`, `rules/rules.lock`, `pyproject.toml`, or `uv.lock`, and run from the
repository root:

```sh
uv sync --frozen
uv run python scripts/record_pages_demo.py --output web-demo/recordings.json
```

The recorder scans the 17 fixed inert inputs in memory with `scan_bytes`, under
all three policies, against disposable copies of `rules/local` and
`rules/rules.lock`; the failure case gets its own copy with one invalid rule file.
It refuses to write when a verdict, completeness state, or skip count differs
from the reviewed expectation, or when the scanner sources differ from `HEAD`.
It keeps only the response/finding fields the builder allowlists, plus
`exit_code`: no paths, namespaces, timings, or input/matched bytes. It records
`HEAD` and the UTC capture time. Review the JSON diff and rerun the artifact checks
and browser acceptance; the merge then deploys it. To check outcomes without
writing, pass `--baseline web-demo/recordings.json` and an `--output` outside the
tree, as the workflow does. A recording never authorizes access to another input.

See the [showcase verification record](verification/2026-11-06-demo-showcase.md),
the [refresh verification record](verification/2026-11-02-pages-demo-refresh.md)
and the [first verification record](verification/2026-11-01-pages-demo.md) for the
observed outcomes, exact artifact fingerprints, screenshots, and limits.
