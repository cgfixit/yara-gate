# Public recorded demo

GitHub Pages can host the presentation, but it cannot run yara-gate's Python and
YARA-X backend. This site therefore replays **real recorded results** for six
inert examples under `default`, `agent-ingest`, and `agent-document`. Selecting an
example does not start a scan. The UI labels every result as recorded and shows
the scanner revision, capture time, rule coverage, and engine version.

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
| `app.mjs` | Local rendering and scenario/policy selection |
| `recordings.mjs` | Module generated from the curated `web-demo/recordings.json` |

The builder never recursively copies the repository. Rule bodies, sample files,
screenshots, docs, logs, credentials, and unrelated files are excluded. It rejects
linked source files, extra recording fields, content-entry elements, unexpected
assets, and changes to the browser policy. These checks catch accidental
regressions; review the actual public strings before publishing. They are not a
secret detector or a sandbox for malicious source changes.

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

## Activate after review and merge

No repository setting is changed by this PR, and no PR or push event publishes
the site. The workflow uses SHA-pinned GitHub actions. Its build job has only
`contents: read`, and checkout does not persist credentials. Both artifact upload
and deployment require an explicit `workflow_dispatch` on `refs/heads/main`.
Only the separate deployment job has `pages: write` and `id-token: write`.

1. Review and merge the static site and `.github/workflows/pages-demo.yml`.
2. In repository **Settings → Pages → Build and deployment**, choose **GitHub
   Actions** as the source. Do not publish the repository root from a branch.
3. Configure the **github-pages** environment to permit deployments from `main`
   only. Retain any required reviewers or other existing environment protections.
4. Run **Actions → pages-demo → Run workflow**, selecting `main`. The workflow
   validates and uploads only `build/pages`, with one-day artifact retention,
   then deploys through the protected environment. Concurrent deployments are
   serialized, not cancelled mid-deploy.
5. Follow the deployment job's `page_url`, confirm HTTPS, and repeat the scenario,
   policy, narrow-screen, and browser-console checks on the hosted site. The
   expected default project URL is `https://cgfixit.github.io/yara-gate/`; this
   guide does **not** claim it is already live. Keep HTTPS enforcement enabled.

See GitHub's [publishing-source setup](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
and [custom-workflow requirements](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages).
The workflow does not enable Pages or change environment protections itself.
To update the site, review/merge the change and run the same workflow again.
To roll back, revert the relevant site change through review and redeploy `main`;
to withdraw it, unpublish the Pages site in repository settings.

## Recording provenance and refresh

The initial dataset was captured on November 1, 2026 at 16:09:44 UTC from scanner
revision `68e27e7917e0ca5b2f0ebfb8428c67e97ed6fbda`, Python 3.12.12 and YARA-X
1.22.1. It uses the 80 bundled rules only, with no vendor packs. The six examples
are an ordinary note, a quoted override, a secret-transfer request to an invalid
example address, an HTML-encoded override, a synthetic executable header named
as a PDF, and a deliberately broken rule compilation in a disposable rules tree.
No sample was executed and no referenced URL was fetched.

For a refresh, run `scan_bytes` from the intended source revision with disposable
copies of `rules/local` and `rules/rules.lock`, using all three policies for each
example. The failure case must use its own deliberately invalid rule copy. Save
only the response/finding fields allowlisted by the builder, plus `exit_code`;
omit paths, namespace paths, timings, and input/matched bytes. Record the source
revision and UTC capture time, verify the policy and incomplete outcomes, inspect
the public JSON, and rerun the artifact checks and browser acceptance before
review. A recording never authorizes access to another input.

See the [dated verification record](verification/2026-11-01-pages-demo.md) for
the observed outcomes, exact artifact fingerprints, screenshots, and limits.
