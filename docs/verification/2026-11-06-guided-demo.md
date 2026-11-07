# Guided synthetic workflows: November 6, 2026

Base: `682cf08fbb37` on refreshed `origin/main`; there were no open PRs at the
initial overlap check. Implementation: `a4f3e517430ec177a426498d96436bb5f99439de`.
The source, scanner rules, and fixtures used below are from that commit. The
subsequent evidence commit updates only recordings, screenshots, and documentation.

The Pages replay now opens on a supplier workbook scenario with its outcome beside
it. Five fictional workflows select existing fixtures; the full 20-pair catalog
and incomplete case remain accessible. The local workbench has matching shortcuts
that prepare a sample and reset the policy to `agent-ingest`, clearing any old
result. The root `demo.html` describes both entry points. No detection, disposition,
network policy, dependencies, or deployment workflow changed.

## Direct recording and artifact checks

Python 3.12.12, locked YARA-X 1.23.0, 85 bundled rules, zero skipped files on
completed scans. `uv sync --frozen --group dev` prepared the environment. No vendor
packs were installed. An owned temporary rules copy and cache were used; no
operator gate home or real document was used.

Commands run from the checkout (the `.venv` commands use that locked environment):

```sh
XDG_CACHE_HOME=/private/tmp/yara-gate-guided/cache .venv/bin/python scripts/record_pages_demo.py \
  --output web-demo/recordings.json --baseline web-demo/recordings.json
.venv/bin/python scripts/build_pages.py --output /private/tmp/yara-gate-guided/preview/final/yara-gate
node --check /private/tmp/yara-gate-guided/preview/final/yara-gate/app.mjs
node --check /private/tmp/yara-gate-guided/preview/final/yara-gate/recordings.mjs
.venv/bin/python docs/verification/check_text_controls.py
git diff --check
```

All passed. The inline local-workbench JavaScript was also extracted and passed
`node --check`. The recorder executed 41 synthetic inputs under all three policies
(123 results). Every outcome matched the reviewed baseline; only revision and
capture time changed. All 20 detection fixtures were blocked under `agent-ingest`;
all 20 controls were clean with zero findings under every policy; the intentionally
broken rules example stayed incomplete under every policy. The builder validated
exactly four public files, including the existing restrictive CSP and recording
allowlist. The broad local test suite was not run for this UI change.

## Browser acceptance

Computer Use on macOS in the in-app browser, November 6, approximately
22:32–22:34 EST (America/New_York). The final Pages artifact was served at a project
subpath on an owned loopback HTTP server. The live workbench used
`yara-gate demo --port 0 --rules /private/tmp/yara-gate-guided/rules` at
`127.0.0.1:59179`. The server started from the dirty candidate whose HTML was then
committed unchanged as `a4f3e51`; its source hash is below.

- Browser assertions exercised all five workflows in each app: supplier review,
  build triage, design handoff, model intake, and repository intake. Each selected
  attack returned block under `agent-ingest`; its twin returned clean. Live
  workflow selection cleared the preceding verdict before the next scan.
- Changing the supplier case to `agent-document` gave advisory/exit 0 with a
  notes-only explanation in both apps. In the live UI the policy change cleared
  the old result before scanning again.
- Expanding the replay catalog, filtering to Rules, and selecting the compilation
  failure produced incomplete/exit 2 and hid the former workflow context and twin.
- Submitting empty text after a live result displayed the input error and cleared
  the verdict. No target was executed, unpickled, or contacted.
- Desktop rendering was inspected at 1265 × 712. At the browser's effective
  narrow viewport (375 × 812), both pages had document scroll width equal to
  client width. The replay's model-intake twin button worked, with vertically
  stacked comparisons. The temporary viewport override was reset afterward.
- No warning/error console entries were observed on the replay or live page.

The assertions inspected rendered verdicts and visibility through real controls;
no simulated scan result was injected. These checks do not exercise an installed
agent integration, actual uploaded traffic, or file relocation. The old precision
studies linked by the page were not rerun. Their scopes remain labeled, and no
production false-positive rate is claimed. Hosted checks and deployment are
separate from this local evidence.

## Original screenshots and hashes

These are original JPEG viewport captures, saved without cropping or re-encoding.
Only synthetic context and inert fixture results are visible.

| Capture | Size | SHA-256 |
| --- | --- | --- |
| [Guided replay](../../screenshots/yara-gate-guided-replay.jpg) | 1265 × 712 | `9d17621f10c5641a5e24ea5758ff833e5aa7d256dd3140a7099403d0b6880ffd` |
| [Live workbench](../../screenshots/yara-gate-guided-local.jpg) | 1265 × 712 | `94be02d507f40f4670e99289c3c38967969f7d18d1d079e318b0765deef01f54` |
| [Narrow replay comparison](../../screenshots/yara-gate-guided-mobile.jpg) | 375 × 812 | `1d44af70f21781fc42931d3065a9687bde4b1162ea48d04a8cd84ce5243f6c4d` |

Source SHA-256 fingerprints:

| File | SHA-256 |
| --- | --- |
| `src/yara_gate/demo_page.html` | `96a222ef113d38967bd96302cc1511b6da8eedfa509335776b2db2a13100ca1e` |
| `web-demo/index.html` | `53019a6b0300836ef68aabe109a37b410ddcb7b9ef6830bb7f1d0e4e03b6e921` |
| `web-demo/app.mjs` | `c6c90c059e778ee87606586baecb699946138438891e31ca472f9686b30dafb0` |
| `web-demo/style.css` | `79ea011e8d46aa9f9bcde3709fc30bb3e85c8eaae0da5adec53f91557deb41e8` |
| `web-demo/recordings.json` | `7081321dc0d75e7ab479127977f2648a2105199864dd3c8ca9b49c42ef3035e7` |
