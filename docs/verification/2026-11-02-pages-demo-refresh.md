# Pages recorded-demo refresh — November 2, 2026

This record covers a refresh of the static Pages companion's recordings, a
committed recorder, builder consistency checks, and small interface changes. It
is not evidence for a hosted scanner: the site still replays saved results.
The work was exercised as an uncommitted change on `main` at
`38e100bbc559e86e570e3361256498d3a0c23420` (branch `claude/pages-demo-refresh`).

## Deployment status before this change

The GitHub Actions API shows `pages-demo` run 3
([41347105100](https://github.com/cgfixit/yara-gate/actions/runs/41347105100)):
a manual `workflow_dispatch` on `main` at `1d13547`, November 1, 2026 20:29 UTC.
Both jobs succeeded and the deploy job logged the environment URL
`https://cgfixit.github.io/yara-gate/`. `web-demo/`, `scripts/`, and the workflow
did not change between `1d13547` and `38e100b`, so the live site served the
November 1 recordings (revision `68e27e7`, 80 rules) while `main` shipped 82.
This environment's egress proxy refused `cgfixit.github.io`, so the hosted page
itself was **not** fetched here; the deployment is established from the API only.

## Real scanner recordings

`scripts/record_pages_demo.py` ran in the locked environment (Python 3.12.3,
YARA-X 1.22.1, yara-gate 0.2.0) with the scanner sources clean against `HEAD`.
It called `scan_bytes` for each of six inert inputs under all three policies,
against disposable copies of `rules/local` and `rules/rules.lock`; the failure
case used its own copy with one invalid rule file. No vendor pack was installed,
no target was executed, and no referenced URL was fetched.

```sh
uv run python scripts/record_pages_demo.py --output web-demo/recordings.json
```

Captured at **14:24:08 UTC** on November 2. 82 bundled rules compiled with zero
skips. Ruleset SHA-256:
`b59e933f08a25a943ae4e1492598eafea50a4d279b891a85107b166a872f18d1`.

| Case | default | agent-ingest | agent-document |
| --- | --- | --- | --- |
| plain | clean / 0 | clean / 0 | clean / 0 |
| note | advisory / 0 | block / 1 | advisory / 0 (notes only) |
| advisory | advisory / 0 | block / 1 | block / 1 |
| encoded | advisory / 0 | block / 1 | advisory / 0 (notes only) |
| pe_pdf | block / 1 | block / 1 | block / 1 |
| incomplete | incomplete / 2 | incomplete / 2 | incomplete / 2 |

Before writing, the same recorder was run to a scratch file and compared with
the November 1 dataset. The JSON was byte-identical in layout and differed only
in `source_revision`, `captured_at`, and, in the 15 completed records,
`compiled_rules` (80 → 82) and `ruleset_sha256`. Verdicts, findings, offsets
(the encoded case is still `html-unescaped`, offset 3, length 28), input
fingerprints, and coverage counters were unchanged. The six documented inputs
reproduce the recorded input SHA-256 values.

With `# probe` appended to `src/yara_gate/__init__.py`, the recorder exited with
`refusing: scanner sources differ from HEAD` and wrote no file; the probe line
was then reverted.

## Builder consistency checks

`validate_recordings` now also rejects: completed recordings with more than one
ruleset/runtime, a scenario whose policies record different inputs, `advisory`
or `note` flags that disagree with the findings, non-integer or boolean counters
and offsets, rule identifiers that are not identifiers, and a non-UTC capture
time. A direct probe mutated the refreshed dataset once per rule and each
mutation was rejected with its message; the unmodified November 1 and November 2
datasets both validated. `uv run pytest -q tests/test_pages_build.py` passed
(4 tests), and Ruff check/format passed on `scripts/`.

## Interface changes

- Header link to the repository (`Source on GitHub`, `rel="noopener noreferrer"`,
  within the builder's link allowlist).
- The local-run guide starts with `git clone` and `cd yara-gate` instead of
  assuming a checkout.
- The policy comparison table follows the picker's order (agent-ingest,
  agent-document, default).
- Shorter policy labels and narrow-screen select padding. Measured with the
  page's computed font, the policy names were truncated at 360, 375, and
  390 CSS pixels before the change and fit at all three after it. At 320 the
  agent-ingest label and the executable scenario's title still truncate.
- Open Graph title, description, and type for link previews. No image or other
  asset was added; the CSP and the four-file artifact are unchanged.

## Browser acceptance

Headless Chromium 153.0.8010.12 through the pre-installed Playwright, against a
loopback `python3 -m http.server` serving only the built artifact at
`/yara-gate/`. This is an equivalent real browser, not Computer Use, and not the
hosted site.

- At 1366×900 and 375×740, all six scenarios under all three policies displayed
  the recorded verdict, exit, and decision text (18 per viewport).
- Only the HTML, stylesheet, and two modules were requested; selection changes
  made no further requests. No console messages or page errors.
- No horizontal document overflow at either width.
- The comparison table read `agent-ingest, agent-document, default`, and the
  metrics showed 82 compiled rules.

Two consecutive builds were byte-identical. Builder: system Python 3.13.18;
`node --check` (Node 22.23.4) passed for both generated modules.

| Public artifact | SHA-256 |
| --- | --- |
| `app.mjs` | `210d2a4f44add310f4cc870536b731fb3fbe303848b8a726ab28eea567a0bc58` |
| `index.html` | `8611aa22f7c6ed9ba097c73e4d2841819ad45b7efb271246c0d07136d24d0b2f` |
| `recordings.mjs` | `8f2087d12576941294593e76358f8fa37788caa44c89ea951ee1853cbbb90ca9` |
| `style.css` | `dc4bf3090613bc8a646583699a79cf7a9b54e78eefd04be5b2c8e2b6cc3305fd` |

## Limits

The hosted site, HTTPS, and the post-merge deployment were not exercised here;
the refreshed data reaches the site only after a manual `pages-demo` run on
`main`. No new screenshots were captured; the November 1 Pages screenshots
remain dated captures of the 80-rule dataset. Other browsers, a screen-reader
audit, vendor-pack accuracy, and live CyClaw/Harness integration are unverified.
