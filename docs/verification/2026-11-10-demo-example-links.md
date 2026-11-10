# Demo example links and a resync with main — November 10, 2026

Base: `main` at `163ec4ae8f8725bdfe504d5ddfb0ffd9770f3fb1`, which holds the shared demo
catalog (#201), the workflow and link audit (#202), and the independent-verdict check (#203).
No pull request was open. Linux x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85 bundled
rules, no vendor packs, disposable rules copy and `HOME`. Headless Chromium 153.0.8010.12
through Playwright. No scanner, rule, policy, intake, recording, or workflow file changed.

## State found

- Documentation: `check_doc_links.py` passed (533 relative links). No reference to the removed
  `demo.html` launcher or the old `pages-demo` workflow name remained outside dated records.
  The README's CI paragraph did not name the checks #202 and #203 added.
- Hosted demo, `https://cgfixit.github.io/yara-gate/`, loaded in the browser: HTTP 200,
  recorded from `163ec4ae8f87`, 58 examples, scoreboard 28 / 28 held, 28 / 28 twins clean,
  0 findings across 84 twin recordings, 2 / 2 unfinished scans incomplete, seven workflows.
  Only the page's four files were requested; no console message. No horizontal overflow at
  1280, 1040, 800, 390, or 320 px.
- One wording defect on that page: for a clean result with derived views, the sentence read
  "Nothing matched, though the scanner read the text with small capitals…" and left out the
  original bytes, which are always read.

## Changes

- Public page: the address names the open example and policy (`#example/policy`). The page
  writes it on a selection or policy change and reads it on load and on `hashchange`. Both
  parts are looked up in the recordings; nothing from the address is written into the page.
- Workbench: an example id after `#` in its address selects that sample on load.
- README: each row of the intake table links to its recorded example, and the CI paragraph
  names the workflow audit, the link check, type checks over `scripts`, and the
  `independent-verdict` check. The user guide and the Pages guide describe the links.
- The clean-result sentence now starts with the original bytes.
- `tests/test_pages_build.py` fails if a documented demo link names an example the recordings
  lack or a policy that does not exist.

## Browser acceptance

The four-file artifact built by `scripts/build_pages.py`, served from a loopback directory:

| Address | Opened |
| --- | --- |
| no fragment | default example, `agent-ingest`; the address is left unchanged |
| `#word_hidden_override/agent-document` | hidden Word text, `agent-document`, block |
| `#mcp_tool_poisoned` | poisoned tool list, `agent-ingest` |
| `#pickle_call/bogus` | the checkpoint, policy left at `agent-ingest` |
| `#no_such/agent-ingest`, `#catalog`, a malformed percent escape, a fragment holding an `img` tag | default example; no error, nothing rendered from the fragment |
| workflow, policy, card, and strip clicks | the address follows each |
| fragment changed in place to `#zip_concat/default` | glued zips, `default`, advisory |

A linked load moves focus to the result heading. Workbench: `/#mcp_tool_poisoned` selects that
sample; an unknown id and no fragment select the default. No console error on either page.

## Checks

- `scripts/record_pages_demo.py --baseline web-demo/recordings.json` at the committed head:
  outcomes match; only provenance refreshed.
- `tests/test_pages_build.py`, `tests/test_demo.py`, `tests/test_pages_deploy.py`: passed.
- Ruff check and format, `mypy --strict src scripts`, `check_text_controls.py`,
  `check_doc_links.py`, `node --check web-demo/app.mjs`: passed.

## Boundaries

- The README's links open the default example on the hosted site until this change is
  deployed; the old page ignores the fragment.
- Whether `independent-verdict` is a required check on `main` is a repository setting and was
  not read.
- Headless Chromium only. No screenshot was added; the November 10 captures still show the
  pages apart from the address.
