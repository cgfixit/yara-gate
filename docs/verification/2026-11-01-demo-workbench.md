# Local scan workbench verification — November 1, 2026

The scanner-backed loopback page now explains policy decisions, finding severity,
and coverage, with a responsive layout and recoverable request states. This PR
changes the demo response allowlist and presentation, not scanner rules, policy
semantics, intake, or either consumer application.

## Exercised source and environment

- Base: `68e27e7917e0ca5b2f0ebfb8428c67e97ed6fbda`, refreshed `origin/main`.
- Candidate: dirty `cx/demo-agent-workbench` on that base. The final runtime
  file hashes below identify the implementation exercised; documentation and
  screenshots were added afterward.
- Python 3.12.12, locked YARA-X 1.22.1, yara-gate 0.2.0, macOS ARM64.
- Owned demo processes, launched with `uv run yara-gate demo --port 0 --rules
  <disposable-rules>`. Each rules root copied all 80 bundled rules. The normal
  root had zero skips; no vendor packs were downloaded and no operator gate
  home was used. The processes were stopped after verification.
- Open work inspected: #142 at `8ad87ee3b9ef805f4457e009185dc32b3f50b8d5`
  and #144 at `6641eab08b61c403ca423ce5f8fb6c3eedeb03b5`. Neither changes
  the demo. README edits are confined to the Live demo section; their rule and
  vendor work remains separate. Both heads' CI and CodeQL runs were successful
  when inspected; CodeQL upload is disabled. These are not this PR's checks.

| Runtime file | SHA-256 |
| --- | --- |
| `src/yara_gate/demo.py` | `a1d022de6216b98359566850585688cf01b5cd94bc264eacbae479c4dea3e901` |
| `src/yara_gate/demo_page.html` | `f3e890962b988866354266d74451c805056914ea2381dcb2bf84da28088ee573` |
| `tests/test_demo.py` | `6f8e1ea2d4733e099521e0aded1b512583e607b9f89a7736aee8ce413a95535d` |

## Computer Use: actual loopback scanner

The macOS in-app browser exercised the live HTTP page, not root `demo.html` or
a mocked scanner. Captures used inert built-in examples. Pasted synthetic text
was scanned as data; nothing in it was executed. Desktop and narrow layouts
were checked, including a 375 CSS-pixel-wide document view with no horizontal
overflow and a working keyboard-focusable **View result** anchor.

| Scenario | Observed |
| --- | --- |
| Plain example, agent-ingest | Clean, exit 0, 80 compiled rules, 1 content unit |
| Advisory example, default → agent-ingest | Advisory/exit 0 → block/exit 1; finding remains advisory and the policy reason is visible |
| Note example, agent-document → agent-ingest | Notes-only advisory/exit 0 → block/exit 1; document guidance does not permit messages |
| Executable named PDF example | Block/exit 1, `filetype_mismatch_pe`, unavailable offset represented without a fabricated position |
| Entity-encoded HTML phrase paste | Block/exit 1; note finding labeled `html-unescaped` with view-relative offset |
| MIME text paste | Block/exit 1; advisory finding labeled `mime:0`; two units, derived-view counts, fingerprints, and content-free JSON visible |
| Ordinary emoji and Persian joiners | Clean/exit 0 via Command + Enter submission |
| 16,385 emoji characters | Counter reports 65,540 UTF-8 bytes; rejected before submission; old result cleared |
| Empty paste / Clear | Actionable error or cleared state; no previous verdict remains visible |
| Deliberately invalid active local rule in a separate copied root | Incomplete/exit 2, `local rule compile failed`, zero scanned units; hold explanation and skip count visible |
| Deliberately invalid synthetic vendor rule in a separate copied root | Scan completes with 80 rules; one skipped file produces a reduced-coverage warning |
| Stop the owned normal server after a successful scan, then submit | Connection error, no current verdict, controls re-enabled for retry |

Changing a policy, example, or paste invalidates the previous result. The page's
loading controls were also observed during the first compilation. A clear or
browser abort does not claim to preempt the server-side scanner.

## Focused runtime and static checks

- `uv sync --frozen --group dev` used the locked environment.
- `uv run pytest tests/test_demo.py`: **10 passed**. This focused file exercises
  real HTTP sample scans, new coverage fields, non-echoing responses, rejected
  requests, same-origin/foreign-origin/foreign-host handling, invalid JSON
  encodings, non-JSON rejection, loopback-only binding, and in-memory scanning.
  Its existing launch-agent plist check also ran. No broad local suite ran.
- Added telemetry assertions initially assumed raw scans appeared in
  `views_scanned`. Inspection showed raw units are counted by `units_scanned`;
  the assertion and UI label were corrected to **Additional derived views**.
- A disposable Node VM probe executed the actual inline script with a minimal
  DOM and controlled transport: **8 checks passed** for duplicate submission,
  late responses after policy change, clear during a request, transport error,
  malformed response, HTTP rejection, multibyte size rejection, and literal
  rendering of markup-shaped metadata. This is deterministic state-machine
  evidence, separate from the browser checks above.
- Extracted inline JavaScript passed `node --check`.
- `uv run ruff check src/yara_gate/demo.py tests/test_demo.py` and matching
  `ruff format --check` passed.
- `uv run mypy --strict src` passed for all 16 source files.
- `uv run python docs/verification/check_text_controls.py` and `git diff --check`
  passed. No workflow files changed, so no new Actions lint run was needed.

The response adds only existing counters, versions, and fingerprints through
the explicit `DemoResponse` allowlist. It still omits paths and matched content.
All rendered metadata uses text nodes; no input becomes HTML. Existing nonce
CSP, self-only connections, frame restriction, no-store headers, body/text
limits, origin/host checks, and loopback binding are preserved. There is no new
dependency, local/browser storage, upload, telemetry, download, or file action.
The explicit GitHub documentation link is an outbound navigation when clicked.

## Original screenshot evidence

The first four were captured approximately 10:53–10:55 EST, America/New_York,
November 1. JPEG bytes
are saved directly from Computer Use without cropping or re-encoding. The
desktop capture shows the actual advisory hold; the document and failure
captures show the corresponding rendered outcomes, not just HTTP success.

The fifth capture (expanded coverage) was taken at 11:01 EST on November 1
against committed source `455b98ca6ab46c2f0f427ca3433c12da9419b7db`, with the
same runtime hashes above. A fresh owned loopback process and copied 80-rule
root scanned the inert PE-named-as-PDF example: block/exit 1,
`filetype_mismatch_pe`, one unit, 128 bytes handed to YARA, zero skipped files.
Computer Use expanded **Coverage & provenance** to show fingerprints, engine
version, and counters. No executable was launched. The original four captures
are unchanged.

| Capture | Dimensions | SHA-256 |
| --- | --- | --- |
| [Advisory hold](../../screenshots/yara-gate-workbench-hold.jpg) | 1265 × 889 | `72333daf71e0d76f531c005dcb72b0290bdcf7351eb1bf4e51fde65bdee1a71b` |
| [Notes-only document](../../screenshots/yara-gate-workbench-document.jpg) | 375 × 812 | `0294854c9e2f0b221d9a8232e21190b5c532ec31d298a3a7132861a376cd16ca` |
| [Incomplete hold](../../screenshots/yara-gate-workbench-incomplete.jpg) | 617 × 621 | `eaecf72c0c83a0c26558301ed82eba4949302b0077db5bbeab37d3c9f20d1624` |
| [Connection failure](../../screenshots/yara-gate-workbench-offline.jpg) | 375 × 812 | `eaa24829caa20f440db24cd14dbc08af7e4055b3f7a60c6686f98c5a34c95b37` |
| [Structural finding and expanded coverage](../../screenshots/yara-gate-workbench-coverage.jpg) | 1265 × 988 | `91d957b63091a2f110977d890b02b434c50b6ca9e481aa912233519f81031451` |

## Limits

This is local browser/API acceptance with bundled rules and synthetic fixtures.
It does not establish native Windows/Linux browser behavior, a screen-reader
audit, vendor-pack accuracy, production false-positive rates, or live CyClaw/
CG-agent-harness integration. The browser's **Clear** is not secure erasure;
clipboard contents, extensions, and host memory are outside this app's control.
The existing compiler can write a local rule cache, although pasted content and
scan reports are not persisted by the demo. Hosted CI status belongs to the
published PR head and must be read separately from this local record.
