# Detection review and next steps — November 7, 2026

The most useful next work is to make coverage and prior read decisions reliable as
the detector evolves. The current design already has useful complementary layers:
YARA-X signatures, structural heuristics, bounded reader views, policy, and
quarantine. This review found concrete precision and coverage gaps, and reproduced
a sync-folder upgrade path that preserves an obsolete permission to read.

Scope: offline screening before messages, files, retrieved documents, repository
content, and tool results enter an agent. This is a detection review and roadmap,
not a comprehensive security audit or approval of the open PR.

## Source and open work

- Local `main` and fetched `origin/main` both point to
  `05f94caaf596413a2011612821f3d7d2916e3e16`. The checkout was clean before this review;
  existing feature branches and other worktrees were preserved.
- The only open PR was [#182](https://github.com/cgfixit/yara-gate/pull/182),
  Office/PDF hidden-text detection. Its head changed during review from `8f6b29f`
  to `0fa5098ee2860ebd254d5566c2541b55de868588`. The latter's PDF header discovery
  delta was read and the selected runtime probes rerun against its archived source.
  The PR contains current main; it was not merged locally or remotely.
- At 05:46 UTC, the latest PR head had successful Windows, demo-recording, three
  CodeQL analysis, and CodeQL alert checks. Ubuntu and macOS checks were running.
  The two main-only deployment checks were skipped. GitHub reported mergeable,
  with no submitted reviews or inline review threads. These are separate from
  approval or completed CI. The observed main push CI run was also still pending.
- Before publication, the same PR head's Ubuntu, macOS, Windows, demo-recording,
  and three analysis checks had all completed successfully. The separate CodeQL
  alert check also passed with no new alerts in the PR's changed code. The two
  main-only deployment checks remained skipped. This updates the earlier CI
  snapshot, not the review's runtime coverage or viewer acceptance.
  [CI run](https://github.com/cgfixit/yara-gate/actions/runs/42344060773),
  [CodeQL alert check](https://github.com/cgfixit/yara-gate/runs/128317946681).
- [#171](https://github.com/cgfixit/yara-gate/issues/171) already tracks the remaining
  reader work and measurement cadence; [#183](https://github.com/cgfixit/yara-gate/issues/183)
  already describes the SVG and MCP issues reproduced below. Some #183 statements
  describe an older base: current main already has bounded intake and the
  capture/snapshot pre-read handoff. They should not be repeated as unchanged defects.

## Current detection methods

| Layer | What the current source does | Practical boundary |
| --- | --- | --- |
| YARA-X | Matches shipped local rules and explicitly installed vendor packs; rule metadata determines severity; reviewed overrides scope vendor exceptions | Lexical and structural evidence does not establish semantic safety. This review used 85 bundled rules, zero skips, no vendor bodies |
| Decoded and normalized text | UTF-16, HTML/JSON escapes, Unicode folding, controls, base64, percent encoding, MIME headers/parts | Bounded supported transformations; novel encodings and paraphrases remain possible |
| Reader views | Joins appropriate OOXML runs/cells/comments, HTML/SVG and Markdown pieces, source comments, notebook cells, PDF text blocks and paragraphs | A custom reader does not necessarily emit the same text as a consumer's extractor or vision model |
| Structural heuristics | File/type/name checks, PDF actions and encryption, Office macros/DDE, embedded executables, pickle opcode inspection, model headers, MCP-shaped JSON checks | Some checks depend on names and bounded structural recognition; no target is executed |
| Container handling | In-memory supported archive/mail traversal; shared depth, member, expansion, and deadline budgets | Recognized unsupported/encrypted containers hold as incomplete; supported formats can still have unsupported subfeatures |
| Enforcement and evidence | Incomplete takes precedence; `agent-ingest` holds notes and advisories; `agent-document` allows exact notes-only results; reports include views, counts, digests and versions | Callers must enforce the result on the same bytes. Coverage counters do not prove all consumer-visible content was inspected |

Owning sources: [scanner](../../src/yara_gate/scanner.py),
[content readers](../../src/yara_gate/content.py),
[PDF text reader](../../src/yara_gate/pdftext.py),
[heuristics](../../src/yara_gate/heuristics.py),
[models](../../src/yara_gate/models.py), and [rules](../../src/yara_gate/rules.py).

## Reproduced findings

### 1. P1: scanner upgrades do not invalidate or revoke sync-folder read permission

The sync example's skip key contains only size and mtime
([lines 83–86](https://github.com/cgfixit/yara-gate/blob/05f94caaf596413a2011612821f3d7d2916e3e16/docs/examples/sync_folder_gate.py#L83-L86)).
Using its real CLI path and a disposable home:

1. Main scanned a DOCX with a vanished instruction under `agent-document`, exited
   0, and placed it in `allowed/` with a notes-only record.
2. Switching the scanner to PR `0fa5098`, keeping the same source and home, exited
   0 without scanning; the allowed copy and old record remained.
3. The same PR scanner with a fresh home exited 1 and put the same bytes in `held/`.
4. Forcing a rescan in the original home by changing only the source timestamp
   produced the held record, but the prior copy also remained in `allowed/`.

The placement path writes the new destination without withdrawing the old allowed
entry ([lines 101–110](https://github.com/cgfixit/yara-gate/blob/05f94caaf596413a2011612821f3d7d2916e3e16/docs/examples/sync_folder_gate.py#L101-L110)).
This affects deployments using this example's `allowed/` contract; it does not
establish that a live CyClaw or harness adapter uses this behavior.

Fix both parts together: bind cached admission to the current detector build,
ruleset, policy, logical name and source identity; withdraw stale permission before
continuing retrieval when a required rescan holds or fails. Keep historical
evidence outside the active read set. The downstream index needs the same
invalidation rule. A ruleset digest alone is insufficient: main and this PR
produce different hidden-text verdicts with the same ruleset digest, YARA-X version,
and reported tool version `0.2.0`.

Acceptance: the four-step upgrade sequence must leave no currently readable stale
copy or index entry. Include policy/ruleset changes and incomplete rescans. Reuse
the existing ledger; no new service is needed.

### 2. P1 for MCP consumers: a traversal limit silently removes coverage

The same inert MCP-style shell configuration blocks at list item 50 and returns
clean at item 51, under both agent policies, on main and PR `0fa5098`. Nesting it
below depth 8 also returns clean. `_walk_mcp` silently stops at those limits
([source](https://github.com/cgfixit/yara-gate/blob/05f94caaf596413a2011612821f3d7d2916e3e16/src/yara_gate/heuristics.py#L1591-L1611)).
This demonstrates loss of the intended shell heuristic, not execution of the fixture.

Use a global node budget and the existing deadline, with an explicit incomplete
result when recognized MCP content cannot be fully inspected. Keep ordinary large
JSON distinct. Also make the caller contract explicit: the heuristic currently
requires a `.json` name; the identical configuration under a generic buffer name
was clean. That suffix requirement is an existing interface boundary, separate
from the silent truncation defect.

Acceptance: position/depth permutations of the same recognized entry yield the
same finding or a named coverage limit, never an unexplained clean result.

### 3. P2: the SVG rule blocks an ordinary page containing an unrelated script

An HTML page with a scriptless SVG icon and a separate inert JavaScript declaration
blocked under both policies on both revisions. The active-SVG control also blocked.
`doc_svg_active` tests presence anywhere in the input, not membership in one SVG
subtree ([rule](https://github.com/cgfixit/yara-gate/blob/05f94caaf596413a2011612821f3d7d2916e3e16/rules/local/doc_svg_active.yar#L10-L16)).

Scope active-content detection to the SVG element using a bounded structural
reader. Retain embedded SVG coverage; filtering only by `.svg` extension would
lose it. Add benign HTML plus inline-icon controls alongside standalone and
embedded active SVG. Fix this before broadening phrase rules: avoidable hard
blocks pressure users to bypass the gate.

### 4. Known reader gaps remain; #182 closes the tested hidden-text gap

| Inert case | Main, `agent-document` | PR `0fa5098`, `agent-document` |
| --- | --- | --- |
| Vanished DOCX instruction | Notes-only, exit 0 | Block, exit 1 |
| PDF instruction in invisible render mode or white fill | Notes-only, exit 0 | Block, exit 1 |
| Same visible DOCX instruction | Notes-only, exit 0 | Notes-only, exit 0 |
| Hidden ordinary watermark / benign OCR-layer text | Clean | Clean |
| RTF formatting or hex escape splitting the phrase | Clean | Clean |
| Hex-encoded PDF annotation text | Clean | Clean |

The three latter reader-gap cases also pass `agent-ingest`; their known phrases
are not recovered. Reuse the existing lexical rules with bounded RTF paragraphs
and PDF annotation-string views, as #171 already proposes. Preserve piece
boundaries, benign twins, shared budgets and derived-view provenance.

Before accepting #182's visibility claims, exercise real viewers and the actual
extractor. Its documented exclusions include inherited styles, hidden sheets,
clipping/transparency and CropBox behavior. A specific calibration concern:
`w:webHidden` applies to web view, not normal paginated display. A hiding property
is evidence conditioned on viewer mode. [Microsoft's WebHidden semantics](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.webhidden?view=openxml-3.0.1)

## Improvements in delivery order

| Priority | Improvement | Acceptance evidence |
| --- | --- | --- |
| First | Fix cached admission/revocation, MCP truncation and SVG scope | The reproductions above change as intended; benign counterparts retain their decisions |
| Next | Complete #182 viewer/extractor checks; add the small RTF and annotation readers | Reader output matches the declared use; attacks and benign twins exercise each new view |
| Next | Enforce the existing original-plus-extracted-text contract in a real consumer | Exact buffer/hash handoff before indexing or model input; no unscanned fallback on error; record extractor build/options |
| Next | Make coverage limitations machine-readable | Distinguish no matching indicator from an unsupported/truncated relevant view; consumers declare required coverage for text, documents and visual input |
| Next | Add a hard parent timeout to the sync example; then evaluate isolated parser workers where needed | Hung child is killed, partial output rejected, input held; memory/CPU/output limits validated for the deployment OS |
| Ongoing | Run versioned, held-out evaluation on detector/parser/rule updates | Per-channel/policy benign holds, known attack coverage, incomplete rate, latency and memory; reviewed verdict/coverage deltas before promotion |

The two-stage scan contract is already in
[the integration guide](../integrations.md#pdfs-and-other-compressed-documents).
Proving its enforcement is more valuable than trying to emulate every renderer.
PDF extraction involves ambiguous ordering, whitespace and layout; image text
also requires a different stage. [pypdf's extraction limits](https://pypdf.readthedocs.io/en/stable/user/extract-text.html)

For coverage, start with supported-format gaps and explicit reasons, not a blanket
block on every unimplemented feature. For example, an unsupported PDF text filter
and an ordinary embedded image should not be conflated. If the consumer actually
sends images to a vision model, it needs an explicit admission policy for that
uninspected channel; bounded local OCR is an option to evaluate, not an automatic
core dependency.

The shared scanner deadline is cooperative. The sync example passes `--timeout`
but its parent `subprocess.run` has no hard timeout; the current pre-read example
already uses `timeout + 5`. The CMap tokenizer also materializes a section's tokens
between deadline checks. These are source observations, not measured resource
exhaustion in this review. Start with the existing subprocess boundary and retain
format budgets; use an OS-enforced worker boundary for stronger resource isolation.

Keep clean content untrusted at tool authorization, network destinations and
trusted-memory writes. Evaluate paraphrases and multi-message attacks at the
consumer, with a fixed attempt budget and synthetic task outcomes. An optional
future classifier should earn its incremental benefit and must not override
deterministic holds or permissions. [OWASP's agent-specific guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html#agent-specific-defenses)

Keep the current pinned installs, staged validation and visible skips. Add a
repeatable update comparison and a scanner build identity that changes with reader
or heuristic behavior. Scheduled review of vendor pins is useful; unattended
rule promotion is not justified by this review. See the separate
[primary-source research note](../research/2026-11-07-detection-primary-sources.md)
for the external evidence and optional directions.

## Verification and limits

- Locked environment: `uv sync --frozen --group dev --offline` succeeded using a
  temporary uv cache. Python 3.12.12, YARA-X 1.23.0; 85 local rules, zero skips.
- Direct library evidence: 17 inert inputs, both agent policies, main and final
  PR head (68 scans for that comparison). The prior PR head was also exercised;
  all 34 selected results were unchanged after its PDF-header follow-up.
- Real CLI evidence: the sync example drove the installed CLI with explicit
  source selection, copied rules, disposable folders and an outer verification
  timeout. Source bytes were unchanged. Both final-PR upgrade and forced-rescan
  findings reproduced.
- Ruleset digest in these runs:
  `4517a40579c9522edb8ad94babfee8cb338a4aded9fdb62d94f90133b3e35985`.
- Review probes and full synthetic results are in
  `/private/tmp/yara-detection-review-20261107/`: `probe_selected.py`,
  `probe_upgrade.py`, `main-selected.json`, `pr182-0fa5098-selected.json`, and
  `sync-upgrade-0fa5098.json`. These are session artifacts; the findings and
  acceptance criteria are recorded here.

The original review changed no production code, rules, dependencies or workflows
and performed no PR, issue comment, merge, vendor install or consumer
configuration change. These two review documents were subsequently prepared for
publication in a documentation-only draft, based on the same `05f94ca` main.
Full local suites, native Office/PDF viewers, OCR, live consumer integration and
production recall/false-positive rates were not checked. The selected fixtures
do not establish comprehensive detection or PR acceptance.
