# Normalized reader text: research and verification — November 7, 2026

The 20 attack examples in the existing Pages catalog are historical misses, not
20 current failures. On main `05f94caaf596413a2011612821f3d7d2916e3e16`, all 123
recorded policy outcomes reproduce: 20 attacks held under `agent-ingest`, 20
twins clean with no findings under all three policies, and one compilation failure
held as incomplete. This change closes two additional normalization gaps while
reusing existing phrase rules, severities, and policy decisions.

## Scope and baseline

Work used an isolated checkout from refreshed `origin/main`, preserving the
operator's `cx/detection-review` checkout and other worktrees. The implementation
and sample source is commit `6fe62e337e6385d5fc29244674147fddf71e036d`; the
following recording/evidence commit changes no scanner code. Python 3.12.12,
Unicode database 15.0.0, locked YARA-X 1.23.0, 85 bundled rules, zero skipped files,
and no vendor downloads. Scans use copied rules and disposable homes.

Open work was inspected before implementation:

- [#182](https://github.com/cgfixit/yara-gate/pull/182), head `0fa5098`, adds
  hidden Office/PDF text detection. Its current CI passed; deployment jobs were
  skipped and no submitted review was present. This change does not implement or
  accept its visibility heuristic or native-viewer claims.
- [#184](https://github.com/cgfixit/yara-gate/pull/184), head `6a53365`, records a
  broader detection review. Its current CI passed with no submitted review.
- [#171](https://github.com/cgfixit/yara-gate/issues/171) and
  [#183](https://github.com/cgfixit/yara-gate/issues/183) retain their separate
  RTF, annotation, ingestion, visibility, and scope work.

A `git merge-tree` trial is clean with #184. With #182 it reports conflicts in
`scanner.py`, `README.md`, `docs/rules.md`, and `rules/README.md`. A disposable
merge resolved them by retaining the folded PDF pieces and #182's hidden-text
findings, and preserving both documentation changes. All 37 new tests and the
combined gap probe passed (201 ok, 3 open, no FAIL or STALE). This is focused
compatibility evidence, not authority to merge #182 or native-viewer acceptance.
The PRs remain independently based on main, so whichever lands second needs
that integration and fresh verification.

Acceptance is narrow: reproduce both misses on main; detect the same bytes on
the candidate; preserve benign twins, native-language text, case-sensitive ASCII
signatures, PDF piece boundaries, namespace/member identity, report privacy,
policy exits, and physical disposition; compare identical corpora; exercise the
real demos; publish a draft without merging.

Affected surfaces are `content.folded_text`, its existing raw/decoded/joined
callers, `scanner._pdf_text_findings`, focused tests, the existing gap probe,
shared demo samples and registry, the Pages recorder/builder, and maintained
README, operator, rule, integration, and demo references. No dependency or rule
file was added; dated prior evidence and screenshots retain their original claims.

## Research and decision

| Primary source | Date | Application |
| --- | --- | --- |
| [Unicode case FAQ](https://unicode.org/faq/casemap_charprop.html) | Undated; accessed 2026-11-07 | Cyrillic has case. Preserve its script while comparing casing. |
| [Python 3.12 `str.lower`](https://docs.python.org/3.12/library/stdtypes.html#str.lower) | Undated; accessed 2026-11-07 | Reuse the standard library's Unicode lowercase conversion. |
| [Unicode TR39, revision 34](https://www.unicode.org/reports/tr39/tr39-34.html) | 2026-08-27 | Confusable detection can flag legitimate text; identifier skeletons are not a general natural-language rewriting rule. |
| [Unicode TR15, revision 58](https://www.unicode.org/reports/tr15/tr15-58.html) | 2026-08-12 | Compatibility normalization can erase distinctions; retain the existing supported normalization and test its composition. |

The multilingual YARA rule already lists Russian override phrases, but YARA's
`nocase` covers ASCII. Its raw Cyrillic alternatives list only initial capitals.
An uppercase or title-case instruction therefore returned clean. The existing
mixed-script token callback now lowercases a token only when its letters are all
Cyrillic. Mixed-script look-alike mapping runs first. ASCII `DAN` stays uppercase,
and ordinary `Dan`, Greek, and accented Latin retain their previous behavior.

PDF glyph decoding already produces blocks and reconstructed paragraphs, but
those pieces bypassed the folding helper used by other readers. The scanner now
uses that helper for both, producing `pdf-text+text-folded` and
`pdf-paragraph+text-folded` only when spelling changes. Original pieces remain
scanned, and separate paragraphs stay separate. This is a consistency fix to the
existing byte-to-reader-text-to-rule path, not a new language classifier.

Generic transliteration, dotless-i substitution, and combining underline or
strike-through removal are deferred. The latter two decorative forms and
dotless-i examples still reproduce misses. Ordinary accents and script distinctions
must not be discarded merely to increase a synthetic detection count.

## Reproduced improvement

| Inert input | Main under `agent-ingest` | Candidate | Benign boundary |
| --- | --- | --- | --- |
| Uppercase/title-case Russian override | Clean | Block, multilingual note in folded text | Uppercase Russian request to ignore noise stays clean |
| Same Russian through UTF-16, escaped JSON, or joined HTML | Clean | Block, labeled derived view | Existing nine-language positive/benign pairs retained |
| Glyph-ID PDF with leet, Cyrillic look-alikes, or Latin small capitals | Clean | Block, phrase note in folded PDF text | Same transformations in ordinary review prose stay clean |
| Same PDF phrase split across adjacent text objects or a wrapped line | Clean | Block, folded PDF paragraph | Phrase halves in separate paragraphs stay clean |

The new indicators retain **note** severity: default and `agent-document` return
advisory/exit 0; `agent-ingest` returns block/exit 1. A note is evidence of a phrase,
not proof of malice. Existing documentary quotation suppression remains intact.

## Local evidence

- Focused baseline tests: Cyrillic cases had 7 failures and 8 passes; PDF folding
  had 19 failures and 3 passing benign controls. The failures were clean results
  on inputs containing the existing phrases, not incomplete scans.
- Candidate: all **37 focused tests passed**. They exercise `scan_bytes` and
  `scan_file`, all policies, nine supported languages, native-script and ASCII
  case boundaries, PDF line/paragraph boundaries, duplicate rule IDs in distinct
  namespaces, ZIP member ordinals, original byte hashes, and SARIF derived regions.
- Identical-corpus comparison: **906 inputs × 3 policies × 2 revisions**.
  The inputs were the existing 324 generated precision files, 82 baseline
  Markdown documents outside `.agents`, and the first 500 sorted Python 3.12
  standard-library `.py` files outside `site-packages`. **Zero changed verdicts,
  incomplete reasons, rule IDs, severities, views, or member paths; zero incomplete
  scans** on either revision. Documentary and source inputs are not asserted clean.
- The generated precision table remains unchanged: 81 of 85 rules have no hits;
  four documented Windows shortcut collisions each occur once in 324 files.
- The existing look-alike scan regressions passed (9 cases). The updated gap
  probe reports 163 ok / 6 open, up from 159 ok / 6 open; no FAIL or STALE.
- Direct CLI intake passed 16 operations: both new attacks and both twins under
  default → agent-ingest → agent-document → default, resubmitting identical
  bytes to the same disposable home. JSON verdict, exit, on-disk destination,
  source bytes, and unchanged rule files agree.
- Two 4 MiB synthetic inputs (uppercase Cyrillic prose and mixed-script tokens)
  remain clean and complete in 0.898 s and 1.079 s respectively on this Mac.
  The existing 16-input, 4 MiB timing tripwire also passes. These are bounded
  smoke checks, not a performance improvement claim.
- The maintained direct rule/intake probe passes. Ruff, formatting, strict mypy,
  text-control and whitespace checks cover the affected files.

Commands run from the candidate root with its locked `.venv` (the same commands
are available through `uv run`):

```sh
.venv/bin/pytest -q tests/test_cyrillic_case.py tests/test_pdf_text_folding.py
.venv/bin/pytest -q tests/test_scanner.py::test_look_alike_spellings_are_folded_as_a_view
.venv/bin/python docs/research/probe_rule_coverage.py --verify
.venv/bin/python docs/research/probe_detection_gaps.py --verify
.venv/bin/python docs/verification/measure_precision.py --fail-over
.venv/bin/python docs/verification/check_worst_case_timing.py
.venv/bin/mypy --strict src
.venv/bin/python docs/verification/check_text_controls.py
.venv/bin/python scripts/record_pages_demo.py --output web-demo/recordings.json
.venv/bin/python scripts/build_pages.py --output <new-disposable-site-directory>
.venv/bin/pytest -q tests/test_pages_build.py
```

Ruff check and format ran on changed Python and Markdown files. No Actions
workflow changed, so no workflow-lint delta was required.

The comparison used the baseline's identical bytes and copied rules with either
the archived baseline or candidate scanner on `PYTHONPATH`. Session artifacts
include `sweep.py`, `sweep-base.json`, and `sweep-candidate.json` under
`/private/tmp/yara-detection-evidence-20261107/`. These paths are local working
evidence; the maintained tests and gap probe carry the durable regression cases.

## Demos and remaining limits

Two new attack/twin pairs bring Pages to **45 scenarios / 135 policy outcomes**
and the local workbench to 15 pairs. All 22 Pages twins are clean without findings.
All original 123 verdict/finding/exit outcomes are unchanged. The old benign
Russian SMS now also runs a folded view: `bytes_scanned` changes from 98 to 196
under each policy. The reviewed recordings retain that coverage change.

The recorder produced 135 outcomes at `6fe62e3`; a second recording matched
those reviewed outcomes exactly apart from provenance. The Pages builder
validated four allowlisted files, and all 11 focused Pages build tests passed.
The real HTTP demo sample test also passed; its first attempt was blocked at
loopback bind by the sandbox, before assertions, then passed unchanged with
authorized listener access.

Real-browser acceptance passed on the built Pages artifact and the running
loopback scanner at `6fe62e3`, using Playwright 1.64.1 and installed Chrome
157.0.8103.38. CUA had no available browser surface, so the equivalent browser
route was used. Both new pairs under all three policies displayed the expected
verdict, exit, rule, severity, and folded view; attack → twin → attack navigation
worked on both surfaces. Pages showed 22/22 attacks, 22/22 twins, and 1/1 held
failure. No page/console errors or requests outside the two loopback origins were
observed. Both 390 px mobile layouts had no horizontal overflow; desktop/mobile
captures were inspected. Clearing a live input and attempting an empty scan left
no stale verdict. The owned browser and both servers were stopped. Local evidence:
`/private/tmp/yara-demo-browser-20261107/browser-acceptance.json`; screenshots
remain local and do not replace the repository's historical screenshot evidence.

Full local suites, native PDF/Office rendering, vendor packs, and live consumer
integration are outside this run. The six existing OPEN gap-probe cases remain:
RTF formatting/hex, PDF annotation hex, and three hidden Office/PDF cases owned
by #182. These synthetic results and corpus comparisons establish no production
recall or false-positive rate and no comprehensive prompt-injection defense.
