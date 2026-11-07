# Encoded PDF annotation verification — November 7, 2026

This focused draft is based on the RTF draft #186 (`72aadf0`), which is based on
main `05f94ca`. Exercised scanner/demo source: `2e0609d06e37`; later commits only
integrate the RTF documentation follow-up and update documentation/recordings.
macOS 27.2 arm64, Python 3.12.12, YARA-X 1.23.0, 85 bundled rules, zero skips,
no vendor download. Ruleset SHA-256:
`4517a40579c9522edb8ad94babfee8cb338a4aded9fdb62d94f90133b3e35985`.

## Reproduced gap and approach

On main, the #171.7 hexadecimal annotation case was clean, without findings,
under all policies. `pdf-annotation` now decodes annotation `/Contents` separately
from page glyph text. It reuses the bounded PDF dictionary parser and decoded
object-stream members, then feeds original and folded pieces to existing rules.
No YARA rule or dependency changed. A matching phrase remains a note:
default/agent-document advisory (exit 0), agent-ingest block (exit 1).
Malformed recognized annotation content is incomplete (exit 2).

The [PDF Association's text-string explanation](https://pdfa.org/understanding-utf-8-in-pdf-2-0/)
distinguishes PDFDocEncoding, BOM-marked UTF-16BE and PDF 2.0 UTF-8 strings from
page glyph strings. The [annotation specification errata](https://pdf-issues.pdfa.org/32000-2-2020/clause12.html)
and the [pypdf PDFDocEncoding table](https://github.com/py-pdf/pypdf/blob/main/pypdf/_codecs/pdfdoc.py)
were consulted November 7; the latter was read through the GitHub connector.
The implementation uses no pypdf dependency. [Reader boundaries](../rules.md#pdf-annotation-boundaries)
state exactly which fields, encodings, object sources, and limits apply.

## Direct and focused verification

- `pytest -q tests/test_pdfannotations.py tests/test_pdftext.py tests/test_rtftext.py`:
  **62 passed** (26 annotation, six existing page-text, 30 RTF). Hex/octal,
  UTF-16BE/UTF-8, direct and indirect strings, >4 KiB references, compressed and
  uncompressed object streams, escaped PDF names, folded spelling, PDFDocEncoding,
  language tags, odd hex nibbles, literal escapes, and all policy/twin outcomes.
- Boundary cases: annotations and blank-line-separated paragraphs cannot form a
  phrase across pieces; unrelated `/Contents`, comments, literal strings, and
  properly length-bounded stream bytes do not become annotation dictionaries.
  Object headers inside strings do not resolve `/Contents`. Duplicate keys,
  unreadable Unicode, invalid text types, unresolved references, actual dictionary
  and string caps, shared expansion/deadline limits, member ordinals, JSON privacy,
  and nonphysical SARIF offsets are checked. Default action lookups retain their
  existing 4 KiB window and behavior.
- **768 identical benign PDF fixtures × three policies × baseline/candidate**:
  2,304 scans per revision; zero verdict, incomplete-reason, or finding changes;
  all clean. These are 96 numbered revision notes in hex/octal/UTF-16/UTF-8,
  with direct and indirect contents. Input hashes and normalized results matched.
  The final source rerun matched the same baseline exactly.
- Six real CLI operations with disposable inbox/rules/home: identical attack bytes
  default → agent-ingest → default exited 0/1/0 and moved to clean/blocked/clean;
  agent-document exited 0/clean; the twin exited 0/clean; malformed UTF-16 exited
  2 and stayed quarantined. The inbox entries moved in every case.
- `probe_rule_coverage.py --verify` on the final scanner source passed: 531 library
  observations, 55 CLI observations, nine benign observations, 85 rules/no skips,
  and required-rule/vendor-skip/deadline failure paths.
- `probe_detection_gaps.py --verify`: 162 satisfied cases; the three #110 hidden
  text cases owned by #182 remain explicitly open on this branch. Removed only
  the annotation marker, following the two RTF removals in the base PR.
- New exact 4 MiB dictionary/string floods return their named incomplete limits
  in 0.115827 s / 0.029308 s, below the unchanged 10 s scan ceiling. They join
  the hosted timing tripwire (now 18 cases); the broad timing matrix was not
  repeated locally.
- Ruff check/format, strict mypy, text-control checking, JavaScript syntax, diff
  whitespace checks, and 11 focused Pages builder tests passed. No workflow changed.

## Demo and native-reader agreement

This branch adds one encoded PDF annotation pair to the RTF base: **45 scenarios,
22 attack/twin pairs, one incomplete scan; 135 policy recordings**. The real
loopback workbench has 15 pairs. The recorder ran on clean source `2e0609d06e37`;
the builder validated the four-file artifact and every twin has zero findings
under all policies. Maintained README, operator/integration/rule/demo docs,
detailed catalog rows/counts, and the source map reflect both readers.

Chrome 157.0.8103.38 / Playwright 1.64.1, November 7 at 10:48 UTC: the real
loopback scanner and built Pages artifact passed the new pair under all three
policies, attack/twin round trips, exit/severity/view labels, 22/22 scoreboard,
empty-submission clearing, and 390-pixel mobile layout. No browser/console errors
or external requests were observed. Local screenshots/JSON retain the original
capture bytes; they are not presented as published screenshots.

macOS PDFKit loaded the two exact demo PDFs as one-page documents with one
annotation each and returned the expected attack/twin text. That independently
checks the UTF-16BE hex fixtures; it is not native viewer UI or broad PDF fidelity
acceptance. The public Pages site remains unchanged until an authorized merge
passes all main deployment gates.

## Open-PR integration trial

#182 at `0fa5098` and #185 at `99940bc` were freshly fetched and remain separate.
In `/private/tmp/yara-reader-combined-20261107`, trial source `b60ac382742b`
combines their hidden-text and Unicode/PDF-folding changes with these two readers.
The trial passed **99 focused tests** and **204 satisfied gap-probe cases, zero
open markers**. Its recorder/builder validated **49 scenarios / 24 pairs / 147
policy recordings**. Strict mypy passed. No trial branch was published or merged
into a delivery branch.

Manual reconciliation was required for documentation, gap markers, timing counts,
recorder entries, demo options/recordings, and `_pdf_text_findings`: keep the
folded page-text pieces from #185 and the hidden-text findings from #182 together.
A merge of these PRs must reconcile those files and regenerate recordings; this
trial is evidence that the combined scanner works, not a claim that GitHub can
merge the branches without conflicts or that #182 has native visibility acceptance.

## Limits

These synthetic corpora do not establish a production false-positive rate.
All annotation definitions, including inactive revisions, are inspected; active
xref reachability and rendering are not fully resolved. Rich text `/RC`, form values,
and unsupported object-stream filters remain outside this reader. RTF's documented
font/layout limits still apply. Broad pytest/selftest and platform coverage are
left to hosted CI. No real malware, vendor-pack accuracy, live consumer integration,
or production upload corpus was exercised.

## Merge onto main

Main `fe985c8` is merged in `0a5ea15`. Annotation pieces use the shared fold helper.
A lengthless image stream with no `endstream` of its own was placed before a hex
annotation. pypdf 7.0.0 read the annotation text. The previous skip jumped to a later
`endstream` and returned no pieces. The skip now stops at the next object header
when that header comes first. `tests/test_pdfannotations.py` covers that file shape.
The Pages baseline at `397adf0` has 49 scenarios. CodeQL did not register on the
push made while the base was still `cx/rtf-reader`. This note is the retarget
commit, so the default setup can analyze a head whose pull request targets `main`.
