# RTF reader verification — November 7, 2026

Base: `05f94caaf596413a2011612821f3d7d2916e3e16`. Exercised scanner and demo
source: `b7d679990367`; the following evidence commit changes only this record
and the recorded Pages results. A later documentation-only follow-up also
corrects the detailed catalog counts/table and adds the reader to the source map. macOS 27.2 arm64, Python 3.12.12, YARA-X 1.23.0,
85 bundled rules, zero skips, no vendor download. Ruleset SHA-256:
`4517a40579c9522edb8ad94babfee8cb338a4aded9fdb62d94f90133b3e35985`.

## Reproduced gap and change

On the base, both #171.4 cases in `probe_detection_gaps.py` were clean with no
findings under all three policies: bold formatting inside the override phrase,
and a hex-escaped initial letter. The bounded `rtf-text` reader now recovers
these paragraphs and supplies them, and any folded spelling, to existing rules.
No YARA rule, severity, intake, or policy code changed. The phrase remains a note:
default and `agent-document` are advisory/exit 0; `agent-ingest` blocks/exit 1.
Malformed supported RTF is incomplete/exit 2.

Reader behavior follows Microsoft's [RTF syntax](https://learn.microsoft.com/en-us/previous-versions/office/developer/office2000/aa140284(v=office.10))
and [file-content rules](https://learn.microsoft.com/en-us/previous-versions/office/developer/office2000/aa140298(v=office.10)),
consulted November 7. Group formatting is scoped, unknown starred destinations
are skipped, and a separate text story is not joined into the body. Hex bytes,
Unicode escapes/fallbacks, font codepages, and binary lengths are interpreted as
data. Pictures, objects, and field instructions are never executed or fetched.
[Reader limits](../rules.md#rtf-reader-boundaries) describe the supported subset.

## Direct and focused verification

- `pytest -q tests/test_rtftext.py`: 30 passed. Nine attack/twin shapes under all
  three policies, paragraph/cell/story separation, ignored destinations, field
  results, Unicode alternatives, surrogate pairs, codepage/font scope, malformed
  input, actual 128-depth and 100,000-piece caps, deadline, archive ordinals, and
  JSON/SARIF privacy/provenance. No derived offset becomes an outer-file region.
- Baseline/candidate comparison: 576 identical benign RTF files (96 numbered
  revision notes in plain, bold, all-hex, all-Unicode, font-table, and paragraph
  forms), each under all three policies: **1,728 scans per revision**, all clean
  with no findings or incomplete reasons, with identical input hashes/results.
- Five inert files converted using macOS `/usr/bin/textutil -convert txt -stdin
  -stdout`: bold, hex, Unicode fallback, emoji surrogate pair, and CP1251 prose
  all agreed with extracted RTF text. This is converter agreement, not Word or
  native viewer acceptance.
- Six actual CLI intake operations with disposable rules/home: identical attack
  bytes resubmitted default → agent-ingest → default exited 0/1/0 and went to
  clean/blocked/clean; agent-document exited 0/clean; benign twin exited 0/clean;
  invalid binary length exited 2 and stayed in quarantine. Inbox entries moved.
- `python docs/research/probe_rule_coverage.py --verify`: passed, 531 library
  observations, 55 CLI observations, nine benign observations, 85 rules/no skips,
  required-rule failure, vendor-skip, and deadline paths verified.
- `python docs/research/probe_detection_gaps.py --verify`: 161 satisfied cases,
  four explicitly open cases (encoded PDF annotation plus the three #110 hidden
  text cases owned by #182). Removed only the two now-fixed RTF markers.
- The existing exact 4 MiB `rtf-controls.rtf` timing case completed in 0.273364 s
  with `rtf group depth exceeds 128`. Its prior clean expectation predated the
  reader; the tripwire now requires the explicit limit reason.
- Ruff check/format, strict mypy on `src`, text-control checking, JavaScript
  syntax, and diff whitespace checks passed. No workflow changed.

## Demo accuracy and browser acceptance

The fetched public Pages recording was already at main `05f94ca`, with 20
attacks detected/held by agent-ingest and 20 clean twins. Those are fixed examples,
not 20 remaining bypasses. The UI now states that explicitly and distinguishes
policy decisions from whether a rule matched. This branch adds the RTF pair:
**43 scenarios, 21 pairs, one incomplete scan; 129 policy recordings**.
The live workbench has 14 pairs. All recorded twins have no findings under all
policies. `record_pages_demo.py` recorded the clean source revision above;
`build_pages.py` validated the four-file artifact; 11 focused builder tests passed.

Chrome 157.0.8103.38 driven with Playwright 1.64.1 exercised the real loopback
scanner and built Pages artifact on November 7 at 10:35 UTC. For the new pair,
all three policies, attack/twin round trips, actual exit/severity/view labels,
21/21 scoreboard counts, empty submission clearing, and 390-pixel mobile layout
passed. No browser or console errors or external requests were observed. Original
captures and the JSON acceptance report are retained in the task's local evidence
directory, not represented as published screenshots. The public site changes
only after an authorized merge and green main deployment gates.

## Scope and open work

#182 (`0fa5098`) owns hidden Office/PDF text; #185 (`99940bc`) owns uppercase
Cyrillic and folded PDF glyph text. Neither is incorporated or merged here.
Their demo counts/recordings and shared documentation need reconciliation when
combined. Encoded PDF annotation contents are the next focused draft.

Synthetic results establish these cases, not a production false-positive rate
or comprehensive prompt-injection defense. Symbol-font glyphs, image/object
text, layout/visibility, and legacy default-language charset inference remain
outside this reader. Unsupported declared fonts/encodings become incomplete.
Broad pytest/selftest and non-macOS coverage are delegated to hosted CI; no real
malware, vendor packs, or authenticated consumer integration was exercised.
