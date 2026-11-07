# Reader-pair demo refresh

Base: main at `a6c0444`. Demo source and recording: `34c40f1`.
Python 3.12.12 and locked YARA-X 1.23.0 on macOS arm64, with 85 bundled
rules, zero skips on complete cases, and no vendor packs.

| Pair | Derived view | Attack under agent-ingest | Benign twin under all policies |
| --- | --- | --- | --- |
| SVG label split across CDATA and a span | `html-text` | Block, exit 1, note finding | Clean, no findings |
| Excel comment split into rich-text runs | `ooxml-comment` | Block, exit 1, note finding | Clean, no findings |
| Latin small-capital message | `text-folded` | Block, exit 1, note finding | Clean, no findings |

Each attack reports advisory/exit 0 under default and agent-document; its
finding remains a note. The recorder validated 41 scenarios and 123 policy
results. All 35 previous case records matched the previous baseline exactly.
A second recording matched the new reviewed baseline. The Pages builder
emitted its four allowlisted files and the generated JavaScript parsed.

In the in-app browser, the real loopback workbench held the SVG example
under agent-ingest, scanned its twin clean using **Scan paired example**,
then reported the original note without a hold under agent-document.
The built Pages preview displayed 20/20 attacks held and 20/20 twins clean.
Selecting the Excel pair showed `ooxml-comment` provenance for the attack
and no findings for the twin. This was a loopback preview, not a deployment.

The separate 324-file generated corpus passed its existing precision gate:
zero incomplete, 81 of 85 rules with no hits, and the four documented
Windows shortcut collisions at one file each. These are curated and
generated inputs, not an estimate of a production false-positive rate.

Review before merge corrected the Pages explanations for `ooxml-comment`,
SVG `html-text`, and small capitals in `text-folded`; the findings and decisions
did not change. The existing HTTP showcase regression now covers all 13
workbench pairs and passed, including exact attack rule/view provenance and
clean twins under all three policies. Re-recording all 123 results matched
the baseline. The Pages build, module syntax, Ruff on the changed test, and
tracked-text control check passed.

Browser review of this correction used the real workbench to scan the Excel
attack, switch to its clean twin, and switch back under document policy;
the paired control preserved the selected policy. The built Pages preview
rendered the corrected Excel and SVG explanations. Deployment verification
is separate from these local checks.
