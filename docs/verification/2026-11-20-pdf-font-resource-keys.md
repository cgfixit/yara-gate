# Escaped PDF font resource keys

This covers one reader-agreement item in [#231](https://github.com/cgfixit/yara-gate/issues/231).
On `a6e8143`, the file-wide font lookup recognized the literal `/Font` key and skipped its
equivalent PDF name escapes. The same onboarding PDF reconstructed ordinary text with a plain
key and different text with an escaped key. The existing reader probe independently confirmed
the gap in PDFium and pdfminer.six.

Both direct and indirect font resource lookups now recognize the same escaped spelling.
The page-specific map still falls back to the file-wide lookup when the resource key is escaped.
Permissive readings of malformed references and the remaining B3, B5, and B8 cases stay tracked
in [the backlog](../research/detection-backlog.md).

Verified on macOS with Python 3.12.13, YARA-X 1.23.0, PDFium via pypdfium2 5.15.2,
pdfminer.six 20260107, and pypdf 7.1.1. The scanner used 89 bundled rules in a disposable
rules directory with no vendor packs.

| Check | Result |
| --- | --- |
| Focused PDF text test | Plain, partly escaped, and fully escaped keys reconstruct identical text through direct and indirect dictionaries. Four parameterized cases pass. |
| Page reader agreement | 141 directed cases. The escaped-key case moved from absent to decoded in both the file-wide and page-aware readings. Nine pre-existing gaps remain and no case lost a reading supported by a reference reader. |
| Font reader agreement | 107 directed cases and their outcomes are unchanged. Existing probe fuzz passes used 15,000 inputs per probe and reported zero narrowing misses. |
| Installed PDF sweep | 378 paths, 216 distinct file digests, from installed app and system documentation PDFs up to 5 MiB. The candidate and base give the same verdicts and findings, including offsets, under `default` and `agent-document`. |
| Timing | A 4 MiB inert PDF with repeated near-match names stayed clean under `agent-document`. Three scans took 0.90–1.08 s on the base and 0.91–0.97 s on the candidate. |
| Packaged browser demo | The in-app browser ran the bundled glyph PDF pair from the wheel. Under `agent-ingest` the fixture held with exit 1 and a PDF paragraph finding. The benign twin was clean with exit 0 and no findings. |

The installed files and fixtures establish the behavior of this change on those inputs.
The live workbench uses its bundled pair. The focused reader tests exercise the new key spellings.

## Coverage for disputed resource references

The follow-up preserves existing font readings and adds the unmapped coverage note
when a selected name has a measured reference that readers recover differently.
The note also applies when an ordinary reference for that name exists elsewhere.
The key must occur as a PDF token. Text strings and comments that print resource
examples do not count.

On the same Mac toolchain, eighteen new cases for nine recovery spellings across
direct and indirect dictionaries reproduced the missing note on `e483328` and
pass with this change. A quoted example and an unused name stay clean. The
packaged CLI checked eight affected documents and three controls with rebuilt
cross-reference tables. Under `agent-document`, each affected document returned
advisory/0 with only the unmapped note, and the controls returned clean/0.

The 141 directed reader cases now include nine that report unmapped text where
they previously reported nothing. This establishes coverage reporting for those
references. Their exact glyph decoding remains reader dependent. The 15,000-input
page-map fuzz pass observed zero narrowing misses. The 216-PDF sweep showed no
changed verdicts or findings. A 4,194,298-byte inert comment holding repeated
reference examples stayed clean. Three scans took 1.09–1.17 s on the prior draft
and 1.14–1.22 s with the follow-up.

The wheel passed all 276 conformance checks with no changed findings or verdicts.
In the live browser, the built-in plain-font pair showed block/1 for the
instruction and clean/0 for the ordinary revision note under `agent-ingest`.
