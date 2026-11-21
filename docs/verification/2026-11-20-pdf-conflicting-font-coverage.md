# Coverage for conflicting PDF font declarations

Base `a6e8143`, [#231](https://github.com/cgfixit/yara-gate/issues/231). An unreadable selected
font can inherit a map candidate from the bytes after its object header. If that map belongs to
the next font, a PDF with no usable map in the selected font can scan clean. Some viewers
recover text in these cases and others do something different. The scanner now retains the
existing unmapped-text coverage note for the three shapes in the [rules guide](../rules.md#pdf-font-coverage).
It keeps the existing candidate readings.

| Check | Evidence |
| --- | --- |
| Packaged CLI | Three synthetic planning PDFs with conflicting declarations gave a single `heuristic_pdf_text_unmapped` note each. `agent-document` returned advisory/0 and `agent-ingest` returned block/1. The plain-font control gave clean/0 with no findings under both policies. |
| PDF-focused tests | All 43 selected font and map tests passed. The three new cases reproduced the missing note on the base. |
| Directed reader agreement | 107 cases with PDFium, pdfminer.six, and pypdf. Both existing cases with a conflicting font next to a map changed from no coverage to unmapped. No reading was lost. |
| Reader-agreement fuzz | 14,997 generated documents from 15,000 attempts, seed 1. 216 were checked against the readers, with zero narrowing misses and eight existing gaps. |
| Installed PDF sweep | 378 paths, 216 distinct PDFs, up to 5 MiB each. No verdict, finding severity, view, offset, or length changed across `default` and `agent-document`. |
| Timing | A 4,194,288-byte synthetic PDF completed in 0.32–0.40 s on the base and 0.41–0.47 s on the candidate across three scans per build. The intended coverage note appeared on the candidate. |
| Packaged conformance | 92 fixtures and 276 policy checks. No verdicts or findings changed. |
| Live browser | The workbench from the fresh wheel matched all 90 reviewed outcomes under `agent-document`. It showed zero findings on the 44 benign twins and two incomplete verdicts for the unreadable fixtures. |

The locked scan ran on macOS with Python 3.12.13, YARA-X 1.23.0, and 89 bundled rules.
The reader comparison used pypdfium2 5.15.2, pdfminer.six 20260107, and pypdf 7.1.1.
These checks cover the measured corpus. They cannot rule out a legitimate malformed PDF
receiving the same coverage note and being held by the existing agent intake policy.

## Other direct values and null controls

[ISO 32000-1](https://udp.adobe.io/document-services/docs/assets/35e4369068f86065372c18787171a17e/PDF_ISO_32000-1.pdf)
requires an indirect reference to the CMap stream (sections 7.3.8 and 9.10.3).
A null dictionary value is equivalent to omission (section 7.3.9). Both
dictionary readers now keep that distinction when describing an unresolved
composite font. A missing or null descendant entry no longer relies on the
presence of an explicit Latin encoding to preserve the note. Readable map
candidates remain available.

On the same toolchain, the direct CLI returned advisory/0 under
`agent-document` and block/1 under `agent-ingest` for the six non-null
wrong-type values and one null descendant case. Both policies gave clean/0
for the null-map and omitted-map controls beside the existing candidate.
Eleven focused cases reproduced the missing note on `6dec7ef`. The final
candidate passed 106 selected font and dictionary tests.

The 107-case directed reader comparison stayed unchanged from the previous
draft. From 15,000 fuzz attempts, 14,997 documents were generated and 216
were checked by the reference readers. There were zero narrowing misses.
The 216 installed PDFs and the 18 generated CJK PDFs retained their verdicts
and findings under the policies previously measured. A 4 MiB timing fixture
completed in 0.32–0.38 s on the earlier draft and 0.37–0.42 s with this change.
The final wheel passed 276 conformance checks with identical outcomes. The
live browser showed block/1 and clean/0 for the bundled merged-PDF pair.
