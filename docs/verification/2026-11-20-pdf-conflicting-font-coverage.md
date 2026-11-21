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
