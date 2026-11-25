# CJK PDF generator inventory

The B8 decision in [#231](https://github.com/cgfixit/yara-gate/issues/231) depends on
which legacy named CMaps ordinary generators emit. None appeared in 18 synthetic
one-page PDFs or 216 distinct installed documentation PDFs. Defer those tables
until a representative input demonstrates a need.

## Method and results

Draw one ordinary planning label per document, using horizontal text. The four
strings are `季度采购计划`, `季度採購計畫`, `四半期の購入計画`, and `분기 구매 계획`.
Read each page's `/Resources /Font` entries with pypdf. Count each font resource
entry once per page. For each entry record the subtype, its named `/Encoding`, and
whether `/ToUnicode` resolves to a stream. Legacy means a named Type0 encoding
outside the supported predefined Unicode families and the Identity mappings.
Identity maps character codes to same-numbered CIDs. It does not identify a
legacy character encoding.

| Generator on macOS 27.2.1 | PDFs | Font resource entries | Encoding and map evidence |
| --- | ---: | ---: | --- |
| ReportLab 5.1.0, `UnicodeCIDFont` | 6 | 12 | Six simple WinAnsi fonts and six Type0 fonts with predefined Unicode CMaps. The Type0 fonts have no `/ToUnicode`. |
| Quartz through Core Graphics and Core Text, Swift 6.4.2 | 4 | 4 | Two Type1 fonts with maps, and two Type0 `Identity-H` fonts without maps. |
| LibreOfficeDev 26.8.0.0.alpha0, Writer PDF export | 4 | 4 | Two Type1 and two TrueType fonts with maps. |
| Chromium 158.0.8127.37, print to PDF | 4 | 21 | Type3 resources with maps. |

PDFium via pypdfium2 5.15.2 extracted the expected label in all 18 files.
pypdf 7.1.1 agreed in 14. It extracted different text from two Quartz files
and different code points from the Japanese and Korean Chromium exports.
This comparison checked text extraction. The Preview connection failed before
a painted-page inspection.

The installed sample covers PDF files up to 5 MiB in application and system
documentation locations. Of 378 paths, 216 were distinct by SHA-256. pypdf
found 355 distinct page-referenced font objects within those files. Of 35
Type0 objects, 25 had no `/ToUnicode` and all 25 used `Identity-H`.
The sample is limited to the installed documents and generator paths described here.
Export settings, other platforms, and intentional legacy encoding selections
can produce other outputs.

## Reproduce

- ReportLab: use `Canvas(..., invariant=True)`, register each face via
  `UnicodeCIDFont`, set it to 18 points, and draw the corresponding label at
  (72, 690). Use STSong-Light, MSung-Light, HeiseiMin-W3, HeiseiKakuGo-W5,
  HYSMyeongJo-Medium, and HYGothic-Medium respectively for the four languages.
- Quartz: make a 612 × 792 point PDF context, use `CTFontCreateWithName` at
  18 points, and draw a `CTLine` at (72, 690). Use PingFang SC, PingFang TC,
  Hiragino Sans, and Apple SD Gothic Neo with the respective Core Text language
  tags `zh-Hans`, `zh-Hant`, `ja`, and `ko`.
- For both HTML exports, put one label in a UTF-8 HTML paragraph with the same
  font family and language tag. Run Chrome with `--headless`,
  `--print-to-pdf=OUTPUT.pdf`, `--no-pdf-header-footer`, an isolated profile,
  and a local `file://` URL. For LibreOffice use `soffice --headless --convert-to pdf:writer_pdf_Export`
  with a disposable profile. Use a disposable fontconfig file that includes
  `/System/Library/Fonts` and `/System/Library/Fonts/Supplemental` and sets a
  writable cache. The initial headless export's font fallback did not reproduce
  the labels. The four corrected exports did.

## Scanner comparison

On `a6e8143`, 14 files were clean under the document policy, and two Quartz
files with unmapped fonts had a note. Two other Quartz files were incomplete
with `pdf xref malformed`. The combined `f5ab58f` and `ae265f6` tree gave
identical verdicts and findings for all 18 PDFs under all three policies.

Both incomplete Quartz files have an invalid cross-reference row. A pypdf
rewrite retained the extracted labels and scanned clean. The separate
[Quartz issue](https://github.com/cgfixit/yara-gate/issues/317) tracks that
compatibility finding. It does not provide evidence for shipping a legacy CMap.

## Quartz cross-reference follow-up

On 2026-11-24, two runs of the Quartz recipe above on macOS 27.2.1
(build 26B131) and Swift 6.4.2 produced the same failure for PingFang SC and
PingFang TC. Each PDF 1.3 export had a classic cross-reference entry marking
object 6, generation 0, in use at byte 0. Byte 0 begins the PDF header,
and no matching object header appeared elsewhere. The Japanese, Korean,
and an additional English Helvetica export had no such row.
[ISO 32000-1 §7.5.4](https://udp.adobe.io/document-services/docs/assets/35e4369068f86065372c18787171a17e/PDF_ISO_32000-1.pdf)
defines the in-use offset as the position of the indirect object's beginning.

PDFium (pypdfium2 5.15.2) and pypdf 7.1.1 extracted the intended simplified
and traditional Chinese labels from the originals. Default pypdf discarded
the bad row with a warning. Preview painted both expected labels. A pypdf
`PdfWriter(clone_from=reader)` rewrite to a separate file removed the bad
row and preserved the expected text in both extraction libraries. For
Japanese and Korean, PDFium extracted the intended labels and pypdf returned
different code points.

On `e278c53a22dc8f329b02fdfc3119ecce37124a6b`, the locked Python 3.12.13
environment used YARA-X 1.24.0 with all 89 bundled rules and zero rule files
skipped. `scan_file` and `yara-gate scan --json --policy agent-document` on
disposable homes and rules agreed on verdict, reason, and SHA-256. Each CLI
case checked the stored JSON report and the location of the identical bytes.

| Input | Result under `agent-document` | Inbox disposition |
| --- | --- | --- |
| Raw simplified and traditional Chinese exports, both runs | Incomplete, exit 2, `pdf xref malformed` | Quarantine |
| Both pypdf rewrites | Clean, exit 0, no findings | Clean |
| English Quartz export | Clean, exit 0, no findings | Clean |
| Japanese and Korean Quartz exports | Advisory, exit 0, `heuristic_pdf_text_unmapped` note | Clean |
| Malformed `startxref` control | Incomplete, exit 2, `pdf xref malformed` | Quarantine |
| Valid incremental fixture from `tests/test_pdfxref.py` | Advisory, exit 0, annotation finding | Clean |
| Existing classic, Flate, predictor, hybrid, and incremental stream-offset fixtures | Incomplete, exit 2, `pdf annotation xref offset inside stream` | Quarantine |

The live loopback workbench labels the built-in merged-PDF finding advisory
with exit 0 under `agent-document` and block with exit 1 under
`agent-ingest`. Its benign twin is clean under both policies, and the
unsupported-archive example displays incomplete with exit 2. The workbench
runs catalog PDFs. The original Quartz files and rewrites went through the
file-scanning CLI and library.

Recovery by these readers establishes that the two pages remain readable.
It gives no evidence that a general exception for zero-offset in-use entries
would account for every object a reader might recover. Preserve the
fail-closed check and [rescan a trusted replacement](../../user-guide.md#quartz-pdfs-with-malformed-cross-references).
The prevalence of the malformed row in other Quartz exports is unknown.

### Scanning the original Quartz exports

The follow-up for [#317](https://github.com/cgfixit/yara-gate/issues/317)
validates the observed PDF 1.3 layout before treating one in-use row at
offset zero as an unused slot. It requires a single classic table and
exact agreement with the remaining object headers. The layout pass must
account for every reference and find no definition for that object.
The native scanner then continues on the original bytes with the existing
file-wide font reading.

Both original exports and both repeated exports scanned clean with exit 0
under all three policies in an installed candidate wheel. Each reported a
`pdf-text` view, no findings, and the SHA-256 of the original bytes. The
bad-pointer control and five stream-offset controls still exited 2 and
stayed in quarantine under all three policies. The prior rewrite, ordinary
Quartz, and valid incremental results stayed consistent with each policy.
The CLI and library agreed on all 48 observations. The CLI check also
compared the JSON on disk and the SHA-256 of the bytes at their final
destination.

Python 3.12.13, YARA-X 1.24.0, 89 bundled rules, zero skipped. Candidate
detector SHA-256 `21db8ce0601b0896af7039d2908cbcc8f9b728c8d346d200177f30691ec66748`.
The xref regressions passed 49 cases. The bundled conformance kit passed
282 checks with no changed verdicts or findings. The page-map agreement
probe had zero narrowing misses against PDFium and pypdf in 141 fixtures
and 532 cases selected from 15,000 fuzz mutations. The packaged loopback
workbench displayed the expected merged PDF pair and incomplete archive
result with the same detector identity. The file CLI and library scanned
the actual Quartz exports.
