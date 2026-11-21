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
