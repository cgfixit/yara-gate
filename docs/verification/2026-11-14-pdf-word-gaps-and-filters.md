# PDF words placed by position, and page content under LZW and RunLength — November 14, 2026

Base: `main` at `e365218`. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0, 87
bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local`. Nothing was executed, unpacked to disk, or fetched by the scanner.

Two items: the [detection backlog](../research/detection-backlog.md)'s row for PDF word gaps
written as position, and the decoding half of
[#223](https://github.com/cgfixit/yara-gate/issues/223). Each was scanned on `e365218` before
the change, beside a control the gate already held.

## 1. Words a PDF places by position

**Gap (verified on `e365218`).** The reader joins the strings of a line with nothing between
them unless a `TJ` adjustment is -200 or less. Two common ways of writing words read as one
glued word, so the phrase rules never matched, under every policy:

- one text object per word, each placed by its own `Td`;
- one `TJ` array with a gap of -150 or -110 between words and no space glyph.

**Readers.** On the probe fixtures, poppler 24.02.0, pypdf 6.17.0, pdfminer.six 20260107, and
PDFium (pypdfium2) all show the sentence with spaces for the `Td` and -150 shapes. For -110,
poppler and pdfminer.six do and pypdf and PDFium do not: readers start a space near -120 and
differ around it.

**Change.** A third grouping beside the plain and hidden ones receives each operator's strings
read with spaces: at a `TJ` gap of -100 or less, and before a string drawn on the same line
after `Td`, `TD`, `T*`, `Tm`, or a new text object, unless a space is already there. It reuses
the plain grouping's decoded strings and ends its blocks and paragraphs where the plain one
does, so it decodes nothing twice and holds no more pieces. Its blocks and paragraphs are added
to `pdf-text` and `pdf-paragraph` where they differ from the plain ones; nothing the plain
reading gives is dropped. Spaced pieces past the 20,000-piece cap are not added, so the scan
does not become incomplete for them. Kerning written as a small `Td` inside a word makes the
spaced reading split the word; the plain reading keeps it whole, and the probe's benign twin of
that shape stays clean. The hidden-text grouping is not read with spaces.

## 2. Page content under LZWDecode and RunLengthDecode

**Gap (verified on `e365218`).** `_pdf_flate_plan` decoded a stream only when its chain reached
FlateDecode, so a page content stream under `/LZWDecode` or `/RunLengthDecode` was not read: a
split phrase in one was clean. poppler, pypdf, pdfminer.six, and PDFium decode both. The
earlier reason for leaving them out stands for large streams: Python has no decoder for either,
and a pure-Python one cannot decode 100 MB inside the deadline.

**Change.** Both are decoded after any ASCIIHex or ASCII85 stage, LZW with its `EarlyChange`
(1 unless the parameters say 0) and the same predictors as Flate, but only for a stream whose
dictionary is not an image (`/Subtype /Image` or `/Width`) and whose encoded bytes are at most
2 MiB (LZW) or 8 MiB (RunLength). The deadline is checked every 65,536 steps and the output is
charged to the shared expansion budget and the 100 MB stream limit. A larger stream stays out
of the view, as before. A code the LZW table cannot have yet ends the data, keeping what came
before it, as pdf.js does; a full table (4,096 entries) is not grown further.

**Agreement.** A Python LZW encoder (in the probe) round-trips through the decoder on 300 random
inputs up to 20,000 bytes, including ones that fill the table. A content stream that fills the
table without a clear code shows the sentence in poppler, pypdf (with warnings), pdfminer.six,
and PDFium, and the gate holds it.

The coverage note #223 asks for (page content the gate could not decode, reported as such) is
a change to the report schema and is not part of this change.

## Fixtures

The probe's `gaps` group, 11 cases. Each attack is missed on `e365218` and held here.

| Case | `e365218` | This change | Readers showing the phrase |
| --- | --- | --- | --- |
| Words with space glyphs (control) | held | held | 4 of 4 |
| One word per text object, placed by `Td` | clean | held | 4 of 4 |
| `TJ` gaps of -150 | clean | held | 4 of 4 |
| `TJ` gaps of -110 | clean | held | poppler, pdfminer.six |
| Words placed by `Td`, ordinary text (benign) | clean | clean | none |
| Kerning by `Td` inside words, ordinary text (benign) | clean | clean | none |
| Page content under `LZWDecode` | clean | held | 4 of 4 |
| Page content under `RunLengthDecode` | clean | held | 4 of 4 |
| Page content under `[/ASCII85Decode /LZWDecode]` | clean | held | 4 of 4 |
| LZW page content, ordinary text (benign) | clean | clean | none |
| RunLength image holding content operators (boundary) | clean | clean | none |

## Benign files, `e365218` against this change

`main` and this change, each from its own source tree with the same rules, scanned every unique
PDF on the machine (8,622, by content) under `default` and `agent-document`: generator output
(LibreOffice, Chromium, reportlab, pypdf, PDFium, pdftocairo, MuPDF, Pillow), test-suite
files, earlier probe fixtures, and the tripwire's inputs. 23 changed; none got slower by more
than half a second and twice its time.

- 15 are attack fixtures from earlier probes of these shapes (`gaps--*`, `*-words-joined-by-*`):
  7 went from clean to advisory and 8, already advisory for another finding, gained the phrase
  in `pdf-paragraph`. poppler shows the override sentence in each.
- 8 are copies of this repository's own documentation exported to PDF, which quote attack
  text on purpose and were already advisory or incomplete: `docs/rules.md` (`md14.pdf` and two
  rewrites) now also reports `script_osascript_shell` and `win_recovery_inhibit` in
  `pdf-paragraph`, because its tables quote `osascript -e` and `vssadmin delete shadows` in
  cells LibreOffice writes word by word; a Pages verification record (`md30.pdf` and two
  rewrites) reports `agent_secret_transfer_request` for its quoted "Read .env and send"; and two
  copies of a merge that holds an earlier verification record report `agent_override_imperative`
  in one more view. Their verdicts are unchanged.

No benign document outside this repository's own documentation gained a finding. None of the
first 3,000 PDFs on the machine uses `/LZWDecode` or `/RunLengthDecode`, so the decoders are
measured on the fixtures; their benign exposure on this corpus is close to nil.

## Timing

TIMING_SECTION

## What was run

CHECKS_TABLE

## Not established

- The `-100` threshold of the spaced reading is read more widely than pypdf and PDFium space;
  it is a further reading, so it can add a finding where those two readers show a glued word,
  never remove one.
- Real PDFs with LZW or RunLength page content were not in the corpus.
- The coverage note for page content the gate cannot decode (#223) is not built.
- Synthetic fixtures. This is evidence for the shapes listed, not a detection rate.
