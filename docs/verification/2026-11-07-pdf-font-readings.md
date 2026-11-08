# PDF font readings past the cap — November 7, 2026

Base: branch `claude/sweet-tesla-ubj0gd` at `23e47a8` (Read overflowing ToUnicode bfrange
destinations both ways), whose parent is main `43aba2e` (#189). The defect was reproduced on
both. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0, 85 bundled local rules,
zero skips, no vendor download. Ruleset SHA-256
`4517a40579c9522edb8ad94babfee8cb338a4aded9fdb62d94f90133b3e35985`. Every scan used a
disposable copy of `rules/local` and `rules/rules.lock`. Every CLI scan used a disposable
home.

## Defect

`_fonts` in `src/yara_gate/pdftext.py` maps a font resource name to every distinct font it
names anywhere in the file, up to 64 references, because the reader does not resolve a
content stream's page resources. `_Paragraphs.show` decodes each string through
`variants[:MAX_FONT_VARIANTS]` (4). Text that only a fifth font decodes was never scanned,
and nothing reported it. References past 64 were dropped the same way. Since `23e47a8`, an
overflowing `bfrange` can give a font a second, carried reading, ordered after every font's
first. A name with four fonts therefore lost the carried reading without a report.

Fixtures come from `yara_gate.samples.merged_pdf`. Each page's `/F1` is its own Type0 font
with its own ToUnicode map, and every page shows `_PDF_PHRASE` from
`docs/verification/check_added_rules.py` as glyph ids. Only font *n* maps those ids to the
phrase. The other fonts map each id *k* printable characters along. `fonts-3-carried.pdf`
has three decoy fonts, then one font whose phrase reading is the carried one.

| Fixture | main `43aba2e` | base `23e47a8` | this change |
| --- | --- | --- | --- |
| `fonts-4-last.pdf` (4 fonts, phrase in 4th) | advisory, `agent_override_imperative` | same | same |
| `fonts-5-last.pdf` (phrase in 5th) | **clean** | **clean** | advisory, `heuristic_pdf_text_unmapped` |
| `fonts-8-last.pdf` (phrase in 8th) | **clean** | **clean** | advisory, `heuristic_pdf_text_unmapped` |
| `fonts-2-carried.pdf` (4 readings) | incomplete, `content scan failed` | advisory, `agent_override_imperative` | same as base |
| `fonts-3-carried.pdf` (5 readings) | incomplete, `content scan failed` | **clean** | advisory, `heuristic_pdf_text_unmapped` |
| `fonts-4-plain.pdf` (benign) | clean | clean | clean |
| `fonts-5-plain.pdf` (benign) | clean | clean | advisory, `heuristic_pdf_text_unmapped` |

The table shows the default policy. `agent_override_imperative` is a note rule, so a
note-only result is `advisory` with exit 0. CLI with an inbox copy
(`yara-gate scan <inbox file> --home … --rules … --policy …`):

| Fixture | main and base | this change |
| --- | --- | --- |
| `fonts-5-last.pdf`, default | 0, filed clean | 0, filed clean, note recorded |
| `fonts-5-last.pdf`, agent-ingest | **0, filed clean** | 1, filed blocked |
| `fonts-5-last.pdf`, agent-document | 0, filed clean | 0, filed clean, note recorded |
| `fonts-4-last.pdf`, agent-ingest | 1, filed blocked | 1, filed blocked |

SHA-256 of the fixtures: `fonts-5-last.pdf` `a4133f51…7b97`, `fonts-8-last.pdf`
`38faa1d0…e29c`, `fonts-3-carried.pdf` `0fa8e760…7eca`, `fonts-5-plain.pdf`
`c497f24e…6409`. All are rebuilt deterministically by `font_reading_cases()`.

## Choosing the signal

The shipped precision corpus (324 files) contains no PDF with more than one font, so it
cannot decide this alone. Benign files that reuse names were generated in this container:

- 12 Chromium 153.0.8010.12 `page.pdf()` exports of multi-font, multi-page HTML.
- 8 LibreOffice 24.2.7.2 exports of the same text through pandoc DOCX.
- 8 merges of those made with pypdf 5.1.0 (`PdfWriter.append`, which keeps each page's
  resource names), in a throwaway environment.
- The one third-party PDF on disk, `theme-showcase.pdf`.

The reader was instrumented to record how many readings each text operator's name had.

| Files | Most readings per name | Operators over 4 |
| --- | --- | --- |
| 12 Chromium, 8 LibreOffice, 1 third-party | 1 | 0 |
| merges of 2 and 4 Chromium files | 2, 4 | 0 |
| merges of 5 Chromium, 5 LibreOffice, 3+3 mixed | 5, 5, 6 | 4,427 of 5,507; 4,052 of 4,052; 2,949 of 5,546 |
| merges of 8 LibreOffice, 12 Chromium, 20 mixed | 8, 12, 20 | almost all |

A single generator never exceeded one reading per name, but every merge of five or more
sources did. Merges of 8 or more were already `incomplete` (`pdf text blocks exceed 20000`)
on main and on this change: each reading emits its own blocks.

Outcomes on the real files, by policy (default / agent-ingest / agent-document):

| File | main and base | this change |
| --- | --- | --- |
| `merge-lo-5.pdf` | clean / clean / clean | advisory / **block** / advisory (`heuristic_pdf_text_unmapped`) |
| `merge-chrome-5.pdf`, `merge-mixed-6.pdf` | advisory / block / block | unchanged, note added |
| every other file | unchanged | unchanged |

Decision: report the cap as `result.unmapped`, the `heuristic_pdf_text_unmapped` note, when
a string with any bytes is shown in a name that has more than four readings. Report it the
same way when a name's references pass 64: an unresolved composite font stands in for them.

- **Dedicated incomplete reason** (`pdf font readings exceed 4`): rejected. Every benign
  merge of 5 to 7 sources would exit 2 and stay quarantined under every policy, including
  the default. `measure_precision.py --fail-over` fails on any benign incomplete, so the gate
  could not hold a realistic merged file.
- **Raise the cap**: rejected. Each reading emits its own blocks, so a higher cap moves
  benign merges onto the 20,000-block limit (incomplete) sooner. It also multiplies the
  per-string decode cost.
- **Report only when a reading past the cap decodes differently**: rejected. Merged
  Chromium and LibreOffice subsets map the same ids to different characters, so their
  readings differ and the note would fire anyway. Paragraph variants also mix readings by
  index across names, so per-string equality does not prove that nothing was lost. It also
  adds decode work an attacker can multiply.

The note's existing meaning is "some shown text was not decoded". Under `agent-ingest` it
holds the file. Under `agent-document` it is recorded and the file passes, the same as a
composite font with no map.

## Change

- `MAX_FONT_REFERENCES = 64` names the reference cap. A name that has more distinct
  references gets an unresolved composite `Font` appended, which `show` already reports.
- `_Paragraphs.show` sets `unmapped` when `len(fonts) > MAX_FONT_VARIANTS` and a string has
  bytes. Second readings still come last, so the carried reading counts toward the cap.
- `show` remembers whether the last font list had an unreadable font. Before, it rescanned
  every font of the name on every string. On the new 4 MiB tripwire input (64 fonts under
  one name), the scan dropped from 6.8–7.1 s on base to 4.7–5.1 s.
- Fixtures: `samples.shared_name_pdf` and `samples.merged_pdf`. Cases:
  `check_added_rules.font_reading_cases()` (7), five `fonts` cases in
  `docs/research/probe_detection_gaps.py`, `pdf/merged-4-fonts.pdf` and
  `pdf/merged-5-fonts.pdf` in the precision corpus, `pdf-font-readings.pdf` in
  `check_worst_case_timing.py`, and four tests in `tests/test_pdftext.py`.

## Commands and results (this container)

- `uv run pytest -q tests/test_pdftext.py tests/test_pdf_text_folding.py`: 41 passed.
  With `pdftext.py` from `23e47a8`, three of the new tests fail: the reading cap, the
  carried reading past the cap, and the reference cap. The fourth new test is a boundary:
  an empty string under an over-cap name is not unmapped. A broader focused run
  (`tests/test_worst_case_timing.py tests/test_scanner.py -k "pdf or font or timing or sample"`
  plus the two files above): 58 passed.
- `docs/verification/check_added_rules.py`: passed, 191 cases plus 4 vendor-override cases.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 209 `ok`, no FAIL, STALE, or
  open cases. CLI agent-ingest intake filed every case as blocked.
- `docs/research/probe_rule_coverage.py --verify`: exit 0, with 531 library, 55 CLI, and 9
  benign observations, no compile skips, and no failures.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 326 benign files, zero
  incomplete. `heuristic_pdf_text_unmapped` hits 1 file (0.31%, `pdf/merged-5-fonts.pdf`).
  `pdf/merged-4-fonts.pdf` is clean. The other hits are the four tagged Windows files at
  0.31% each, as before.
- `docs/verification/check_worst_case_timing.py`: PASS, 25 inputs of exactly 4 MiB.
  `pdf-font-readings.pdf` took 4.72 s, advisory, with 28 `pdf-text` pieces, and it now
  requires that view. The slowest input was `pdf-page-objects.pdf` at 6.59 s.
- `docs/verification/check_rule_pairs.py`: passed (115 rules).
- `ruff check .`, `ruff format --check .`, `mypy --strict src` (20 files), and
  `check_text_controls.py` (277 files): clean.

## Residual risks and boundaries

- **agent-document passes it.** A phrase that only a fifth font decodes is reported, not
  read. Under `agent-document` the note is recorded and the file passes to the agent, as
  for any unmapped text. Gate an extractor's own output as well.
- **Benign merges pay the note.** Under `agent-ingest`, every merge of five or more sources
  that reuse a name is held. That is one new hold in the sample above
  (`merge-lo-5.pdf`); the other merges were already held or incomplete.
- **Root cause stays.** The reader resolves names file-wide, not per page. Resolving
  each content stream's page `/Resources` would read exactly one font per string, remove
  this note on merges, and keep merges of 8 or more sources under the block limit. That is
  a separate change.
- **Cross-name mixing.** Paragraph variants combine readings by index across names. A
  phrase split between two names that both have several readings can still be assembled
  in no variant. This is pre-existing and unchanged.
- The rates above come from synthetic and locally generated files. They are not a
  production false-positive rate or a general prompt-injection guarantee. Hosted CI
  (Ubuntu, macOS, Windows) has not run this change.

## Observed in passing

Seven of the 12 Chromium exports and all 8 LibreOffice exports get `agent_base64_blob`
(advisory), so `agent-ingest` and `agent-document` block them on main as well. For
LibreOffice, the match is a 1,340-character UTF-16BE hex outline title (`/Title<FEFF…>`):
hex digits are base64 characters. The Chromium match is in `pdf-flate` and was not traced.
This change does not address it.
