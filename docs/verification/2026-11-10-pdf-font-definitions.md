# PDF font objects defined more than once — November 10, 2026

Base: main `2b6eda8` (#204). Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0,
85 bundled local rules, zero skips, no vendor download. Ruleset SHA-256
`bf5331f06848cfc3a02e46ff903180a0ef56de233c6db7f589fe69ccea18cf39`. Every scan used a
disposable copy of `rules/local` and `rules/rules.lock`, and every CLI scan a disposable
home. Nothing was executed and no pack was fetched. The base was run from a detached
worktree of `2b6eda8` on the same fixtures.

## Defect

`_font` in `src/yara_gate/pdftext.py` looped over an object's definitions and returned at
the first body that looked like a font, so a font object defined more than once was read
through one definition. Three more places did the same thing one step away:

- `pdf_text` built `by_number` as a dict, so a `ToUnicode` stream defined twice was read
  through the **last** definition only.
- The lookup is keyed by `(number, generation)`. `6 1 obj` was not a definition of the
  font a page names `6 0 R`, and the reverse.
- For a font longer than the lookup's 4 KB window, the whole object was read from a table
  that kept one offset per key, so every definition was read through the last one's
  `/ToUnicode`.

Fixtures: `samples.redefined_font_pdf` and `samples.redefined_map_pdf`. One page whose
`/Font` is `<< /F1 6 0 R >>` shows `_PDF_PHRASE` as glyph ids. One definition maps the ids
to the phrase; the others map each id a few printable characters along. The files have no
cross-reference table, so nothing in them says which definition is in use.

Library outcomes, `scan_bytes`, default / agent-ingest / agent-document. `phrase` is
`agent_override_imperative`, a note rule; `unmapped` is `heuristic_pdf_text_unmapped`.

| Fixture | main `2b6eda8` | this change |
| --- | --- | --- |
| `font-twice-first.pdf` (`6 0 obj` twice, phrase map in the first) | advisory / block / advisory, phrase | same |
| `font-twice-last.pdf` (phrase map in the second) | **clean / clean / clean** | advisory / block / advisory, phrase |
| `font-generation.pdf` (`6 0 obj` decoy, `6 1 obj` phrase, page says `6 0 R`) | **clean** | advisory / block / advisory, phrase |
| `font-reference-generation.pdf` (page says `6 1 R`; `6 1 obj` decoy, `6 0 obj` phrase) | **clean** | advisory / block / advisory, phrase |
| `font-objstm-member.pdf` (raw decoy, phrase font in an object stream) | **clean** | advisory / block / advisory, phrase |
| `font-map-twice-first.pdf` (font once; map stream twice, phrase map first) | **clean** | advisory / block / advisory, phrase |
| `font-map-twice-last.pdf` (phrase map second) | advisory / block / advisory, phrase | same |
| `font-five-first.pdf` (five distinct definitions, phrase in the first) | advisory / block / advisory, phrase | same, plus unmapped |
| `font-five-last.pdf` (phrase in the fifth) | **clean** | advisory / block / advisory, phrase and unmapped |
| `font-five-second.pdf` (phrase in the second) | **clean** | advisory / block / advisory, unmapped |
| `font-twice-plain.pdf`, `font-generation-plain.pdf`, `font-map-twice-plain.pdf`, `font-five-equal-plain.pdf` (benign) | clean | clean |
| `font-five-plain.pdf` (benign, five distinct definitions) | clean | advisory / block / advisory, unmapped |

CLI with an inbox copy (`yara-gate scan <inbox file> --home … --rules … --policy …`):

| Fixture | Policy | main | this change |
| --- | --- | --- | --- |
| `font-twice-last.pdf`, `font-generation.pdf`, `font-map-twice-first.pdf` | default | 0, filed clean | 0, filed clean, note recorded |
| the same three | agent-ingest | **0, filed clean** | 1, filed blocked |
| the same three | agent-document | 0, filed clean | 0, filed clean, note recorded |
| `font-twice-plain.pdf` | all three | 0, filed clean | 0, filed clean |

SHA-256 of the fixtures: `font-twice-last.pdf` `db83b10f…8dc6`, `font-generation.pdf`
`49ae078c…45f3`, `font-map-twice-first.pdf` `1def5b8c…6497`, `font-five-second.pdf`
`712cb55a…3727`, `font-twice-plain.pdf` `99b18c79…4a6f`. All are rebuilt deterministically
by `check_added_rules.font_definition_cases()`.

## Which definition a reader uses

**Direct runtime, one reader.** `pdftotext` 24.02.0 (poppler) on this machine, on copies of
the fixtures with a complete Type0 font (descendant font and descriptor) so that it opens
them, with and without a cross-reference table:

| File | Table names | `pdftotext` shows |
| --- | --- | --- |
| font twice, phrase map in the first | the first / the last / no table | phrase / decoy / decoy |
| font twice, phrase map in the second | the first / the last / no table | decoy / phrase / phrase |
| map stream twice, phrase map in the first | the first / the last / no table | phrase / decoy / decoy |
| `6 0 obj` decoy, `6 1 obj` phrase, page says `6 0 R` | generation 0 / generation 1 / no table | decoy / no text / no text |
| only `6 1 obj`, page says `6 0 R`; only `6 0 obj`, page says `6 1 R` | either | no text |

poppler follows the table to whichever definition it names and takes the last when there
is none, so the second and third rows of the first table are text a real reader shows and
main did not scan. poppler compares the generation, so it does not show the generation
rows.

**Source read on November 10** (default-branch heads fetched from GitHub; not run):

- PDFium: `CPDF_Reference(CPDF_IndirectObjectHolder*, uint32_t objnum)` holds an object
  number only; the syntax parser discards the reference's generation
  (`cpdf_reference.h`, `cpdf_syntax_parser.cpp`). `ParseIndirectObject(objnum)` asks the
  table by number. `RebuildCrossRef` calls `AddNormal`, which keeps the earlier entry only
  when its generation is higher, so a later or higher-generation header wins
  (`cpdf_parser.cpp`, `cpdf_cross_ref_table.cpp`).
- MuPDF: `pdf_resolve_indirect` calls `pdf_cache_object(ctx, doc, num)` and checks the
  parsed object's number, not its generation (`source/pdf/pdf-xref.c`).
- pdfminer.six: `getobj(objid)` takes a number; `_getobj_parse` reads the generation into
  `_genno` and does not use it (`pdfminer/pdfdocument.py`).
- pdf.js: `fetchUncompressed` raises on a generation mismatch, except that with
  `_generationFallback` a reference to a later generation falls back to the entry's
  earlier one. `indexObjects`, its rebuild, replaces an entry only for a header of the same
  generation, so the first header's generation is kept (`src/core/xref.js`).
- pypdf: looks the object up as `xref[generation][idnum]` and rejects a header whose
  generation differs (`pypdf/_reader.py`).

PDFBox's `COSParser.java` was fetched and only located (it keys objects by number and
generation); poppler's `XRef.cc` could not be fetched and its behavior is the runtime table
above. Nothing here was run against Acrobat, Preview, or a browser.

## Decisions

- **Every definition gives a reading.** Raw `N G obj` definitions of the object number,
  then object-stream members. Equal readings count once.
- **A different generation counts.** Three of the readers above ignore a reference's
  generation, and pdf.js falls back across it. The page says `6 0 R`; `6 1 obj` is a font
  some reader shows. The lookup therefore goes by object number, for the font and for an
  indirect `/Font` resource dictionary. The cost is one more reading on a file that reuses
  a number; the benign twin `font-generation-plain.pdf` is clean.
- **The `ToUnicode` stream is read the same way.** Leaving it would move the same file one
  object along: define the font once and its map twice. Stream numbers were already
  generation-blind.
- **Order under the cap.** The last definition, then the first, then the ones between,
  latest first. An ordinary incremental update leaves the last in use; a table can still
  name the first, which is also the one main read, so no finding main had is lost on a font
  alone. The order matters only past four readings.
- **Caps stay fail-visible.** A font with more than four distinct readings, or more than 64
  raw definitions (`MAX_FONT_DEFINITIONS`), or a long definition that could not be read to
  its end, gets an unresolved reading as well. Text shown in it is
  `heuristic_pdf_text_unmapped`, as for a name that means five fonts
  ([2026-11-07-pdf-font-readings.md](2026-11-07-pdf-font-readings.md)).
- **Not chosen:** following the cross-reference table to one definition (readers disagree,
  and the file's author writes the table); an incomplete reason past the cap (a file saved
  five times with a re-subset font would exit 2 under every policy).

## Change

- `_Definitions` in `pdftext.py`: one pass over the file finds every header of the wanted
  object numbers, under any generation, and keeps their offsets. A body is the lookup's
  4 KB window; a long font is read from its own offset to its own `endobj`.
- `_font(number, definitions, cmaps)` returns a reading for each definition of the object
  and of its map, then the carried readings of overflowing maps, capped at four plus the
  unresolved reading. `_Cmaps.fonts` keeps the answer per map and font kind, so fonts that
  share a map share the reading objects.
- `_fonts` caches by object number, so a font named under many generations is read once,
  and checks the deadline in its loop over a name's fonts.
- `MAX_FONT_OBJECT_BYTES` (256 MiB) bounds the bytes read past the window. Objects that do
  not overlap cannot reach it in a file of that size; headers with no `endobj` between
  them could each be read for 1 MiB.
- Fixtures and cases: `samples.redefined_font_pdf`, `samples.redefined_map_pdf`; 15 cases
  in `check_added_rules.font_definition_cases()`; 12 `fonts` cases and three `B7` cases in
  `docs/research/probe_detection_gaps.py`; `pdf-font-definitions.pdf` in
  `check_worst_case_timing.py`; 18 tests (11 functions) in `tests/test_pdftext.py`.

## Real generator output

`sweep_rule_changes.py` compares two rule trees over text files and does not read PDFs, so
it does not apply to a reader change with no rule edit. The comparison was made on PDFs
instead, base against this change, three policies each:

- 12 Chromium 153.0.8010.12 `page.pdf()` exports of multi-font, multi-page HTML, 8
  LibreOffice 24.2.7.2 exports of the same HTML, and the two third-party PDFs on disk.
  No object number is defined twice in any of the 22.
- The same 22 with an incremental update appended that rewrites every font dictionary
  unchanged, and again with each font pointed at another font's `ToUnicode` map, as a
  re-subset font would have a new map. `pdftotext` reads the updated definition in both.

| Files | Verdicts and rule ids, base and change | Text pieces |
| --- | --- | --- |
| 22 originals | identical | identical |
| 22 with fonts rewritten unchanged | identical | identical: equal definitions are one reading |
| 22 with fonts rewritten onto another map | identical | 20 scan about twice the pieces: the updated definition, which is what `pdftotext` shows and main did not read |

No file changed verdict or rule ids under any policy. The LibreOffice exports are
advisory / block / block on both, from `agent_base64_blob`, as recorded on November 7.

## Timing

`check_worst_case_timing.py`: PASS, 30 inputs of exactly 4 MiB. The new
`pdf-font-definitions.pdf` (one font object defined until the file is full, over a map
defined 1,900 times) took 5.84 s, advisory with `heuristic_pdf_text_unmapped`; in a
side-by-side run main took 4.93 s and this change 5.74 s on the same bytes. The slowest
input was `pdf-page-objects.pdf` at 6.84 s.

Other 4 MiB inputs written for this change, one run each, base and change:

| Input | main | this change |
| --- | --- | --- |
| one font number, definitions fill the file | 4.21 s | 4.92 s |
| one font number, bare headers fill the file | 5.02 s | 5.80 s |
| one font number under all 65,536 generations | 1.71 s | 1.89 s |
| one font, 64 definitions, named under 65,536 generations | 2.02 s | 1.88 s |
| font defined 64 times over a map defined 1,900 times | 2.17 s | 2.28 s |
| 4,000 font numbers, 64 long definitions each | 9.60 s | 8.37 s |
| 122,000 font numbers, one long definition each, no `endobj` | **158.15 s**, then `timeout` | 6.95 s, `pdf annotation objects exceed 100000` |
| 2,764 names that each mean 64 fonts with near-equal 8,192-entry maps | stopped by hand after 555 s | 30.02 s, `timeout` |

The last two rows are defects main already has. In the first, each long font was read for
1 MiB with no deadline check; `MAX_FONT_OBJECT_BYTES` and a check per read bound it. In the
second, `_fonts` compares every pair of a name's fonts by map contents and never checked
the deadline. This change adds the check, so the scan ends at the deadline as incomplete.
The comparison itself is still quadratic and still over the 10 s ceiling, so that input is
not in the tripwire; it is a separate change.

## Commands and results (this container)

- `uv run pytest -q tests/test_pdftext.py`: 45 passed. With `pdftext.py` from `2b6eda8`,
  13 of the 18 new tests fail; the other five are controls main already holds. One existing
  test, `test_an_overflowing_tounicode_font_has_a_second_reading`, calls `_font` directly
  and was moved to the new signature with its assertion unchanged. A broader
  focused run (`tests/test_pdftext.py tests/test_pdf_text_folding.py
  tests/test_worst_case_timing.py tests/test_scanner.py tests/test_pdfannotations.py
  tests/test_phase1c_readers.py tests/test_heuristics.py tests/test_pages_deploy.py
  tests/test_demo.py`): 369 passed.
- `docs/verification/check_added_rules.py`: passed, 230 cases plus 4 vendor-override cases.
- `docs/research/probe_detection_gaps.py --verify`: exit 0; 236 `ok`, no FAIL or STALE; the
  ten open cases are B1 to B6 and the new B7. CLI agent-ingest intake filed every case as
  blocked.
- `docs/research/probe_rule_coverage.py --verify`: exit 0, with 607 library, 55 CLI, and 9
  benign observations and no failures.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 benign files, zero
  incomplete. `heuristic_pdf_text_unmapped` hits 1 file (0.30%, `pdf/merged-5-fonts.pdf`),
  as before; the other hits are the four tagged Windows files.
- `docs/verification/check_worst_case_timing.py`: PASS, 30 inputs (above).
- `docs/verification/check_rule_pairs.py` (115 rules) and `lint_rules.py` (85 rules, 2
  vendor overrides): passed. No rule changed.
- `scripts/record_pages_demo.py --baseline web-demo/recordings.json`: the recorded outcomes
  are unchanged.
- `ruff check .`, `ruff format --check .`, `mypy --strict src scripts` (24 files),
  `check_text_controls.py`, and `check_doc_links.py`: clean.

## Residual risks and boundaries

- **agent-document passes the capped case.** A phrase only the unread definition decodes
  (`font-five-second.pdf`) is reported, not read. Under `agent-document` the note is
  recorded and the file passes, as for any unmapped text.
- **A benign file can pay the note.** A font object with five distinct definitions, such
  as one re-subset in five incremental saves, is held under `agent-ingest`. No generator
  file examined here redefines a font at all.
- **More readings on a reused name.** A name that already means four fonts loses one to
  the cap when one of them has a second definition, and the scan says so.
- **Two `/ToUnicode` keys in one dictionary are still read through the first.** poppler,
  PDFium, and pdf.js keep the last. This is B7 in the
  [detection backlog](../research/detection-backlog.md), with the reason it is not built
  here: the 4 KB window runs past the object's end.
- **An object stream the gate cannot decode can redefine a font.** The raw definition is
  the only one read, with no note. Recorded in the backlog.
- **More than 64 object-stream members for one number** come back from the lookup as an
  empty body, as before, and are not read.
- **Header lookalikes count.** `6 0 obj` inside a string or an uncompressed stream is read
  as a definition, as the lookup always did. It can add a reading, never remove one.
- The fixtures are synthetic and the generator sample is 22 files. Neither is a production
  false-positive rate or a general prompt-injection guarantee. Hosted CI (Ubuntu, macOS,
  Windows) has not run this change at the time of writing.

## Open pull request #205

[#205](https://github.com/cgfixit/yara-gate/pull/205) (`6e38a64`, per-page font resources)
edits the same functions. A trial merge of the two heads conflicts in `pdftext.py` and in
one line of `docs/rules.md`; the resolution and the checks run on the merged tree are in
this change's pull request description.
