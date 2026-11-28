# Word field instructions for `heuristic_ooxml_dde` (2026-11-28)

Source: `main` at `135992d`, branch `claude/serene-brown-qb93an`. Linux x86_64 (4 cores),
Python 3.12.3 with expat 2.6.1, YARA-X 1.24.0, 89 compiled local rules, no vendor packs.
LibreOffice 24.2.7.2 as the reader. The DDE test in `ooxml_structure_findings`
(`heuristics.py`) gains a field reader, `dde_field`, beside the byte test it had. No rule
file, rule id, severity, policy, or view changes.

## What the check read

`heuristic_ooxml_dde` is a block. On `135992d` it fires on a unit that holds the bytes
`http://schemas.openxmlformats.org`, `DDE`, and `instrText` or `fldChar`, anywhere, and that
opens with a tag or is not text. It never reads a field, so it misses a DDE field written in
any way that does not leave those bytes.

## Reproduction beside a reader

**Verified.** Fourteen inert `.docx` files, each a `document.xml` with one paragraph of fields
(the DDE target is the word `inert`, never a program), were scanned on `135992d` and converted
by LibreOffice (`soffice --headless --convert-to fodt`, a scratch profile, no network).
LibreOffice imports a Word field it does not handle as a field mark and keeps its instruction
in `field:value`; that value is the reader's reading of the instruction.

| Fixture | LibreOffice's instruction | `135992d` | Now |
| --- | --- | --- | --- |
| One instruction run (control) | `DDEAUTO "inert" "inert"` | block | block |
| `w:fldSimple w:instr="…"` | `DDEAUTO "inert" "inert"` | clean | block |
| Instruction split into ` DD` and `EAUTO …` | `DDEAUTO "inert" "inert"` | clean | block |
| Strict namespace (`purl.oclc.org`), deflated | `DDEAUTO "inert" "inert"` | clean | block |
| `document.xml` in UTF-16LE | `DDEAUTO "inert" "inert"` | clean | block |
| `ddeauto` in small letters | `ddeauto "inert" "inert"` | clean | block |
| `DD&#69;AUTO` | `DDEAUTO "inert" "inert"` | clean | block |
| `DD<!-- x -->EAUTO` | `DDEAUTO "inert" "inert"` | clean | block |
| The `x:` prefix bound to WordprocessingML | `DDEAUTO "inert" "inert"` | block | block |
| `DDE "inert" "inert" "inert"` | `DDE "inert" "inert" "inert"` | block | block |
| A `PAGE` field | a page number | clean | clean |
| "The DDE protocol is described in chapter 4." beside a `PAGE` field | a page number | block | block |
| `HYPERLINK "https://example.invalid/DDEAUTO"` | a link | block | block |
| `w:fldSimple w:instr=" PAGE "` | a page number | clean | clean |

Seven fields LibreOffice reads as DDE were clean, three more than the backlog listed.
**Assessment** for Word: field types are not case-sensitive, and a field's instruction is the
text of its instruction runs between its begin and separate characters; Word was not run. The
two documents with no DDE field that the byte test holds stay held: see below.

## The change

The byte test of `135992d` is kept as it is, and `dde_field` is read beside it; a part
either holds is held. `dde_field` parses the part with expat, namespaces resolved, and reads
each field's instruction as LibreOffice does:

- The `w:instr` of a `w:fldSimple`, and the character data of a complex field's
  `w:instrText` from its `w:fldChar` begin to its separate or end, child elements and
  processing instructions included. `w:delInstrText` and `mc:Fallback` are left out, as
  LibreOffice leaves them out, and a `w:t` between begin and separate is read into the
  instruction, as LibreOffice reads it. Only the WordprocessingML namespaces, transitional
  and Strict, count, on elements and on their attributes.
- A type DDE or DDEAUTO, in any case, after white space or no-break spaces, holds.
- A field whose instruction opens with a nested field holds when DDE or DDEAUTO stands in it
  as a word, since its type is the nested field's result. Instruction text outside any field
  is read on its own. Both are wider than LibreOffice, the safe direction.
- A part with a DOCTYPE, one expat does not parse, or one past 64 nested fields or 1 MiB of
  instruction text is not read by it: the byte test decides. A part's DTD is never read.
- Text that does not open with a tag after a byte order mark and white space is not read,
  the boundary of November 26.

## The first version, and why the byte test stays

The first version (`10c05f7`) replaced the byte test with a reader of patterns: tags matched
under any prefix, text read to the next `<`, comments removed before CDATA, attribute values
not unescaped. An independent review with a fresh context was given its diff and LibreOffice
and asked to make it wrong. Each finding was reproduced here: its 45 fixtures were scanned on
`135992d` and on the branch, and converted by LibreOffice.

| Finding | Fixtures | `135992d` | First version | Now |
| --- | --- | --- | --- | --- |
| A field element or attribute in another namespace changes the field (`x:instrText`, `x:fldChar`, `x:instr`, an unprefixed `fldCharType`) | 5 | block | clean | block |
| A processing instruction or a child element inside `w:instrText` | 2 | block | clean | block |
| `<![CDATA[<!--]]>` and a later `-->` remove the field between | 1 | block | clean | block |
| `w:fldCharType="&#98;egin"` | 2 | block | clean | block |
| `w:delInstrText` or `mc:Fallback` text joined into the instruction | 2 | block | clean | block |
| A `w:t` between begin and separate, a no-break space before the type, a decoy `fldCharType` before the real one, and five shapes LibreOffice does not read as DDE (a quoted type, a switch before the type, an ignorable element, instruction text inside a deletion, a hidden run) | 8 | block | clean | block |
| Leading-zero character references, a decoy `instr=` inside another attribute's value | 3 | clean | clean | block |
| UTF-16LE and BE, with and without a byte order mark or a declaration | 4 | clean | block | block |
| A stray unclosed begin, then `REF _Ref_Addendum` or `HYPERLINK …/hidden-fees`; `{ {REF Hidden_Clause} \* MERGEFORMAT }` | 3 (benign) | clean | **block** | clean |
| A begin, 1,000,000 spaces of instruction, then 3 MiB of begin and end pairs (11,562 bytes zipped) | 1 | clean, 0.7 s | incomplete, 31.8 s | clean, 0.84 s |

Of the 45, 20 that `135992d` held went clean on the first version, 15 of them fields LibreOffice reads as DDE. Every one `135992d` held is held now, every one LibreOffice reads as a DDE field
is held now, and the three benign ones are clean. The three benign ones were held because the
nested reading looked for the letters "dde" anywhere (hi*dde*n, A*dde*ndum); it now looks for
the word. The slow one re-read the outer instruction at every nested begin.

Keeping the byte test means nothing `135992d` holds goes clean, by construction. It also
means the two benign shapes it holds stay held: prose that names DDE beside any field, and a
hyperlink whose address holds `DDEAUTO`. The first version cleared both, but only by reading
less than the byte test in places a reader does not.

## Generated documents against LibreOffice

**Verified.** 3,000 `.docx` files from five seeds. Each holds one to three fields: complex
fields split into one to four runs, simple fields, and nested fields two deep. Field types are
DDE, DDEAUTO, and their mixed-case spellings, PAGE, REF, HYPERLINK, QUOTE, IF, SET, `DDEX`,
and `XDDE`, with arguments that name DDE or DDEAUTO. Letters are written as character
references, comments and CDATA are inserted, and parts use the Strict namespace, UTF-16, other
prefixes, a missing separate character, and prose that names DDE. LibreOffice converted 2,991
in batch runs; the other nine are at the same three positions in every batch (246, 492, 493),
where a batch run stopped, and the two run on their own converted and agreed. `dde_field` was
compared alone, without the byte test.

| Measure | Count |
| --- | ---: |
| Files LibreOffice read | 2,991 |
| A field LibreOffice reads as DDE or DDEAUTO | 1,753 |
| Of those, held by `dde_field` | 1,753 |
| No DDE field to LibreOffice, clean | 1,151 |
| No DDE field to LibreOffice, held | 87 |

All 87 are the nested reading: a field opening with a nested field whose instruction names
DDE or DDEAUTO as a word, checked against a walk of the same part with Python's
`xml.dom.minidom`. LibreOffice does not report the outer field's type there.

## Generated parts against `135992d`

**Verified.** 150,000 parts from the same generator, without LibreOffice: each read by the
byte test of `135992d`, by the check now (byte test or `dde_field`), and by an independent
walk with `xml.dom.minidom`.

| `135992d` | Now | The independent walk finds | Parts |
| --- | --- | --- | ---: |
| held | held | a DDE field | 42,377 |
| clean | held | a DDE field | 45,452 |
| held | held | a nested field (with or without the word) | 3,727 |
| clean | held | a nested field naming DDE as a word | 1,470 |
| held | held | no DDE field | 18,764 |
| clean | clean | no DDE field, or a nested one without the word | 38,210 |
| clean | clean | a DDE field | **0** |
| held | clean | anything | **0** |

## Rule pairs

Three pairs are added to [`check_rule_pairs.py`](check_rule_pairs.py), each checked on
`135992d` (each fire clean there):

- A `fldSimple` DDEAUTO field (fires), beside a stray begin and a `REF _Ref_Addendum` field.
- A field whose type is split as ` DD` and `e<!-- x -->&#97;uto` (fires), beside
  `{ {REF Hidden_Clause} \* MERGEFORMAT }`.
- A UTF-16 Strict `fldSimple` DDE field (fires), beside the same part with `PAGE`.

The two benign near-misses are the review's, which the first version held. The pairs of
November 26 pass unchanged.

## Demo pair

`word_dde_split_field` and `word_page_split_field` join the catalog under **Attachment**: a
report whose DDEAUTO field type is split across three runs with a comment and a character
reference (clean on `135992d`, a block now), and the same report whose page-number field is
split the same way (clean on both). Both are full packages LibreOffice opens; it reads the
first as `ddeauto c:\windows\system32\cmd.exe "/k echo inert"` and the second as a page
number. The catalog is 53 pairs and three unfinished scans (109 scenarios). The 107 cases
recorded on `135992d` are unchanged. `agent-ingest` holds 53 of 53, `agent-document` 28, the
default policy blocks 7, and the 53 twins give 0 findings in 159 recordings. The conformance
manifest gains two fixtures and no fixture moved (84 lines added, none removed): 110
fixtures, 330 checks.

## Installed files

**Verified.** The sweep's `collect` over the roots of the November 26 records plus
`/usr/lib/libreoffice` and `/usr/share/libreoffice` gave 15,012 text files, and a `find` for
`.zip`, `.docx`, `.docm`, `.xlsx`, `.pptx`, `.whl`, `.jar`, `.odt`, `.dotx`, and `.xml` under
50 MB gave 2,616 more. Each was scanned through a `git worktree` of `135992d` and through the
final code. No installed file changed findings in either set: 82 text files had a finding on
both trees, none was incomplete, and no installed file holds a DDE field or the byte pattern.
The only text files that differ are this record and the backlog, both edited here; scanned
with the same text through both trees, the backlog gives the same findings. The 15
`heuristic_ooxml_oleobject` advisories in the second set are LibreOffice's own menu files named
`oleobject.xml`, the same on both trees (backlog).

## Timing

`dde_field` and the whole Office check on inputs of 3 to 4 MiB, one run each:

| Input | `dde_field` | Result |
| --- | ---: | --- |
| `fldChar` begin repeated, never closed | 0.01 s | past the bound: the byte test, clean |
| About 30,000 PAGE fields | 0.23 s | False |
| One `instrText` of 4 MiB | 0.01 s | past the bound: the byte test, clean |
| `instrText` runs of character references | 0.20 s | False |
| `fldSimple` PAGE repeated | 0.24 s | False |
| Nested fields 60 deep, repeated | 0.29 s | False |
| The review's begin, 1,000,000 spaces, and begin and end pairs | 0.18 s | False |
| Paragraphs of prose, then a stray `instrText` after the root | 0.16 s | not well-formed: the byte test |
| `<!-- c -->` repeated | 0.02 s | False |
| PAGE fields as UTF-16 | 0.11 s | False |
| A part cut off inside a tag | 0.01 s | not well-formed: the byte test |

## `agent_role_spoof_action`

A sigil test was tried again for `dpkg-scansources` (`$override{` as a name) and returned
before it was committed. It cleared the raw view, but the `text-folded` view reads `$` as `s`
and `@` as `a`, so `$override{` is `soverride{` there, a letter glued to the verb, which the rule
must keep counting for a verb after an escaped line break (`\nreveal`, a rule pair on `main`).
The three files stay advisory; the declined list has the reason.

## Checks

On `aa3ab98`, which holds the final code and this record:

| Check | Result |
| --- | --- |
| `lint_rules.py` | 89 compiled and linted; vendor overrides (2) |
| `check_rule_generator.py`, `check_rules_lock.py`, `uv lock --check` | passed |
| `check_rule_pairs.py` | 120 rules passed, with the three pairs above |
| `probe_match_cap.py` | 3,447 flooded texts over 84 rules, 0 blind spots, 0 fail |
| `check_added_rules.py` | 271 plus 4 vendor-override cases |
| `measure_precision.py --fail-over` (328 files) | exit 0, 0 incomplete |
| `probe_rule_coverage.py --verify` | passed |
| `probe_detection_gaps.py --verify` | exit 0 |
| `probe_ooxml_reader_agreement.py` | MISS 0, wide 5, ok 77 (the views are unchanged; run as a check) |
| `check_worst_case_timing.py` | 106 adversarial inputs of 4 MiB, pass |
| `check_scan_only.py`, `check_intake.py` | passed |
| `yara-gate selftest` | pass |
| `yara-gate conform`, `build_conformance.py --check` | 110 fixtures, 330 checks, 0 changes; manifest current |
| `scripts/record_pages_demo.py`, `scripts/build_pages.py` | 109 scenarios x 3 policies; 327 recordings validated |
| `check_text_controls.py`, `check_doc_links.py`, `zizmor --offline --pedantic` | passed |
| Ruff, `ruff format --check`, `mypy --strict src scripts` | passed |

## Second independent attempt to break it

**Not done.** A second subagent with a fresh context was given the final diff, `135992d`, and
LibreOffice, and asked to break it again. The model provider's safety filter stopped it
(`claude-opus-5-5`) while it moved from reading the first review's builders to writing
fixtures; it built and scanned nothing. It was not rerun with other wording. The parts of its
brief that need no evasion fixtures were run here instead:

| Input | Size | `dde_field` | Time | Peak memory |
| --- | ---: | --- | ---: | ---: |
| Elements nested 200,000 deep | 2 MiB | False | 1.04 s | 27 MiB |
| One element with 300,000 attributes | 3 MiB | False | 1.25 s | 61 MiB |
| 100,000 namespace declarations on one element | 2 MiB | False | 0.51 s | 28 MiB |
| The WordprocessingML prefix redeclared on every element | 3 MiB | False | 0.36 s | under 1 MiB |
| 64 open fields and nearly 4 MiB of instruction text | 3 MiB | None (the bound) | 0.01 s | 1 MiB |

The first two are the reader's cost: one Python call per element and a dictionary of every
attribute, which expat builds before the handler sees it. Both are under the 10 s ceiling of
the timing check, which passed (Checks). The installed-file sweep above is the benign test.
Whether a field that both `135992d` and the final code miss exists beyond the ones listed under
"What this does not show" was not checked by anyone but the author after the first review.

## What this does not show

- Word did not run. LibreOffice is the reader here; that Word reads the same instruction, and
  reads field types in any case, is an assessment.
- The byte test keeps holding prose that names DDE beside any field, and a hyperlink whose
  address holds `DDEAUTO`; neither is a DDE field.
- `heuristic_ooxml_dde` reads WordprocessingML fields. DDE in a spreadsheet (`ddeLink` in an
  external-link part, a `=cmd|…` formula in a cell), in RTF (`\fldinst`), in a `.doc`, and in
  a Word HTML or MHT file is not read by it. A UTF-32 part is read by neither, nor by
  LibreOffice.
- A nested field that builds its outer field's type from character codes
  (`{ {QUOTE 68 68 69 …} … }`) is not read as DDE; whether Word accepts a type built that way
  was not checked.
- 15,012 and 2,616 files on one machine are not a false-positive rate.
