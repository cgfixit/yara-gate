# Word field instructions for `heuristic_ooxml_dde` (2026-11-28)

Source: `main` at `135992d`, branch `claude/serene-brown-qb93an`. Linux x86_64 (4 cores),
Python 3.12, YARA-X 1.24.0, 89 compiled local rules, no vendor packs. LibreOffice 24.2.7.2 as
the reader. One function changes: the DDE test in `ooxml_structure_findings`
(`heuristics.py`), now `dde_field`. No rule file, rule id, severity, policy, or view changes.

## What the check read

`heuristic_ooxml_dde` is a block. On `135992d` it fired on a unit that holds the bytes
`http://schemas.openxmlformats.org`, `DDE`, and `instrText` or `fldChar`, anywhere, and that
opens with a tag or is not text. It never read a field. So it missed a DDE field written in any
way that does not leave those bytes, and it held a document that names DDE in its text beside
any field at all.

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
| "The DDE protocol is described in chapter 4." beside a `PAGE` field | a page number | **block** | clean |
| `HYPERLINK "https://example.invalid/DDEAUTO"` | a link | **block** | clean |
| `w:fldSimple w:instr=" PAGE "` | a page number | clean | clean |

Seven fields LibreOffice reads as DDE were clean, three more than the backlog listed, and two
documents with no DDE field were held. **Assessment** for Word: field types are not
case-sensitive and a field's instruction is the text of its instruction runs between its begin
and separate characters; Word was not run.

## The change

`dde_field` reads each field's instruction as LibreOffice does and blocks when its type is DDE
or DDEAUTO, in any case, after white space:

- A `fldSimple`'s `instr` attribute, and a complex field's `instrText` (and `delInstrText`,
  read wide) joined from its `fldChar` begin to its separate or end, under any prefix.
- UTF-16 parts are transcoded, character references and the five predefined entities are
  resolved, comments are dropped, and a CDATA section is its text.
- A field whose instruction opens with a nested field counts when "dde" stands anywhere in
  it, since its type is the nested field's result. Instruction text outside any field is read
  on its own. Both are wider than a reader, the safe direction.
- Text that does not open with a tag after a byte order mark and white space is no part Word
  reads and is not read (the November 26 boundary). A zip's own bytes are no longer read; its
  members are.
- Past 64 nested fields or 1 MiB of instruction text the reader stops and the byte test of
  `135992d` decides.

## Generated documents against LibreOffice

**Verified.** 3,000 `.docx` files from five seeds. Each holds one to three fields: complex
fields split into one to four runs, simple fields, and nested fields two deep. Field types are
DDE, DDEAUTO, and their mixed-case spellings, PAGE, REF, HYPERLINK, QUOTE, IF, SET, `DDEX`,
and `XDDE`, with arguments that name DDE or DDEAUTO. Letters are written as character
references, comments and CDATA are inserted, and parts use the Strict namespace, UTF-16, other
prefixes, a missing separate character, and prose that names DDE. LibreOffice converted 2,991
in batch runs; the other nine are at the same three positions in every batch (246, 492, 493),
where a batch run stopped, and the two run on their own converted and agreed.

| Measure | Count |
| --- | ---: |
| Files LibreOffice read | 2,991 |
| A field LibreOffice reads as DDE or DDEAUTO | 1,753 |
| Of those, held now | 1,753 |
| No DDE field to LibreOffice, clean now | 1,107 |
| No DDE field to LibreOffice, held now | 131 |

All 131 are the nested-field reading: a field opening with a nested field whose instruction
names `dde` (`SET bookmark_dde`), checked against a walk of the same part with Python's XML
parser. LibreOffice does not report the outer field's type there.

## Generated parts against `135992d`

**Verified.** 150,000 parts from the same generator, without LibreOffice: each read by the
byte test of `135992d`, by `dde_field`, and by an independent walk with Python's
`xml.dom.minidom`.

| `135992d` | Now | The independent walk finds | Parts |
| --- | --- | --- | ---: |
| held | held | a DDE field | 42,377 |
| clean | held | a DDE field | 45,452 |
| held | clean | no DDE field | 18,764 |
| held | clean | a nested field with no "dde" in it | 282 |
| held | held | a nested field naming "dde" | 3,445 |
| clean | held | a nested field naming "dde" | 2,676 |
| clean | clean | no DDE field, or a nested one without "dde" | 37,004 |
| held | clean | a DDE field | **0** |
| clean | clean | a DDE field | **0** |

## Rule pairs

Three pairs are added to [`check_rule_pairs.py`](check_rule_pairs.py), each verified on
`135992d` (fire clean there, near-miss held there, or both):

- A `fldSimple` DDEAUTO field (fires), beside prose that names DDE and a `PAGE` field
  (held on `135992d`).
- A field whose type is split as ` DD` and `e<!-- x -->&#97;uto` (fires), beside a
  `HYPERLINK` whose address holds `DDEAUTO` (held on `135992d`).
- A UTF-16 Strict `fldSimple` DDE field (fires), beside the same part with `PAGE`.

The pairs of November 26 still pass: the stored Strict document is now held through its member
as stray instruction text, and the DDE detector's source as a deflated member is clean.

## Demo pair

`word_dde_split_field` and `word_dde_prose_page` join the catalog under **Attachment**: a report
whose DDEAUTO field type is split across three runs with a comment and a character reference
(clean on `135992d`, a block now), and a training note that names DDE and DDEAUTO in its text
and numbers its page with a field (a block on `135992d`, clean now). The catalog is 53 pairs
and three unfinished scans (109 scenarios). `agent-ingest` holds 53 of 53, `agent-document`
28, the default policy blocks 7, and the 53 twins give 0 findings in 159 recordings.

One recorded case changes without changing its verdict: `word_dde_field`, a stored `.docx`,
was reported twice on `135992d` (the outer file's bytes and the member) and is reported once
now, on the member. The conformance manifest gains two fixtures and no fixture moved (84 lines
added, none removed): 110 fixtures, 330 checks.

## Installed files

**Verified.** The sweep's `collect` over the roots of the November 26 records plus
`/usr/lib/libreoffice` and `/usr/share/libreoffice` gave 15,012 text files, and a `find` for
`.zip`, `.docx`, `.docm`, `.xlsx`, `.pptx`, `.whl`, `.jar`, `.odt`, `.dotx`, and `.xml` under
50 MB gave 2,616 more. Each was scanned through a `git worktree` of `135992d` and through this
tree. No file changed findings in either set. No installed file holds a DDE field or the old
byte pattern; the 15 `heuristic_ooxml_oleobject` advisories in the second set are LibreOffice's
own menu files named `oleobject.xml`, the same on both trees (backlog).

## Timing

`dde_field` and the whole Office check on 4 MiB inputs, one run each:

| Input | `dde_field` | Result |
| --- | ---: | --- |
| `fldChar` begin repeated | 0.005 s | no instruction, False |
| About 30,000 PAGE fields | 0.20 s | False |
| One `instrText` of 4 MiB | 0.005 s | past the bound: the byte test, clean |
| `instrText` runs of character references | 0.35 s | False |
| Tags left open inside a quoted value | 0.005 s | False |
| `<!--` and `<![CDATA[` repeated | 0.07 s, 0.08 s | False |
| `fldSimple` PAGE repeated | 0.26 s | False |
| Nested fields 60 deep, repeated | 0.002 s | True at the first |
| The same fields as UTF-16 | 0.13 s | False |
| Prose | 0.005 s | False |

A quoted attribute value may not hold `<` in XML, so a tag left open is given up at the next
`<`; the first draft let a quoted value run on and was changed before these runs.

## `agent_role_spoof_action`

A sigil test was tried again for `dpkg-scansources` (`$override{` as a name) and returned
before it was committed. It cleared the raw view, but the `text-folded` view reads `$` as `s`
and `@` as `a`, so `$override{` is `soverride{` there, a letter glued to the verb, which the rule
must keep counting for a verb after an escaped line break (`\nreveal`, a rule pair on `main`).
The three files stay advisory; the declined list has the reason.

## Checks

BATTERY

## Independent attempt to break it

REVIEW

## What this does not show

- Word did not run. LibreOffice is the reader here; that Word reads the same instruction, and
  reads field types in any case, is an assessment.
- `heuristic_ooxml_dde` reads WordprocessingML fields. DDE in a spreadsheet (`ddeLink` in an
  external-link part, a `=cmd|…` formula in a cell), in RTF (`\fldinst`), in a `.doc`, and in
  a Word HTML or MHT file is not read by it.
- A nested field that builds the type of its outer field out of other fields without naming
  "dde" is not read as DDE; whether Word accepts a type built that way was not checked.
- 15,012 and 2,616 files on one machine are not a false-positive rate.
