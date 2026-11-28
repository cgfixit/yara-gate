# `heuristic_ooxml_oleobject`: a menu file named like an OLE object (2026-11-28)

Source: `main` at `0480d67`, branch `claude/ooxml-oleobject-name`. Linux x86_64, Python 3.12,
YARA-X 1.24.0, 89 compiled local rules, no vendor packs. One condition in
`ooxml_structure_findings` changes. The finding's id and severity are unchanged, and no rule or
reader changes. The lead is the backlog row the
[DDE field record](2026-11-28-dde-field-instructions.md#installed-files) left open, and finding
4 of [#376](https://github.com/cgfixit/yara-gate/issues/376), which reproduced the same thing
on a harmless `oleobject.xml`.

## On the base revision

**Verified** with `scan_bytes` on `0480d67`. The check read the unit's name alone: any file or
archive member whose lower-cased path holds `oleobject` was advisory under the default
policy and held under both agent policies, whatever its bytes.

| Input | default | agent-document |
| --- | --- | --- |
| LibreOffice's `swriter/popupmenu/oleobject.xml`, scanned as `oleobject.xml` | advisory | block |
| The same file inside a zip under `soffice.cfg/popupmenu/` | advisory | block |
| A compound file inside a zip at `word/embeddings/oleObject1.bin` | advisory | block |
| A compound file loose, named `oleObject1.bin` | advisory | block |

## The change

An OLE object in an OOXML package is a compound file in the package's `embeddings` folder
(`word/embeddings/oleObject1.bin`, `xl/embeddings/…`, `ppt/embeddings/…`). An unzip of the
package drops the same compound file loose. The check now reports a name that holds
`oleobject` in two cases:

- the name lies in a folder called `embeddings`, whatever its bytes, as before; or
- the bytes do not sniff as text, which covers a compound file anywhere.

A text file outside an `embeddings` folder embeds nothing. That covers LibreOffice's menu,
toolbar, and dialog files (`oleobject.xml`, `oleobjectbar.xml`, `insertoleobject.ui`), and
the check no longer reports them.

## Evidence

| Check | Result |
| --- | --- |
| The four inputs above, `scan_bytes` | The two LibreOffice cases are clean under every policy; both compound-file cases are unchanged |
| A differential of the old and the new condition over every file on this machine whose name holds `oleobject`, and every such member of the 4,076 archives found (`.docx`, `.xlsx`, `.pptx`, ODF, `.zip`, `.jar`, `.whl`, `.egg`, …) | 18 files changed, all advisory to nothing: the 15 LibreOffice menu and toolbar files the backlog names, LibreOffice's `cui/ui/insertoleobject.ui`, and two git ref files named after this branch. Both named archive members are still reported |
| `check_rule_pairs.py` | passes; the new near-miss (a LibreOffice-shaped `oleobject.xml` in a zip) fires on `0480d67`, and the new pair's compound file outside `embeddings` fires on both |
| `check_added_rules.py` | passes, 271 plus 4 vendor-override cases |
| `probe_rule_coverage.py --verify` | exit 0 |
| `yara-gate conform`, `build_conformance.py --check` | 124 fixtures, 372 checks, 0 changed; manifest `2ecb04746b013e5a`, with a change-list row |
| `record_pages_demo.py` | 123 scenarios × 3 policies; the 121 already recorded are unchanged, and only provenance differs |
| `build_pages.py` | 123 scenarios and 369 policy recordings validated |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `lint_rules.py` | clean |

## Demo pair

`extracted_ole_object` is a compound file named `oleObject1.bin` whose one `Ole10Native`
stream holds an inert note. It is advisory under the default policy and held by both agent
policies, on the base revision and here. Its twin, `office_menu_oleobject`, is an office
suite's popup-menu XML named `oleobject.xml`. On `0480d67` the twin was advisory and held by
both agent policies. It is now clean, with no findings, under every policy.

## What this gives up

A loose text file named like an OLE object, outside an `embeddings` folder, is no longer
reported by this check. It is not a compound file, so Office cannot activate it as an OLE
object, and the raw and text views still scan its bytes. Anything inside an `embeddings`
folder keeps the advisory, text included.

## What this does not show

- A rate. The installed files are the benign boundary that was measured, not a production
  false-positive rate.
- Office itself. Word and Excel were not run; the package layout comes from ECMA-376 and
  from the existing fixtures.
- The relationship and content-type checks #376 suggests. The check still reads names and
  sniffed bytes, not `[Content_Types].xml` or the package relationships. An object a package
  names under another folder is reported only if it is not text, which a real compound file
  never is.
