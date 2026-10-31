# PDF action names inside stream bodies (raw view) — October 31, 2026

Baseline: `main` at `03e2404`. This change is based on `main`, not stacked on draft PRs #134 or
#136. Python 3.12.3, YARA-X 1.22.1, Linux x86_64 (root container). Shipped local rules only: 80
compiled, 0 skipped. No vendor pack was installed, no target was executed, nothing was fetched.
Every CLI scan used a fresh disposable `--home` and a fresh copy of `rules/local` as `--rules`.

## Defect reproduced on `03e2404`

The gap was first recorded under "Remaining gaps" in #136's stacked record
(`2026-10-31-pdf-image-grain-and-controls.md`, on `claude/youthful-carson-jd3o1k`). It also
reproduces on `main`. `pdf_findings` → `pdf_token_findings` → `_pdf_name_span` matched the seven
names in `PDF_TOKENS` anywhere in the raw bytes. A stream body that uses the
`[/ASCII85Decode /FlateDecode]` chain (ReportLab's default, `rl_config.useA85 = 1`) is
ASCII85 text. That alphabet includes `/` and letters, so pixel data can spell `/AA` or `/JS`
followed by a delimiter.

Inputs were built with ReportLab 5.0.1 `canvas.drawImage(..., pageCompression=1)` and Pillow
12.3.0. Both are system packages outside the locked environment and were used only to make
inputs. With `yara-gate scan - --name <file> --json`:

| File | `03e2404`, all three policies |
| --- | --- |
| `pyparsingClassDiagram_3.0.9.jpg` (re-saved as PNG), ASCII85 chain | `heuristic_pdf_AA@raw` block, exit 1 |
| `pyparsingClassDiagram_1.5.2.jpg` (re-saved as PNG), ASCII85 chain | `heuristic_pdf_JS@raw` block, exit 1 |
| Synthetic 1200x800 grainy horizontal gradient, ASCII85 chain | `heuristic_pdf_JS@raw` block, exit 1 |

The synthetic image here uses its own seed. It spells `/JS`, where #136's grain image spelled
`/AA`. The mechanism is the same. The Flate-only builds of the same three images
(`rl_config.useA85 = 0`) do not hit the PDF name check.

## Change

`heuristics.pdf_stream_bodies(data)` returns spans of stream bodies that no reader parses as
syntax. `pdf_findings` (raw view only) skips names that start inside them, for both reporting
and the `/OpenAction` page-open judgment. `pdf_token_findings` gains a keyword-only `skip`
argument. The `pdf-flate` view call is unchanged, so names in decoded content and object streams
are checked as before.

**`/OpenAction` and the `PdfObjects` lookup.** References still resolve against every
definition in the whole file. The scanner passes `PdfObjects(unit.data)` (unmasked), and a
direct `pdf_findings` call builds `PdfRawObjects(data)` from the original bytes. A definition
inside a stream body still counts, as before, so it can only make a reference harder to accept.
Only the set of `/OpenAction` *occurrences* changes: one inside a skipped body is no longer
reported or judged. So a page-open catalog plus image text that spells `/OpenAction` now gets the
note (`N2` below). Before, the pixel copy failed the page-open parse and the file blocked.

**When a body is skipped.** A body runs from the CRLF or LF after `stream` to the next
`endstream`. One walk from the start of the file skips strings and comments. It uses the same
lexer as `pdf_encrypted`. A body is returned only when all of these hold:

- its `stream` keyword follows an `N G obj` header and exactly one dictionary;
- that dictionary has no `/First` key and no `/Type /ObjStm`, so it is not an object stream
  (pdf.js and MuPDF read members of any stream with `/N` and `/First`, whatever its `/Type`);
- every `N G obj` match in the bytes, and every `trailer`, is one the walk itself read as a token.

A reader starts parsing fresh only at an object header or a `trailer`. So the last rule means no
reader entry point can fall inside a skipped body, or inside a region where the walk and a
reader disagree about string or comment state. The whole file is read as before ([] returned)
in any of these cases: a header inside an open dictionary or array; a `<` that is neither `<<`
nor a hex string (pdf.js reads `<…>` as hex and skips other bytes); a second `stream` in one
object; a `stream` keyword followed by CR alone or by anything other than CRLF or LF; no
`endstream`; or more than 500,000 top-level tokens. The walk runs only when the raw name pass
finds a name. Every fallback restores the old behavior. Skipping a body can only remove a
finding.

Not done: trusting `/Subtype /Image` or `/Filter`. Those labels are attacker-controlled, as
#136's record argues.

## Direct verification

### Controls (hand-built inert PDFs, CLI, default / agent-ingest / agent-document)

`PIX` is an ASCII85-chain image XObject whose text contains `/AA)`, `/JS(` and `/OpenAction]`.
JavaScript values are the literal `(x)`.

| File | `03e2404` | Head |
| --- | --- | --- |
| N1: names only in `PIX` | block ×3 | clean ×3 |
| N2: `/OpenAction [3 0 R /Fit]` in catalog + `PIX` | block ×3 | advisory / block / advisory (`OpenAction_goto` note) |
| N3: N1 with CRLF after `stream` | block ×3 | clean ×3 |
| N4: `/JS1 /AA_Notes /Launch-Report` in catalog + `PIX` | block ×3 | clean ×3 |
| C1: `/OpenAction <</S/JavaScript/JS(x)>>` in catalog + `PIX` | block | block (`OpenAction`, `JS`, `JavaScript`) |
| C2: real `/AA` in an incremental update after `%%EOF` | block | block (`AA`, `JS`, `JavaScript`) |
| C3: `stream` with no `endstream`, catalog action after it | block | block |
| C4: unfiltered `/Type /ObjStm` whose member holds `/AA` | block | block (`AA`) |
| C5: unfiltered stream with `/N /First`, no `/Type` | block | block (`AA`) |
| C6: fake `9 0 obj … stream` inside a comment after a real header | block | block |
| C7: fake header and `stream` inside a multi-line string in the catalog | block | block |
| C8: stray `(` between objects, `)` in a reader comment (walk desync) | block | block |
| C9: unterminated hex `<` before a fake header | block | block |
| C10: `7 0 obj` catalog inside a body (an xref could point there) | block | block |
| C11: `xref … trailer << /Root << … /OpenAction … >> >>` inside a body | block | block |
| C12: second `stream` in one object holding `/JS` | block | block |
| C13: CR alone after `stream`, `/AA` and `/JS` in the body | block | block |
| C14: `/#4AS` (escaped `/JS`) in the names tree | block | block (`JS`, `JavaScript`) |
| C15: `/AA` in a stream's own dictionary | block | block (`AA`, `JS`, `JavaScript`) |
| C16: `/OpenAction 5 0 R` → `/JavaScript` action, plus `PIX` | block | block (`OpenAction`) |
| C17: header inside an open catalog dictionary | block | block |

Every control keeps every token written in its dictionaries. Head removes only tokens that came
from `PIX` text: for example C1 loses `AA`, and C2, C4 and C5 lose `OpenAction`. N4 holds the
name-boundary contract from [pdf-name-boundaries.md](pdf-name-boundaries.md): suffixed names are
not features, and on base it blocked only on the pixel names.

### ReportLab image PDFs, `03e2404` against head (CLI, three policies)

| File | `03e2404` default / ingest / document | Head |
| --- | --- | --- |
| `pyparsingClassDiagram_3.0.9`, ASCII85 | block / block / block (`heuristic_pdf_AA@raw`) | clean / clean / clean |
| `pyparsingClassDiagram_1.5.2`, ASCII85 | block / block / block (`heuristic_pdf_JS@raw`) | clean / clean / clean |
| grainy gradient, ASCII85 | block / block / block (`heuristic_pdf_JS@raw`) | clean / clean / clean |
| `pyparsingClassDiagram_3.0.9`, Flate | advisory / block / block | unchanged |
| `pyparsingClassDiagram_1.5.2`, Flate | clean / clean / clean | unchanged |
| grainy gradient, Flate | advisory / block / block | unchanged |

The two Flate advisories are `agent_base64_blob@pdf-flate`. #136 addresses them and they are
untouched here. Across all 27 files × 3 policies (81 scans), 39 scans in 13 files changed. Each
change only removed findings that started inside a body, plus N2's page-open note. No scan was
incomplete on either side.

**Physical disposition** (inbox scan, disposable home): the ASCII85 `pyparsingClassDiagram_3.0.9`
build went to `blocked/` on `03e2404` (exit 1) and goes to `clean/` on head (exit 0). C1 goes to
`blocked/` on both.

### Cost

On the ReportLab files (0.9-1.6 MB), `pdf_stream_bodies` took 21-68 ms. That was mostly the
whole-file header and `trailer` checks. The walk is per token, so it is capped at 500,000
tokens. At that cap, a 20 MB dictionary of names or of tiny strings took 0.7-1.3 s before it
fell back. On 2,000 streams it took 0.05 s. A file with a name and a skipped body pays for a
second name pass. Separately, the existing raw name pass already takes about 40 s on a 20 MB
dictionary of 3.3 million names: 41.4 s on `03e2404` and 38.6 s on head. This change does not
make that worse.

## Commands

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
uv run python docs/verification/check_rule_pairs.py
uv run python docs/verification/measure_precision.py --fail-over
uv run ruff check src tests && uv run ruff format --check src/yara_gate tests
uv run mypy --strict src
uv run python docs/verification/check_text_controls.py
uv run pytest -q tests/test_heuristics.py tests/test_scanner.py tests/test_filetype.py
```

- Probe on the head working tree (source revision field `03e2404` plus the uncommitted change):
  passed, 0 failures; 531 library, 55 CLI and 109 benign observations; 3 failure paths.
- Rule pairs: passed (105 rules).
- Precision: 310 files, 0 incomplete, exit 0, on both sides. Apart from the timing line, the
  report is byte-identical to `03e2404`'s. Three head runs took 0.63-0.82 s.
- Ruff, format, strict mypy, and the text control check (200 files): clean. `yara-gate
  selftest` with a disposable `HOME`: `SELFTEST PASS`.
- Tests: `test_pdf_names_in_a_stream_body_are_data` (LF and CRLF) fails on `03e2404` and passes
  on head. The 14 cases of `test_pdf_names_outside_a_verified_body_still_block` pass on both, so
  detection is kept. The focused files pass: 203 tests. The broad suites are left to hosted CI.

## Remaining gaps

- **Strict fallback.** A file with a header-like `N G obj` or the word `trailer` inside a string,
  a comment, or any body is read whole. So is a file with a header mid-dictionary, a stray `<`,
  or more than 500,000 tokens. Such files keep the old false positive if their image text spells
  a name. None of the ReportLab files hit a fallback.
- **The walk models readers' lexing, not every reader's recovery.** The guards cover the desync
  shapes in C6-C13 and C17. A reader with recovery rules beyond "start at a header or `trailer`"
  could in principle parse bytes the walk calls a body. pdf.js and MuPDF reconstruct from the
  same two anchors.
- **Object streams whose first filter is not FlateDecode** (LZW, ASCII85-first chains) are still
  not decoded by the `pdf-flate` view, as before. Their raw bodies are never skipped, because
  `/First` keeps them whole.
- **Raw YARA rules** still read stream bodies. This change covers only the `heuristic_pdf_*` name
  check.
- No production false-positive rate is claimed. The image set is small and synthetic.
