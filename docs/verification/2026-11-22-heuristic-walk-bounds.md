# Whole-file walks beside YARA: the deadline, and one finding per stray joiner

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container with 4 cores and 16 GB, running as root. Rules: a disposable copy of the
shipped `rules/local` (89 rules), no vendor packs. Every input was synthetic and inert,
built in memory and scanned with `scan_bytes`. Every run below is a direct run on this
container; nothing here is hosted CI.

## What was wrong

The scanner's own loops are meant to stop at the scan deadline. Five walks beside the YARA
pass read a whole unit without looking at it, so a file shaped for one of them kept a scan
running long after its deadline. One of them also built a finding per character.

The leads came from a read-only sweep of the readers and heuristics for a loop with no
bound and no look at the deadline. Each was reproduced on the base before any edit.

## Reproduced on the base

A 16 MiB input and a 2 second deadline, so that the overrun is visible beside a control.
Every row but the control's changed cell ended `incomplete` with `timeout`, on the base and
on the change: the base found out when the walk returned.

| Input | Walk | Base | Changed |
| --- | --- | --- | --- |
| Ordinary prose (control) | none | 2.07 s | 1.91 s, clean |
| `%PDF-1.7` and `/a` repeated | `_pdf_name_span`, once for each of seven names | 27.39 s | 2.00 s |
| The same, ending `/OpenAction 1 0 R` | the above and `_open_action_is_goto` | 32.00 s | 2.00 s |
| `%PDF-1.7`, `Encr`, and `a ` repeated | `pdf_encrypted` | 10.44 s | 2.00 s |
| U+200D repeated | `joiner_findings` | 23.39 s, 5,592,406 findings | 1.50 s |
| `MZ` repeated | `embedded_exec_offset` | 5.27 s | 2.00 s |

With the default 30 second deadline:

| Input | Base | Changed |
| --- | --- | --- |
| One stream whose `/Filter` array holds 180 references, in a 16 MiB PDF | 36.78 s, incomplete `timeout` | 30.10 s, incomplete `timeout` |
| The same PDF with a direct `/Filter /AHx` (control) | 1.93 s, clean | 1.96 s, clean |
| 4 MiB of U+200D | 7.04 s, advisory, 1,398,102 findings, 440 MiB peak | 1.64 s, advisory, 101 findings |
| 16 MiB of U+200D | 23.88 s, advisory, 5,592,406 findings, 1,564 MiB peak | 2.71 s, advisory, 101 findings, 177 MiB peak |
| 100 MiB of U+200D | not run: about 94 MiB of memory per MiB of input on the two rows above | 8.52 s, advisory, 101 findings, 261 MiB peak |
| 1 MiB of U+200D, size of the compact report | 59,399,309 bytes | 17,570 bytes |
| 1 MiB of `&zwj;` in an HTML paragraph, size of the compact report | 37,922,321 bytes | 18,704 bytes |

Every other invisible-character signal already reported once per view: 1 MiB of U+200B is
two findings and a 1,069 byte report, on the base and on the change.

A filter reference costs one regular-expression pass over the file, about 0.2 s at 16 MiB.
The dictionary window holds about 580 of them, and the intake limit is 100 MiB.

## The change

- `joiner_findings` reports a reading's first 100 stray joiners (`MAX_JOINER_FINDINGS`),
  each at its own offset, and stops. It walks the joiners, not every character, and looks
  at the deadline every 4,096 of them. A file under the cap reports what it did before.
- `pdf_token_findings` finds the seven action and embedding names in one pass over the
  names (`_pdf_name_spans`) and looks at the deadline every 4,096 names. The seven-pass
  version read a file of names seven times.
- `_open_action_is_goto`, `pdf_encrypted`, and `embedded_exec_offset` take the same `check`
  and look every 4,096 names, tokens, or candidate headers. The three executable searches
  share one loop (`_header_offset`).
- `_pdf_resolve` takes the scan's `Budget` and checks it before each pass over the file for
  a reference it has not met.
- `scanner.py` passes `budget.check` to the joiner check and to the name check on inflated
  views. `heuristic_findings` already had it and now hands it on.

No rule id, severity, view, or verdict changed. The one report that differs is a reading
with more than 100 stray joiners, which lists the first 100.

## Measured: the name walk

`pdf_token_findings` alone, base beside changed in one process, best of three, on the
timing tripwire's own 4 MiB PDFs. The findings were equal in every row.

| Input | Base | Changed |
| --- | --- | --- |
| `pdf-contents-refs.pdf` | 2.146 s | 0.317 s |
| `pdf-page-objects.pdf` | 1.072 s | 0.158 s |
| `pdf-page-fonts.pdf` | 1.063 s | 0.162 s |
| `pdf-font-keys.pdf` | 1.021 s | 0.170 s |
| `/a` repeated | 6.268 s | 0.957 s |

## Checks

| Check | Result |
| --- | --- |
| The tables above, base then changed | as shown |
| `joiner_findings`, changed against the base function, 40,000 random texts (joiners, emoji, Persian and Devanagari letters, variation selectors, tag characters; 22,062 with findings, 78 over the cap) | equal up to the cap; every reported offset is a joiner in the UTF-8 text |
| `pdf_token_findings` and `pdf_encrypted`, changed against base, 60,000 random token sequences (45,490 with findings; names spelled with `#xx`, in strings, comments, and streams) | equal |
| `embedded_exec_offset`, changed against base, 60,000 random blobs (24,003 with a header) | equal |
| Code sweep: 12,005 files already on this machine (9,000 text and source files, 3,000 binaries, archives, and images, and the five documents found, each at most 2 MiB), scanned under `default` and `agent-ingest` with the base source and with the changed source | no file changed verdict, incomplete reason, or any finding's rule, offset, length, severity, view, or member path. The most stray joiners in one reading were 73 (`/usr/share/mime/packages/libreoffice.xml`), under the cap |
| `check_worst_case_timing.py`, 104 inputs | pass; the slowest took 6.7 s (`pdf-font-readings-winansi.pdf`). The 101 inputs the base has kept every verdict and reason; its 28 PDFs summed 95.1 s on the base and 81.4 s on the change, one run each, where inputs this change does not touch moved by up to 0.6 s either way |
| Three inputs added to it, 4 MiB each: `text-stray-joiners.txt` (6.74 s on the base, 1.64 s), `pdf-name-run.pdf` (10.1 s on the base, over the 10 s ceiling; 4.33 s), `pdf-encrypt-tokens.pdf` (6.2 s on both; the annotation reader's token cap ends it) | pass on the change |
| `probe_rule_coverage.py --verify` | passed; outcomes equal to the base run |
| `scripts/record_pages_demo.py --baseline web-demo/recordings.json` at `d6ec6a2` | outcomes match the reviewed baseline: 93 scenarios under 3 policies |
| `yara-gate conform` | 94 fixtures, 282 checks, 0 changed verdicts, 0 changed findings |
| `measure_precision.py` | the table is the base's: 4 of 328 files with findings |
| `check_rule_pairs.py`, `probe_detection_gaps.py`, `lint_rules.py` | pass; output equal to the base run |
| Eight new test cases in `tests/test_heuristics.py` and `tests/test_scanner.py` | seven fail on the base source (the two joiner cases at the import of `MAX_JOINER_FINDINGS`); the one that pins the unchanged name order and offsets passes on both |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts` | pass |
| `check_doc_links.py`, `check_text_controls.py` | pass |

## Browser

Headless Chromium through the preinstalled Playwright, against
`yara-gate demo --port 0 --rules <disposable copy of rules/local>` on the changed source.
The page was not edited; this is the changed scanner behind the real workbench.

| Step | Observed |
| --- | --- |
| Paste 20,000 U+200D (60 KB) under `agent-ingest`, **Scan** | 200, `block`, 101 findings (100 `heuristic_invisible_joiner`, one `agent_invisible_run`), a 14,118 byte response |
| **Run every pair** under `agent-ingest` | 45 of 45 attacks with a finding, 45 of 45 held, 45 of 45 twins clean, 0 findings on twins, 2 of 2 unreadable inputs incomplete; 92 of 92 match the reviewed expectation |
| Console | no errors |

The same paste was not sent to the base source in a browser.

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.

## Left as it is

- `pdf_encrypted` keeps every token of a dictionary until it closes. 100 MiB of
  `%PDF-1.7 Encr << ab ab ab` now stops at the deadline (30.45 s, incomplete `timeout`) with
  a 1,122 MiB peak. Bounding the list means deciding what a dictionary too long to hold
  answers, encrypted or not, and that changes a verdict either way, so it is left to the
  maintainer.
- A filter array of references still costs a pass over the file for each one, up to the
  deadline. An index of object headers built in one pass would make it one pass in all, as
  `PdfRawObjects.prime` does for `/OpenAction`. It was not built here: the deadline is now
  kept, and no ordinary PDF was found that names its filters by reference.
- 16 MiB of `\x7fELF` took 2.83 s against a 2 second deadline on the base and 3.15 s on the
  change. The time is outside these walks and was not traced; the deadline does not preempt
  a YARA pass or a third-party parser.
