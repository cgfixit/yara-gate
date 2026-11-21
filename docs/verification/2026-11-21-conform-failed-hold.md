# A failed `conform` agreement line is never an admit

Date: 2026-11-21. Base: `main` at `78e26bb`. Engine: YARA-X 1.23.0, Python 3.12, x86_64 Linux
container running as root. Rules: the kit's bundled copy (89 rules), no vendor packs. Manifest
`e0f77f72e5cff1af`, unchanged. Every run below is a direct run on this container; nothing here
is hosted CI.

## The contract

[AGENTS.md](../../AGENTS.md) says that a record for other bytes is `failed` in `replay` and is
"never counted or proposed as an admit". `replay` proposes `hold` for every failed item.
`conform --agreement` runs each capture line through the replay core and then checks it
against the kit. Three of those checks mark a line `failed` after its extraction was scanned:
an unknown fixture id, an `original_sha256` that is not the fixture's, and a fixture the plain
pass never reached (`fixture was not scanned`). Each copied the extraction's own decision
through, so a clean extraction read `"decision": "admit"` on a line whose `status` and
`result` were both `failed`.

## Reproduced on the base

`yara-gate conform --export KIT`, then `docs/examples/conform_agreement.py KIT`. Its
`encoded_benign` line was taken three times: unchanged, with `source_id` set to
`no_such_fixture`, and with `original_sha256` set to 64 zeros. The three were passed to
`yara-gate conform --agreement CAPTURE`.

| Line | `status_reason` | `result` | `extraction`, base | `extraction`, changed |
| --- | --- | --- | --- | --- |
| 1, unchanged | (none) | `same` | `clean`, `admit`, `[]` | `clean`, `admit`, `[]` |
| 2, unknown id | `unknown fixture` | `failed` | `clean`, **`admit`**, `[]` | `clean`, `hold`, `[]` |
| 3, other bytes | `extraction is of other bytes` | `failed` | `clean`, **`admit`**, `[]` | `clean`, `hold`, `[]` |

Exit 2 and `CONFORM INCOMPLETE: 92 fixtures, 276 checks, 0 changed verdicts, 0 changed
findings` both times. `diff` of the two outputs: lines 2 and 3 differ in `decision` only. The
summary line differs in `detector_sha256` only, because that digest covers the package's
Python sources and `conform.py` changed. `agreement` counts are `{"failed": 2, "same": 1}`
both times.

## The change

`conform.agreement` builds these three lines through `_failed`, which sets the reason and the
extraction's `decision` to `hold`. It keeps the extraction's `verdict` and `rule_ids`, so a
reader can still see what the text scanned as. A line `replay` already marked `failed` keeps
replay's `hold` as before. The manifest does not move. `docs/conformance.md` gains a sentence
under agreement mode and a change-list row, because a committed `agreement.jsonl` that holds
such a line changes on that field.

## Checks

- `tests/test_conform.py`. The two failed-line tests now assert `hold` on every failed line,
  `clean` kept on the two that were scanned, and `admit` on the line that matched. They fail
  on the base source (2 failed) and pass on the change; the whole file gives 18 passed.
- `ruff check`, `ruff format --check .`, `mypy --strict src scripts`,
  `docs/verification/check_doc_links.py`, and `docs/verification/check_text_controls.py`
  pass.

Not covered: a consumer's real extractor output. The capture above is the shipped example
reader's, edited by hand.
