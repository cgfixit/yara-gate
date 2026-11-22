# The JSON structure budget on text the comment reader produces

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container running as root. Rules: a disposable copy of the shipped `rules/local` (89
rules), no vendor packs. Every run below is a direct run on this container; nothing here is
hosted CI. No file here is executed, and the JSON is built in memory.

## The lead

`mcp_tool_findings` in `heuristics.py` reads the structure budget of `jsonbounds.py` on the
file as written, then decodes it. When strict JSON fails it removes comments and trailing
commas with `_jsonc` and decodes what is left. Nothing read the budget on that second text.

The two passes do not pair quotes the same way. The budget lets a string run over a line
break; `_jsonc` does not take a quote as the start of a string when a line break comes before
the next quote. So in

```text
[" /* <line break>" */ ", [[],[],[], ... ], "command"]
```

the budget sees a string that holds `/*`, then a string that holds the array. `_jsonc` sees a
comment from `/*` to `*/` and removes it with the second quote inside. The decoder is handed
`["   ", [[],[],[], ... ], "command"]` and builds the array.

## Reproduced on the base

`mcp.json`, scanned with `scan_bytes`, default and `agent-ingest` (the same result under both
unless shown):

| Input | Base `bed66d4` | Change |
| --- | --- | --- |
| `["command", <300,000 empty arrays>]`, 900,014 bytes (control) | incomplete, `mcp json exceeds structure limit`, peak 1.5 MiB | the same |
| the same array behind the comment, 900,028 bytes | **clean**, complete; `json.loads` built 300,004 values; peak 21.9 MiB | incomplete, `mcp json exceeds structure limit`; `json.loads` not called on the second text; peak 4.4 MiB |
| 200 nested arrays behind the comment | incomplete, `mcp json exceeds walk limit` (the walk's own cap, after the tree was built) | incomplete, `mcp json exceeds structure limit` (before it is built) |
| `{"command": "bash", ...}` behind the comment | advisory `heuristic_mcp_shell`; block under `agent-ingest` | the same |
| `// servers` and trailing commas around an ordinary server entry | clean | the same |
| `/* not a comment */` inside a description string | clean | the same |

Peaks are `tracemalloc` peaks for one scan. The comment reader takes files up to 1 MiB, so
the miss was bounded: about 350,000 values and some 22 MiB, three and a half times the
budget. It was a budget that did not hold and a scan that reported complete, not an
unbounded allocation.

## The change

After `_jsonc` returns text, `mcp_tool_findings` calls `check_json_structure` on it before
`json.loads`, decoded as `json.loads` decodes bytes. A `JsonLimit` there is the existing
`mcp json exceeds structure limit`. The first read is unchanged: it still decides whether a
file over 1 MiB needed the comment reader (`mcp json exceeds comment limit`). The cost is one
more linear pass over at most 1 MiB, only for a file strict JSON refused.

## Checked against ordinary files

- 40,000 generated documents (`mcpServers` trees with comments of six shapes, trailing commas,
  comment openers inside strings, escaped quotes, URLs): 38,622 were read through the comment
  reader, and every result line (rule ids and reason) is byte-identical between the base and
  the change. 4,563 report `heuristic_mcp_shell`, 196 `heuristic_mcp_hidden_instruction`, 56
  both.
- 2,889 installed `.json` files under `/usr`, `/opt`, `/etc`, `/home`, and `/root`: identical.
  None of them reaches the comment reader on this machine, so this sweep shows only that the
  strict path did not move.
- `tests/test_jsonbounds.py::test_budget_reads_the_text_the_comment_reader_hands_the_decoder`
  fails on the base source (`object tree was allocated before its budget`) and passes on the
  change; the file gives 19 passed.

Checks: `ruff check`, `ruff format --check .`, `mypy --strict src scripts`,
`docs/verification/check_added_rules.py`, `docs/research/probe_detection_gaps.py --verify`,
`docs/research/probe_rule_coverage.py --verify`, `yara-gate conform`,
`docs/verification/check_doc_links.py`, and `docs/verification/check_text_controls.py` pass.

## What this does not cover

- Whether `_jsonc` reads such a file as VS Code's jsonc-parser does. The file above is not
  valid JSON with comments (a string with a raw line break), and what a tolerant parser makes
  of it was not measured. This change bounds what the gate decodes; it does not change what
  the gate decodes.
- Process memory. The budget bounds the tree, as before. The 900 KB input, its decoded text,
  and the comment reader's copy are still held.
- The notebook and Keras readers. They decode the text the budget read, so there is no second
  text to check.
