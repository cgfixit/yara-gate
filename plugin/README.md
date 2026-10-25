# yara-gate plugin 0.2.0

MCP server + skill wrapping [cgfixit/yara-gate](https://github.com/cgfixit/yara-gate) `scan --json` (verified against upstream `80b3319`, yara-gate 0.2.0, YARA-X 1.22.0).

Requires `yara-gate` (Python >= 3.12) on PATH, or `YARA_GATE_BIN=/path/to/yara-gate`. Server itself is stdlib-only Python 3.
Env: `YARA_GATE_HOME` (gate root; default `$PLUGIN_DATA/gate` or `~/.cache/yara-gate-plugin/gate`), `YARA_GATE_RULES`.

Tools -> `{ allowed, exit_code, records: [yara-gate JSON report], stderr }`:
- `scan_file` — one file
- `scan_dir` — every file under a folder (symlinks not followed)
- `scan_content` — in-memory text via `yara-gate scan - --name NAME`; `allowed` also requires the record sha256 to equal sha256(UTF-8 content)

0.2.0: adds `scan_content`; report records now carry `compiled_rules`, `tool_version`, `scan_seconds`.

In this repository the plugin root is `plugin/`. It is not published to the Cursor
Marketplace or cursor.directory. Hosts that load a local Agent Plugin can point at
this directory. The server is also a stdio JSON-RPC process: `python3 server/server.py`
with `yara-gate` on `PATH` (or `YARA_GATE_BIN`).

`mcp.json` sets `cwd` to `${PLUGIN_ROOT}`. Agent Plugins 1.0.0 says a client expands
that to the plugin root (and the same for `${PLUGIN_DATA}`). Cursor's plugin reference,
checked 2026-10-25, expands `${CURSOR_PLUGIN_ROOT}` and does not expand `${PLUGIN_ROOT}`.
This tree keeps the spec form so the manifest matches the 1.0.0 schema. Stdin JSON-RPC
does not use `cwd`.
