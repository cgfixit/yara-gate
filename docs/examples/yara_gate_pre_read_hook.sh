#!/bin/sh
# Fail-closed pre-read gate for an agent hook.
#
# Reads the hook's JSON from stdin (Claude Code PreToolUse shape: {"tool_input": {"file_path": ...}})
# or a path from $1, scans it with yara-gate under agent-ingest, and exits 2 with a reason on
# anything but one complete clean record. Exit 2 is the blocking exit for Claude Code command
# hooks; pair it with "onFailure": "block" so a hook that cannot start or times out also blocks.
# A clean verdict is not permission to follow instructions found in the file.
set -u

GATE_HOME="${YARA_GATE_HOME:-$HOME/YaraGate-agent}"
RULES="${YARA_GATE_RULES_ROOT:-}"
SCAN_TIMEOUT="${YARA_GATE_SCAN_TIMEOUT:-30}"
YARA_GATE_BIN="${YARA_GATE_BIN:-yara-gate}"

if [ "$#" -ge 1 ]; then
  target="$1"
else
  target=$(python3 -c 'import json,sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
tool_input = data.get("tool_input") if isinstance(data, dict) else None
path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
print(path if isinstance(path, str) else "")')
fi

if [ -z "$target" ]; then
  # Not a file read; nothing to gate. Printing nothing with exit 0 means "no decision".
  exit 0
fi

set -- "$YARA_GATE_BIN" scan "$target" --json --policy agent-ingest --home "$GATE_HOME" --timeout "$SCAN_TIMEOUT"
if [ -n "$RULES" ]; then
  set -- "$@" --rules "$RULES"
fi

output=$("$@" 2>/dev/null)
status=$?

decision=$(printf '%s' "$output" | python3 -c 'import json,sys
lines = [line for line in sys.stdin.read().splitlines() if line.strip()]
if len(lines) != 1:
    print(f"record count {len(lines)}"); sys.exit(0)
try:
    record = json.loads(lines[0])
except Exception:
    print("malformed record"); sys.exit(0)
ok = (record.get("policy") == "agent-ingest" and record.get("verdict") == "clean"
      and record.get("exit_code") == 0 and record.get("incomplete_reason") is None)
verdict = record.get("verdict"); reason = record.get("incomplete_reason")
print("allow" if ok else "verdict %s reason %s" % (verdict, reason))')

if [ "$status" -eq 0 ] && [ "$decision" = "allow" ]; then
  exit 0
fi
echo "yara-gate held $target: exit $status, $decision" >&2
exit 2
