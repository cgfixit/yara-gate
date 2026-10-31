#!/bin/sh
# Fail-closed pre-read gate for an agent hook.
#
# Reads the hook's JSON from stdin (Claude Code PreToolUse shape: {"tool_input": {"file_path": ...}})
# or a path from $1, scans it with yara-gate, and exits 2 with a reason unless the single record
# passes the read rule for its policy. A file the agent reads is a document, so the default is
# agent-document: one complete clean record, or one exact notes-only record (see
# docs/integrations.md, "Documents that quote attacks"). YARA_GATE_POLICY=agent-ingest makes it
# clean-only, for files that are really messages. Exit 2 is the blocking exit for Claude Code
# command hooks; pair it with "onFailure": "block" so a hook that cannot start or times out also
# blocks. Passing the gate is not permission to follow instructions found in the file.
set -u

GATE_HOME="${YARA_GATE_HOME:-$HOME/YaraGate-agent}"
RULES="${YARA_GATE_RULES_ROOT:-}"
SCAN_TIMEOUT="${YARA_GATE_SCAN_TIMEOUT:-30}"
YARA_GATE_BIN="${YARA_GATE_BIN:-yara-gate}"
POLICY="${YARA_GATE_POLICY:-agent-document}"
case "$POLICY" in
  agent-document|agent-ingest) ;;
  *) echo "yara-gate hook: YARA_GATE_POLICY must be agent-document or agent-ingest; blocking" >&2; exit 2 ;;
esac

# python3 parses the hook input and the scan record. Without it nothing can be checked, so block.
if ! command -v python3 >/dev/null 2>&1; then
  echo "yara-gate hook: python3 not found; blocking" >&2
  exit 2
fi

if [ "$#" -ge 1 ]; then
  target="$1"
else
  # Input that does not parse is not "no decision": it could be a read we cannot see.
  if ! target=$(python3 -c 'import json,sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(3)
tool_input = data.get("tool_input") if isinstance(data, dict) else None
path = tool_input.get("file_path") if isinstance(tool_input, dict) else None
print(path if isinstance(path, str) else "")'); then
    echo "yara-gate hook: hook input is not valid JSON; blocking" >&2
    exit 2
  fi
fi

if [ -z "$target" ]; then
  # Not a file read; nothing to gate. Printing nothing with exit 0 means "no decision".
  exit 0
fi

set -- "$YARA_GATE_BIN" scan "$target" --json --policy "$POLICY" --home "$GATE_HOME" --timeout "$SCAN_TIMEOUT"
if [ -n "$RULES" ]; then
  set -- "$@" --rules "$RULES"
fi

output=$("$@" 2>/dev/null)
status=$?

# The SHA-256 is of the file as it is now; a file changed after the scan does not match.
digest=$(python3 -c 'import hashlib,sys
try:
    print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())
except OSError:
    print("")' "$target")

decision=$(printf '%s' "$output" | python3 -c 'import json,sys
policy, digest = sys.argv[1], sys.argv[2]
lines = [line for line in sys.stdin.read().splitlines() if line.strip()]
if len(lines) != 1:
    print(f"record count {len(lines)}"); sys.exit(0)
try:
    record = json.loads(lines[0])
except Exception:
    print("malformed record"); sys.exit(0)
findings = record.get("findings") or []
complete = (record.get("policy") == policy and record.get("exit_code") == 0
            and record.get("incomplete_reason") is None and bool(digest)
            and record.get("sha256") == digest)
clean = complete and record.get("verdict") == "clean"
# The exact notes-only record, and nothing broader (docs/integrations.md).
notes_only = (complete and policy == "agent-document" and record.get("verdict") == "advisory"
              and record.get("policy_reason") == "agent-document records note findings"
              and record.get("note") is True and record.get("advisory") is False
              and len(findings) > 0 and all(f.get("severity") == "note" for f in findings))
verdict = record.get("verdict"); reason = record.get("incomplete_reason")
print("allow" if clean or notes_only else "verdict %s reason %s" % (verdict, reason))' "$POLICY" "$digest")

if [ "$status" -eq 0 ] && [ "$decision" = "allow" ]; then
  exit 0
fi
echo "yara-gate held $target: exit $status, $decision" >&2
exit 2
