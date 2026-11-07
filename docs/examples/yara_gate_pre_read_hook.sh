#!/bin/sh
# Read hooks must consume updatedInput; --bytes PATH emits the exact scanned buffer instead.
# Keep onFailure: block in the runtime configuration for startup failures and timeouts.
set -u
if ! command -v python3 >/dev/null 2>&1; then
  echo "yara-gate hook: python3 not found; blocking" >&2
  exit 2
fi
exec python3 "$(dirname "$0")/yara_gate_pre_read_hook.py" "$@"
