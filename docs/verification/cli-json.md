# JSON CLI integration — October 13, 2026

Baseline: `2e8c85ad2fa22e456345efa6071e778326bf29cc`. Runtime: Python 3.12.12,
YARA-X 1.21.0, macOS ARM64. Baseline `yara-gate scan ... --json` exits 2 with
`No such option: --json`. The candidate adds an opt-in JSON Lines output path
using the same serializer as persisted JSON reports. Human output is unchanged.

Six focused checks invoke the actual installed CLI entrypoint with candidate
imports, copied local rules, and disposable gate homes:

| Check | Observed result |
| --- | --- |
| Advisory file with a newline in its filename | One parseable JSON line, identical to the saved report; no matched content; source remains in place |
| Directory containing clean, blocked, and incomplete inputs | Three records with exit codes 0/1/2; process exit 2; all source files remain |
| Identical-byte inbox resubmissions under default → agent-ingest → default | Advisory/0/clean → block/1/blocked → advisory/0/clean; finding severity preserved |
| Missing path | Exit 2, diagnostic on stderr, no fabricated stdout record |
| Active local compilation error | Structured incomplete record, exit 2 |
| Outside symlink | Structured rejection, exit 2; target content not disclosed or modified |

Command: `uv run pytest -q tests/test_cli_json.py` — six passed. These tests
exercise subprocess output, disk reports, policy, and physical disposition at
the integration boundary. No full local suite was run. Ruff lint/format and
`uv run mypy --strict src` passed.

A wheel was built and installed without dependencies into an owned temporary
target, using the locked environment for dependencies. Verified imports came
from that installed target. Its CLI scanned an inert advisory with `--json
--policy agent-ingest`, returned block/exit 1, and emitted a JSON object equal
to the saved report. Bundled rules were loaded beneath a disposable rules root.
Wheel SHA-256:
`428f90dcd965a6b126364498216b7127e619e0183a8019e2070ecb840f69b879`.

No target was executed or URL fetched. No operator gate home, external consumer,
native Windows runtime, or live provider integration was exercised. The
[integration contract](../integrations.md) explains empty output, nonzero exits,
scan-time paths, and modification between scanning and reading. Hosted CI
supplies broad regression and platform coverage.
