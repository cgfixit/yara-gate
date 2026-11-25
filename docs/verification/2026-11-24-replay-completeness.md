# Replay completeness for the shadow evaluation

November 24, 2026 ET. Compared `origin/main` at `7844faf` with the replay change
at `f10ff7f93c81` for [#294](https://github.com/cgfixit/yara-gate/issues/294).
The runs used macOS 27.2.1 arm64, Python 3.12.12, yara-gate 0.2.0, and locked
YARA-X 1.24.0. The shared ruleset compiled 89 bundled rules with zero skips.
The runs used disposable rules directories without vendor packs.

## Installed CLI

Built with `uv build --offline --wheel` and installed into a disposable
environment with frozen runtime dependencies. The installed and checked-out
`cli.py` files both hashed to
`fc45f55394a427841241beb8df406bc2213dcac6b35d0891746151ec4cb1c187`.
The wheel SHA-256 was
`00d10dd83f33deaab73b3037574242d9eef7060549fc4049cd9835212b811882`.

Ran `yara-gate replay - --rules RULES --no-timings` with and without
`--require-complete`. The baseline used the CLI installed by the locked
checkout environment. The candidate used the installed wheel.

| Inert input | Main exit | Candidate default exit | Candidate required exit |
| --- | ---: | ---: | ---: |
| Complete benign admit and synthetic detection hold, under different per-item policies | 0 | 0 | 0 |
| Blank capture | 0 | 0 | 2 |
| Malformed line followed by a complete item | 2 | 2 | 2 |
| Broken local rule, giving one truncated item | 0 | 0 | 2 |
| Non-matching rule added between two clean items, giving two identities | 0 | 0 | 2 |

For the last case, the parent process added the inert rule to the disposable
rules tree after reading the first envelope, then sent the second line.
Both items completed clean, and the summary reported `mixed_identities: true`.
Default and required output matched byte for byte on stdout in all five cases.
File and stdin output matched for the complete capture. Error counts appeared
on stderr in required mode, and the captured text was absent from output.

The focused pytest run passed four cases with
`pytest -q tests/test_replay.py -k 'cli_prints_envelopes or require_complete'`.
Ruff lint and format, `mypy --strict src scripts`, Markdown links, and the
text-control check passed. Full pytest, Windows execution, and vendor-pack
behavior are outside the local verification.

## Browser

Codex Computer Use opened the workbench from the installed wheel, served by
`yara-gate demo --port 0 --rules RULES` on loopback. The vendor-feed sample
returned block / exit 1 and its benign twin clean / exit 0. The displayed
YARA-X version and detector digest matched the installed CLI's replay
identity. The rendered agent-ingest catalog matched all 92 outcomes, with
45 clean twins, zero findings on those twins, and two incomplete scans.

Ran `scripts/record_pages_demo.py --output CAPTURE --baseline web-demo/recordings.json`
at the committed code revision. All 279 reviewed policy outcomes matched.
The four-file Pages build validated the refreshed recording and both JavaScript
modules passed `node --check`. Computer Use opened the rebuilt site on
loopback, showed `f10ff7f93c81` as recording provenance, and displayed the
recorded broken-rule case as incomplete / exit 2.

The browser checks exercise the live scanner and recorded Pages UI. The
installed CLI check exercises replay's exit behavior. The 200-task Harness
capture, cross-run identity checks, and outcome measurements still belong to
[#294](https://github.com/cgfixit/yara-gate/issues/294). These controls
measure synthetic cases only.
