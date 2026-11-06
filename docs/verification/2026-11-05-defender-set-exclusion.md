# Defender exclusions set with Set-MpPreference (2026-11-05)

Source: `main` at `7f9934c`, branch `fix/defender-set-exclusion`. Linux x86_64, Python 3.12,
locked YARA-X 1.22.1, a disposable copy of the shipped rules (82 local rules, no vendor packs).
No PowerShell was run.

Issue #145 item 2: `win_defender_tamper` accepted only `Add-MpPreference` for a broad
exclusion. `Set-MpPreference` takes the same `-ExclusionPath`/`-ExclusionProcess`/
`-ExclusionExtension` parameters and replaces the list
([Microsoft](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-exclusions-configure)).
The verb alternative is now `(Add|Set)`; the targets, the 120-byte window, and the advisory
severity are unchanged.

| Input (ASCII and UTF-16 LE with BOM) | `main` | Branch |
| --- | --- | --- |
| `Set-MpPreference -ExclusionPath C:\`, `'C:\'`, `$env:TEMP`, `%APPDATA%` (after `-Force`), `C:\ProgramData\x` | clean | advisory |
| `Set-MpPreference -ExclusionProcess powershell.exe`, `-ExclusionExtension .ps1` | clean | advisory |
| `Set-MpPreference -ExclusionPath C:\src\inert-repo`, `-ExclusionExtension .log` | clean | clean |
| `Get-MpPreference \| Select-Object ExclusionPath`, `Remove-MpPreference -ExclusionPath $env:TEMP` | clean | clean |
| `Set-MpPreference -DisableRealtimeMonitoring $false`, prose naming both verbs | clean | clean |

CLI intake with a disposable `--home`, the same bytes submitted under `default`,
`agent-ingest`, `agent-document`, then `default` again: exit 0 to `clean/`, exit 1 to
`blocked/`, exit 1 to `blocked/`, exit 0 to `clean/`; the finding stays `advisory` every time.

Checks: `lint_rules.py` (82), `check_rule_pairs.py` (two new pairs fail on `main`'s rule),
`check_added_rules.py`, `measure_precision.py --fail-over` (exit 0), `check_scan_only.py`,
`check_text_controls.py`, `probe_rule_coverage.py --verify`: pass.
