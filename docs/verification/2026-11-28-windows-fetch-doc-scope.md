# Windows fetch-and-launch documentary scope

Date: 2026-11-28. Base: `7e21413e905fe06690dfa07b0cc94890be42502c`.
macOS arm64, Python 3.12.12, YARA-X 1.24.0. The baseline and candidate
each compiled 89 bundled rules with no skipped rule files. Vendor packs
were absent. All script fixtures were scanned as data.

## Issue disposition

| [#322](https://github.com/cgfixit/yara-gate/issues/322) finding | Disposition |
| --- | --- |
| 1. Sync-folder link race | [#331](https://github.com/cgfixit/yara-gate/pull/331) checks source identity. [#356](https://github.com/cgfixit/yara-gate/pull/356) adds native Windows coverage of regular files and replacement during opening. Cloud placeholder and junction timing remain outside those checks. |
| 2. Legacy pickle inspection | [#329](https://github.com/cgfixit/yara-gate/pull/329) added protocol 0 and 1 inspection. [#357](https://github.com/cgfixit/yara-gate/pull/357) applied it to every filename and kept the opcode limits. |
| 3. Windows script-rule suppression | Scope the exemption to the individual indicator. See the comparison below. |
| 4. SMS handler concurrency | [#331](https://github.com/cgfixit/yara-gate/pull/331) limits active handlers. Public deployment still depends on the proxy and provider. |
| 5. Terminal control characters | [#330](https://github.com/cgfixit/yara-gate/pull/330) escapes control characters in `hunt` output. |
| 6. Pages deployment gate | [#330](https://github.com/cgfixit/yara-gate/pull/330) requires a successful CodeQL analysis of the commit. |

The earlier review left finding 3 open pending precision evidence.
[November 22 decision](2026-11-22-windows-fetch-doc-exemption.md)

## Rule change

Both rules previously used a single documentary exemption for the scanned unit.
The new conditions associate an introduction with its next matching reference:
`WScript.Shell` for the script-host rule and the downloader for the command rule.
The next reference starts a new scope. ASCII and UTF-16LE use separate lookups.
The command rule also recognizes a line-number gutter immediately before the
first downloader in an extracted, rendered code listing.
The shell-and-run distance and the command-chain patterns stay the same. Both
rule IDs stay advisory. A full match list can still produce an advisory rather
than lose a finding due to the YARA-X cap.

An introduction can still exempt the specific reference it introduces. Unmarked
quotations and legitimate download-and-launch instructions can produce an
advisory. Those are limits of lexical inspection. A finding's offset can point
to a reference that helps determine the exemption. Review the reported view
and surrounding text to see the full evidence.

## Detection and precision

- Matched two safe marker families across UTF-8, UTF-16LE with and without a
  BOM, the corresponding ZIP members, and all three policies. Across 252 candidate
  scans, both standalone and separately matched indicators were reported. The
  documentary-only controls and individually introduced quotations stayed clean.
  The reports kept advisory finding severity and the member ordinals and views.
- The installed wheel passed 12 inbox cases. Individual quotations reached
  `clean/` with exit 0. The mixed inputs reached `clean/` with advisory and
  exit 0 under default, and `blocked/` with exit 1 under both agent policies.
  The persisted files matched the report digest and reports omitted matched text.
- The 328 generated benign files yielded the same policy hold counts, 1 under
  default and 4 under each agent policy. Neither affected rule fired and all
  scans completed.
- The installed-text and public-source sweep compared 7,188 files and found
  zero changed findings or incomplete reasons. Roots were `/opt/homebrew/share`,
  `/usr/share`, `/usr/local/share`, [CSS-Exchange at a5a267f](https://github.com/microsoft/CSS-Exchange/tree/a5a267f752c719cc465613c47d33ba8f62c32340)
  and [PowerShell-Docs at aedd8ef](https://github.com/MicrosoftDocs/PowerShell-Docs/tree/aedd8efe1fece22f04e478c2521c3fccc17ab03d).
  The sweep selects text-like files up to 512 KiB and compares distinct rule IDs
  and incomplete reasons. Neither affected rule fired on this set.
- Seven independently authored pages were scanned as HTML and as text extracted
  with Python's `HTMLParser`, omitting scripts, styles, and page metadata.
  The first draft, `c5e6d5b`, added a `win_cmd_fetch_start` advisory in the
  extracted Atlassian guide. All three matched installation excerpts immediately
  follow a rendered line-number gutter. Recognizing that local formatting
  removes the added Windows finding in both the raw-text and folded-text views.
  The existing `script_download_execute` finding still gives advisory under
  default and block under both agent policies. The guide's original HTML still
  reports both rule IDs. All 42 comparisons across the 14 representations and
  three policies match `main` on finding IDs, severities, views, verdicts,
  exit codes, and incomplete reasons.
  [Atlassian installation](https://developer.atlassian.com/platform/teamwork-graph/twg-cli/getting-started/installation/)
  · [Enclave downloads](https://docs.enclave.sidechannel.com/agent/downloads.html)
  · [Intel WSL setup](https://docs.openedgeplatform.intel.com/dev/edge-ai-suites/ai-suite-retail/loss-prevention/wsl2/wsl2-setup.html)
  · [Windows curl](https://learn.microsoft.com/en-us/windows/curl/)
  · [ShellExecute](https://learn.microsoft.com/en-us/windows/win32/shell/shell-shellexecute)
  · [Microsoft HTA scripting](https://devblogs.microsoft.com/scripting/how-can-i-start-an-application-from-an-hta/)
  · [Microsoft XMLHTTP security guidance](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ms753790(v=vs.85))
- Scanning the entire [Windows signature fixture bundle](../research/windows-format-signatures.json)
  added both advisory rule IDs. It contains positive scanner fixtures and near-misses.
  The coverage probe passed the individual fixture expectations.

The corpus comparison found no new benign findings or holds. The checks
cover the sampled Windows scripts and documentation. A quotation outside
the recognized formats can still receive an advisory.

## Runtime and browser checks

- Rule lint, the fire and near-miss pairs, the match-cap probe, the rule coverage
  and detection-gap probes, and the installed `conform` command passed. The
  match-cap probe compared 3,635 flooded inputs without a blind spot. The
  conformance kit matched all 372 outcomes.
- The 4 MiB timing worker completed both quotation-heavy cases as clean in
  about one second each. The first MiB of each took about a quarter second.
  A direct 16 MiB scan of each case also completed clean within 10 seconds.
- The numbered-listing follow-up passed 180 direct scans across all policies,
  UTF-8 and UTF-16LE with and without BOM, LF and CRLF, and ZIP members. The
  listing alone was clean for the command rule. A separate match before or
  after it, a downloader mention between the numbering and the matching
  command, and incomplete numbering all reported at the matching raw offset.
  A separate inert match appended to the extracted guide also reported.
  The 4 MiB numbered-listing timing case completed clean within its time and
  scaling limits.
- Computer Use verified the packaged loopback demo's Windows command hold,
  its clean quotation control, and the empty input path. All 122 live
  `agent-ingest` outcomes matched the catalog, with no findings on 60 benign
  twins. The rebuilt static replay rendered the recorded rule compilation
  failure with exit 2.
- Native Windows and vendor packs were outside this local run. The current
  product ships a Python CLI and a browser demo.
