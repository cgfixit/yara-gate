# Attachment signature research — October 13, 2026

The research and detector-evaluation window was 01:51–02:02 America/New_York
(about 11 minutes), against `main` at `2e8c85ad2fa22e456345efa6071e778326bf29cc`.
Sources, the locked engine, existing coverage, inert encodings/containers, and
benign collision boundaries were examined together. No live malware, target
execution, referenced-URL retrieval, or vendor-pack installation was used.

## Selected additions

Four advisory rules in three new `.yara` files extend the shipped pack from
16 to 20 rules. These are original local detection expressions; upstream
research supplies technique and format references, not copied rule bodies.

| Rule | Required combination | Benign boundary |
| --- | --- | --- |
| `script_regsvr32_remote_scriptlet` | Regsvr32 command, HTTP(S) `/i:` argument, and `scrobj.dll` within one bounded command region | Ordinary DLL registration, local scriptlets, unrelated lines/commands, and similarly named executables do not qualify |
| `script_rundll32_mshtml` | Rundll32, JavaScript protocol, and the MSHTML `RunHTMLApplication` entrypoint in a bounded fragment | Normal Control Panel calls, different exports, and separate-line strings do not qualify |
| `shortcut_powershell_encoded` | Parsed PowerShell/pwsh target, encoded command, and hidden-window or bypass arguments | Normal scripts, encoding without the second flag, misleading descriptions, and different targets do not qualify |
| `shortcut_mshta_remote` | Parsed MSHTA target and an HTTP(S) argument | Local HTA files, descriptions naming MSHTA, and URLs passed to other targets do not qualify |

MITRE documents Regsvr32's remote scriptlet behavior and Rundll32's MSHTML
script entrypoint. The Regsvr32 detector requires the scriptlet loader as well
as the URL to avoid treating ordinary registration as the same behavior.
[Regsvr32](https://attack.mitre.org/techniques/T1218/010/),
[Rundll32](https://attack.mitre.org/techniques/T1218/011/),
[LOLBAS Regsvr32 examples](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/).

Shortcut targets and arguments are separate binary fields. A flat command
pattern can miss that separation or confuse description text with a target.
The new rules use the YARA-X `lnk` module's `relative_path`, `local_base_path`,
`common_path_suffix`, and `cmd_line_args`. The locked 1.21.0 engine compiled and
executed these expressions, including fixtures with each target field and
ANSI/UTF-16 StringData. Missing fields participate as undefined values, so
alternative populated target fields can still match through `or`.
[YARA-X LNK module](https://virustotal.github.io/yara-x/docs/modules/lnk/),
[undefined values](https://virustotal.github.io/yara-x/docs/writing_rules/undefined-values/),
[Microsoft Shell Link format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/747629b3-b5be-452a-8101-b9a2ec49978c).

Microsoft and Unit 42 describe interpreter arguments as a shortcut delivery
surface. Their research also shows why this pack is deliberately narrower
than general LNK-malware detection: target-ID lists, appended payloads, and
other interpreters require separate coverage. The rules do not resolve a
Windows shortcut or prove which target Windows would ultimately select.
[Microsoft WinLNK description](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=Trojan%3AWin32%2FWinLNK%21MSR&ThreatID=2147761572),
[Unit 42 LNK analysis](https://unit42.paloaltonetworks.com/lnk-malware/).

## False-positive controls and remaining limits

All four rules are advisory: default intake reports them and exits 0;
`agent-ingest` holds them as block/exit 1 while preserving finding severity.
Legitimate hidden, encoded administrative PowerShell and security documents
quoting the exact command patterns can match. Microsoft documents encoded
commands as an ordinary PowerShell feature; the extra context limits noise
without establishing malicious intent.
[PowerShell command-line reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe).

The fixture corpus deliberately includes normal registration, Control Panel
calls, literal PowerShell, local HTA files, misleading descriptions, executable
suffix lookalikes, insufficient signal combinations, distance limits, and
separate command lines. It also covers UTF-16LE/BE, HTML entities, ZIP/gzip,
renamed inputs, and parsed target fields. The labeled JSON stores inert input
recipes, not downloaded samples or executable scripts.

No new rule matched the 28 designed benign near-misses or an additional 109
benign files (nine shipped fixtures and 100 Python 3.12.12 standard-library
sources). This is a finite local result, not an estimated production
false-positive rate. There is no independent held-out malware corpus or native
Windows execution evidence. An exact quoted attack is an expected advisory
collision; it must not be counted as proof of semantic maliciousness.

Encoded strings shorter than 40 or longer than 512 base64 characters, dynamic
construction/expansion, wrapped interpreter chains, target-ID-list-only LNKs,
malformed LNKs whose fields cannot be parsed, local scriptlets, and arbitrary
URI protocols are outside these new rules. Existing archive/size/deadline
handling remains in force; a third-party parser still lacks hard preemption.

## Evaluated but deferred

| Candidate | Reason and next useful evidence |
| --- | --- |
| npm install-hook rules | Lifecycle hooks are legitimate execution surfaces. The existing downloader/executor rule already catches the simple pipe-to-shell example. Add parsed JSON context and a representative package corpus before treating lifecycle names as signals. [npm lifecycle documentation](https://docs.npmjs.com/cli/v11/using-npm/scripts/) |
| DDE/Office active-content expansion | DDE server lookup and server launch are distinct behaviors. Raw keywords do not establish execution. A future change needs structured field analysis and benign business documents. [Microsoft DDE settings](https://learn.microsoft.com/en-us/troubleshoot/microsoft-365-apps/excel/security-settings) |
| Broad private-key/secret signatures | Presence of intentionally stored sensitive material is a data-handling decision, not evidence of malware. Define a separate consumer policy before adding broad advisories to the default pack. |
| More prompt-injection phrase lists | Current rules already cover selected phrases, authority/action claims, secret transfer, and encodings. More isolated words would expand collisions without establishing whether an agent obeyed the input. [OWASP prevention guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) |
| In-memory compilation reuse | Requires a reliable invalidation contract for changed local/vendor sources. This pass leaves compilation identity checks intact; no speed claim is made for a large installed vendor pack. |

## Executed evidence

- Baseline: all 50 new fixture inputs were clean, including the 22 positive
  detection cases. Candidate: all 22 positive cases advisory; all 28 benign
  near-misses clean, with exact expected new rule IDs.
- Full maintained direct probe: 120 library cases, 24 actual CLI operations,
  20 compiled rules, no compile errors/skips; required-rule, vendor-skip, and
  expired-deadline paths passed. Member/derived provenance and SARIF offsets
  were checked. Identical-byte policy resubmissions retain the existing gate
  contract.
- Additional benign corpus: 109 completed clean scans, zero new signatures.
- Each new source compiled separately with zero YARA-X compiler warnings.
- Two 1 MiB repeated benign-command workloads stayed clean and finished in
  0.139 s and 0.134 s. Three larger text workloads showed no observed slowdown
  against the recorded baseline; these small timing samples are not a
  statistical throughput claim.
- A built wheel was installed into a disposable target directory. Its imports
  and bundled-rule path were verified. The packaged 20-rule pack compiled with
  no skips, and all four families matched through both the library and installed
  CLI with strict-policy exit 1. Wheel SHA-256:
  `145dc44c9202a98f3fc20774b93b998a7150a99873f31b58534673aea9c1ef00`.
- Ruff lint/format passed for the changed Python probe. No production Python or
  workflow changed. Broad pytest/selftest and Ubuntu/macOS coverage run in CI.

[Compact evidence and corpus identity](../verification/delivery-signatures.json)
records hashes, counts, and timing measurements. Regenerate detailed observations:

```sh
uv sync --frozen --group dev
uv run python docs/research/probe_rule_coverage.py --verify --benign-stdlib
```

The optional standard-library corpus is selected deterministically from the
current Python runtime. Its identity may differ across versions; unavailable
corpus files fail that requested check. Routine CI uses the same probe without
that flag and always scans the shipped benign fixtures.
