# Documented delivery patterns added to the local pack

Research and direct verification: October 8, 2026, America/New_York. Starting revision: `6031f74fcec65b9e3aa3f676f386e2c86a165bd1` on the resynced `main` branch. These four original local rules expand the shipped pack from 12 to 16; no vendor rules, incident payloads, hashes, or live infrastructure indicators were imported.

The verified rule and probe changes are committed in [`1855828`](https://github.com/cgfixit/yara-gate/commit/18558283e291bad9542458ab3391182789ea1784) and proposed in [draft PR #7](https://github.com/cgfixit/yara-gate/pull/7). This extends the [initial intake implementation](../verification/intake-coverage.md); its earlier browser captures remain tied to that implementation.

## Sources and selection

Microsoft's [August 2025 ClickFix analysis](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/) describes fake verification pages, browser clipboard writes, and instructions to open a shell and paste commands. Its hunting guidance also identifies encoded/hidden PowerShell launches and `mshta` usage. The [February 2026 CrashFix report](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/) documents continued evolution of browser lures and encoded PowerShell in later stages. Those observations motivate generic advisory combinations; these rules do not identify a campaign or claim complete CrashFix detection.

HTML smuggling is an established technique, not a newly discovered 2026 exploit. Microsoft's [technical explanation](https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges-highly-evasive-loader-technique-increasingly-used-in-banking-malware-targeted-attacks/) documents JavaScript decoding, Blob construction, and download behavior. Its [ShortSeek description, updated May 2025](https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanDownloader%3AWin32%2FShortSeek.C%21dha&threatId=-2147117821), also describes HTML attachments dropping archives and subsequent HTA abuse. We use these as behavior references, not as evidence of a particular family's presence in a scanned file.

[MITRE ATT&CK T1218.005](https://attack.mitre.org/techniques/T1218/005/) documents `mshta` loading remote HTAs; the consulted page was last modified in May 2026. [Microsoft's PowerShell CLI documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1) establishes the legitimate meanings of encoded commands, window style, and execution-policy flags. Their legitimate use is why the combined indicators remain advisory.

We also checked Microsoft's [September 2026 ASCII-smuggling report](https://www.microsoft.com/en-us/security/blog/2026/09/03/ascii-smuggling-crosses-over-from-ai-prompt-injection-to-phishing-evasion/). The existing `agent_invisible_unicode` rule already detects Unicode tag bytes: an inert word interrupted by U+E0041 produced that advisory in a direct scan. No duplicate tag rule was added. This observation does not establish detection of every encoded or rendered variant discussed in that report.

## Rule boundaries and benign collisions

| Rule | Required combination | Benign collisions and missed forms |
| --- | --- | --- |
| `web_clickfix_lure` | Clipboard write/copy API plus verification/CAPTCHA language, shell-opening instructions, and paste instructions; other signals start within 4,096 bytes either side of the clipboard anchor | Security training pages can contain all signals. Ordinary CAPTCHA/copy widgets alone do not match. English phrases and selected Windows/Terminal instructions only; no page rendering, OCR, or extension behavior analysis |
| `web_html_smuggling` | `atob`, `new Blob`, and `URL.createObjectURL`/`webkitURL.createObjectURL` near a literal download filename for a script, executable, disk image, or ZIP/7z archive; 4,096-byte radius around the download anchor | Legitimate encoded archive exporters can match. PNG/PDF exports and Blob use without decoding do not suffice. No variable/data-flow analysis; calculated filenames, other encodings, split scripts, or more distant signals can be missed |
| `script_encoded_powershell` | PowerShell/pwsh launch with `-e`, `-ec`, `-enc`, or `-EncodedCommand`, a 40–512-character base64 token, plus `-w`/`-WindowStyle` with `h`/`hidden`, or `-ep`/`-ExecutionPolicy` with `Bypass` | Administrative automation may legitimately combine these. `-EncodedArguments` or an encoded command alone does not suffice. Signals must occur within the bounded command fragment (up to 1,024 characters after the executable), ending at newline, semicolon, pipe, or ampersand. This is not shell parsing or arbitrary base64 decoding |
| `script_mshta_remote` | `mshta`/`mshta.exe` followed directly by a literal HTTP(S) target, with optional quotes | Legitimate remote HTA administration or quoted examples match. Local HTAs and an unrelated URL elsewhere do not suffice. Renamed binaries, constructed URLs, UNC targets, inline scriptlets, and parsed LNK command extraction are outside this rule |

Patterns include ASCII-wide forms and use the scanner's existing derived UTF-16/HTML views and member traversal. The web API names follow JavaScript casing; human text/command indicators are case-insensitive. Scope bounds trade recall for reduced whole-file coincidence. These rules indicate patterns in bytes, not successful execution, linked JavaScript objects, or malicious intent.

All four findings retain advisory severity. Default policy returns advisory/exit 0 and moves inbox inputs to `clean/`; `agent-ingest` returns overall block/exit 1 and moves them to `blocked/`. Reports retain the finding severity and policy reason. The existing incomplete/exit 2 behavior is unchanged.

## Executed verification

Before adding the rules, four small inert examples—one for each new family—returned clean with no findings on the 12-rule baseline. With the expanded pack, each reports its specific new rule. The examples contain placeholders or `.invalid` URLs and are only scanned as bytes; no sample JavaScript, PowerShell, or Windows utility was executed.

Extended the existing [direct runtime probe](probe_rule_coverage.py), already run by Ubuntu/macOS CI, rather than adding a separate harness. Local execution used Python 3.12.12, YARA-X 1.21.0, and macOS 27.0.1 ARM64 with copied local rules and disposable gate homes:

- All 16 local rules compiled with zero skips.
- 70 library cases passed, including 33 new delivery cases. New cases check exact rule IDs, benign near-misses, bounded proximity, flag ordering/abbreviations, quoted executable paths, UTF-16, HTML entities, gzip/ZIP members, and member/view provenance.
- 16 installed-CLI intake/rescan operations passed, including default → agent-ingest for all four new families. Checks cover process exit, report severity, physical disposition, input-content omission, and SARIF offset attribution.
- The three existing required-local-rule, optional-vendor-skip, and timeout checks passed.
- Ruff lint/format and diff whitespace checks passed. No local pytest or selftest suites ran; existing hosted suites remain enabled. No production Python or workflow files changed.

A separate 2,125,000-byte inert JavaScript file repeated ordinary decode/Blob APIs without a download or clipboard/shell combination. Both the 12-rule baseline and 16-rule candidate returned clean. Single scans with compiled caches took approximately 0.143 s and 0.152 s respectively on this host. This is a bounded volume sanity check, not a throughput benchmark or performance guarantee.

The probe emits source revision, Python-source hashes, engine version, rule hashes, sample hashes, rule IDs, and expected/observed results. Synthetic acceptance is not real-corpus precision/recall, complete phishing detection, native Windows execution, or a new browser-rendering check. The previously documented vendor-update defect is outside this change; verification never invoked the updater.

## Hosted verification

At implementation commit `18558283e291bad9542458ab3391182789ea1784`, all nine registered checks passed. [Pull-request CI](https://github.com/cgfixit/yara-gate/actions/runs/37780123551) and [push CI](https://github.com/cgfixit/yara-gate/actions/runs/37780117327) passed on Ubuntu 24.04 and macOS 15, including Ruff, formatting, strict Mypy, the direct probe, selftest, and pytest. The broad suites ran on GitHub Actions, not locally.

Both the [checked-in CodeQL workflow](https://github.com/cgfixit/yara-gate/actions/runs/37780123596) and [GitHub's separate CodeQL workflow](https://github.com/cgfixit/yara-gate/actions/runs/37780126377) passed. The checked-in workflow has upload disabled; its successful query execution alone is not evidence that results reached the security dashboard. These links record checks for that exact commit; later draft heads have their own checks.
