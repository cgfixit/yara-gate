# Batch scan of the consumer repositories — October 25, 2026

Direct runtime on the `claude/multi-path-scan` head (main `1ed7137` plus the
multi-path `scan`), Linux x86_64 container, Python 3.12.3, YARA-X 1.22.0, 49 local
rules copied to a disposable rules root, disposable gate homes. Read-only clones of
`cgfixit/cyclaw` (`a27406f`) and `cgfixit/cg-agent-harness` (`6d43c74`). Nothing was
executed and no file was moved; every input stayed in place.

## Command

```sh
find <clone> -type f \( -name '*.md' -o -name '*.txt' -o -name '*.json' -o -name '*.yaml' \
  -o -name '*.yml' -o -name '*.pdf' -o -name '*.csv' \) -not -path '*/.git/*' -print0 > list
yara-gate scan --paths-from list --null --json --policy agent-ingest --home GATE --rules RULES
```

## Result

| Repository | Paths listed | Records | Exit | Wall time | clean | held (block) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CyClaw | 386 | 386 | 1 | 4.5 s | 355 | 31 |
| CG-agent-harness | 144 | 144 | 1 | 3.3 s | 136 | 8 |

Record count equals the path count in both runs, nothing was incomplete, and
stderr was empty. One process per repository; the same lists as one process per
file would have cost roughly 0.17 s of startup each (about 65 s and 25 s).

Findings behind the holds (a file can carry several):

| Rule | CyClaw files | Harness files |
| --- | ---: | ---: |
| `agent_prompt_injection_phrases` | 19 | 3 |
| `script_download_execute` | 8 | 0 |
| `agent_role_spoof_action` | 4 | 0 |
| `agent_invisible_unicode` (block) | 4 | 5 |
| `agent_base64_blob` | 3 | 2 |
| `agent_bidi_formatting` / `agent_bidi_override` (block) | 0 | 2 / 1 |
| `heuristic_pdf_OpenAction` / `_AA` / `_JS` / `_EmbeddedFile` (block) | 2 / 1 / 1 / 0 | 1 / 0 / 0 / 1 |
| `heuristic_mcp_shell` | 1 | 0 |

The advisory holds are the known shape: security documentation that quotes lures,
install instructions, and role-marker examples, held because `agent-ingest` holds
every advisory. The block-severity hits are the lead worth a follow-up: nine
Markdown or text files in the two repositories carry a zero-width or
bidirectional control, and four PDFs carry an action name. Those block under both
policies. Whether each is a copy-paste artifact or intentional is a review
question for the owner; no file content or matched snippet is recorded here.

## Source verification done in this pass

The MITRE ATT&CK technique IDs cited by the rules added in this pass were checked
against the ATT&CK STIX bundle (enterprise-attack, version 20.0) fetched from the
`mitre-attack/attack-stix-data` GitHub mirror on 2026-10-25 [primary]. All sixteen
IDs resolve to the named techniques (`T1056.002` GUI Input Capture, `T1555.001`
Keychain, `T1548.003` Sudo and Sudo Caching, `T1574.006` Dynamic Linker Hijacking,
`T1098.004` SSH Authorized Keys, `T1070.003` Clear Command History, `T1218.005`
Mshta, `T1218.014` MMC, `T1059.005` Visual Basic, `T1547.001` Registry Run Keys,
`T1105` Ingress Tool Transfer, `T1559.002` Dynamic Data Exchange, `T1204.001`,
`T1204.002`, `T1566.001`). `T1562.001` is marked deprecated in version 20.0; the
TCC-database shape in #71 is cited under `T1548.003` in the rule metadata and
should not be filed under `T1562.001`. The OWASP `www-community` repository was
reachable but the CSV Injection page it serves is a 3.6 KB stub without the
examples, so that citation stays `[not fetched]`. Elastic, Invariant Labs, and
MSRC remain unreachable from this container.
