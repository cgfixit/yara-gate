# Precision with Windows shortcut-family files

Measured 2026-10-24 with `uv run python docs/verification/measure_precision.py --write
docs/verification/precision-windows-shortcuts.md`. The corpus gained 21 Windows files that
Explorer reads when it lists a folder (`_windows_files()` in that script). No rule or scanner
code changed.

## Result

The 17 ordinary Windows files hit no rule: four default libraries (`knownfolder:` locations,
two with a UTF-8 BOM), a library of local folders, a local search connector, Internet
shortcuts to https, `steam:`, and `mailto:` targets (one with an https favicon), two `.scf`
files, and `desktop.ini` files for Documents (UTF-16LE), Pictures, OneDrive, and Dropbox.

The four tagged files hit, one rule each, as the README describes:

| File | Rule (advisory) |
| --- | --- |
| `Team.library-ms`, location `\\fileserver.corp.example\team` | `win_library_remote_location` |
| `Intranet.searchConnector-ms`, an https location | `win_library_remote_location` |
| `Branding/desktop.ini`, icon on a file server | `win_shortcut_remote_icon` |
| `Handbook.url`, `URL=file:///C:/...` | `win_internet_shortcut_launch` |

Control: the UTF-16LE `desktop.ini` and a BOM library, each edited to a UNC target, fired
their rules in the raw and decoded views, so the clean results are not an encoding blind spot.

Limits: the files are synthetic and hand-shaped from documented formats, not collected from
Windows hosts, and the mix is chosen, so the rate over 267 files understates how often these
rules fire on a real Windows profile. Read the per-file list, not the percentage.

## After the UNC promotion

Same corpus, same command, on the branch that adds `win_library_unc_location` (40 rules,
0 incomplete). `Team.library-ms` now hits the block rule instead of the advisory one; the
https search connector stays on `win_library_remote_location`; the other two hits are
unchanged; every other rule, including the new one, hit 0 files. The table below is the
earlier 39-rule run.

## Table

Revision `f210a64a70f7b5edf0497590e1d6eac8e1e6d775`. YARA-X `1.22.0`.
Files: 267. Incomplete: 0. One scan pass took 0.425 seconds.

The rate is files hit divided by files scanned.
A rule over 2% is over the bar.
This corpus has no true positives, so the rate is a false-positive rate.
It is not a precision ratio.

Tagged files (planted documentary text or a documented Windows collision):
- `conceal`: 6 files
- `css`: 2 files
- `curl`: 5 files
- `exfil`: 6 files
- `fileserver-icon`: 1 files
- `fileserver-library`: 1 files
- `local-file-url`: 1 files
- `marker`: 3 files
- `pem`: 6 files
- `phrase`: 8 files
- `sharepoint-connector`: 1 files
- `sysprompt`: 4 files

| Rule | Files hit | Rate | Over 2% |
| --- | ---: | ---: | --- |
| `agent_base64_blob` | 0 | 0.00% | no |
| `agent_bidi_formatting` | 0 | 0.00% | no |
| `agent_bidi_override` | 0 | 0.00% | no |
| `agent_eicar` | 0 | 0.00% | no |
| `agent_encoded_instruction` | 0 | 0.00% | no |
| `agent_fake_chat_marker` | 0 | 0.00% | no |
| `agent_hidden_html` | 0 | 0.00% | no |
| `agent_invisible_unicode` | 0 | 0.00% | no |
| `agent_markdown_exfil` | 0 | 0.00% | no |
| `agent_persistent_instruction` | 0 | 0.00% | no |
| `agent_prompt_injection_phrases` | 0 | 0.00% | no |
| `agent_role_spoof_action` | 0 | 0.00% | no |
| `agent_secret_transfer_request` | 0 | 0.00% | no |
| `agent_tool_output_override` | 0 | 0.00% | no |
| `container_disk_image` | 0 | 0.00% | no |
| `doc_external_template` | 0 | 0.00% | no |
| `doc_rtf_object` | 0 | 0.00% | no |
| `doc_svg_active` | 0 | 0.00% | no |
| `linux_desktop_exec_fetch` | 0 | 0.00% | no |
| `script_base64_decode_pipe` | 0 | 0.00% | no |
| `script_chmod_execute` | 0 | 0.00% | no |
| `script_clear_quarantine` | 0 | 0.00% | no |
| `script_download_execute` | 0 | 0.00% | no |
| `script_encoded_powershell` | 0 | 0.00% | no |
| `script_fetch_chmod_run` | 0 | 0.00% | no |
| `script_launchagent_shell` | 0 | 0.00% | no |
| `script_mshta_remote` | 0 | 0.00% | no |
| `script_osascript_shell` | 0 | 0.00% | no |
| `script_regsvr32_remote_scriptlet` | 0 | 0.00% | no |
| `script_rundll32_mshtml` | 0 | 0.00% | no |
| `shortcut_mshta_remote` | 0 | 0.00% | no |
| `shortcut_powershell_encoded` | 0 | 0.00% | no |
| `web_applescript_url_lure` | 0 | 0.00% | no |
| `web_clickfix_lure` | 0 | 0.00% | no |
| `web_html_smuggling` | 0 | 0.00% | no |
| `web_search_ms_remote` | 0 | 0.00% | no |
| `win_internet_shortcut_launch` | 1 | 0.37% | no |
| `win_library_remote_location` | 2 | 0.75% | no |
| `win_shortcut_remote_icon` | 1 | 0.37% | no |
