# Precision after the local pack grew

Parent of this write-up is `994a4986652dc576dd806be171850ac062c45e3c`. YARA-X `1.22.0`.
246 files. Incomplete scans: 0. No heuristic rule id appeared, so those detectors were also at 0 hits.

## Scan time

FACT. Five interleaved runs, old code and old 22 rules first, then this tree, on the same 246 files.
Old median 0.3578 seconds, range 0.3571 to 0.3585. New median 0.2999 seconds, range 0.2990 to 0.3024.
Ratio 0.838. That is under a 20% regression. Both sides scanned 246 files with 0 incomplete scans.

The limiter on the old side is `ruleset_digest`, which reread every rule file for every input.
A cProfile of one new-tree pass before the stamp cache put 0.653 of 0.909 seconds in that function.
The stamp cache keeps the content hash for one process when mtime and size are unchanged.
A same-size rewrite in the same nanosecond waits until the next process. That is the gap.

## False-positive rate

One later pass took 0.301 seconds. It is one run, not part of the five.

The rate is files hit divided by files scanned.
A rule over 2% is over the bar.
This corpus has no true positives, so the rate is a false-positive rate.
It is not a precision ratio.

The rate is files hit divided by files scanned.
A rule over 2% is over the bar.
This corpus has no true positives, so the rate is a false-positive rate.
It is not a precision ratio.

Planted documentary files, and why they are in the denominator:
- `conceal`: 6 files
- `css`: 2 files
- `curl`: 5 files
- `exfil`: 6 files
- `marker`: 3 files
- `pem`: 6 files
- `phrase`: 8 files
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
| `script_base64_decode_pipe` | 0 | 0.00% | no |
| `script_chmod_execute` | 0 | 0.00% | no |
| `script_clear_quarantine` | 0 | 0.00% | no |
| `script_download_execute` | 0 | 0.00% | no |
| `script_encoded_powershell` | 0 | 0.00% | no |
| `script_launchagent_shell` | 0 | 0.00% | no |
| `script_mshta_remote` | 0 | 0.00% | no |
| `script_osascript_shell` | 0 | 0.00% | no |
| `script_regsvr32_remote_scriptlet` | 0 | 0.00% | no |
| `script_rundll32_mshtml` | 0 | 0.00% | no |
| `shortcut_mshta_remote` | 0 | 0.00% | no |
| `shortcut_powershell_encoded` | 0 | 0.00% | no |
| `web_clickfix_lure` | 0 | 0.00% | no |
| `web_html_smuggling` | 0 | 0.00% | no |
