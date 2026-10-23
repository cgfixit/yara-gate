# Local rule false positives on the benign corpus

Parent revision `78ee1fda912da1c14487165681e466667beeda6b`. YARA-X `1.22.0`.
Files: 246. Incomplete scans: 0.

The rate is files hit divided by files scanned.
A rule over 2% is over the bar.
This corpus has no true positives, so the rate is a false-positive rate.
It is not a precision ratio.

## What the number is

FACT. Both passes scanned the same 246 generated files in one process, with a copied `rules/local` and no vendor bodies.
FACT. Incomplete scans were 0, so a hit is a rule match and not a failed scan.
FACT. The before pass took 1.037 seconds and the after pass took 0.400 seconds. Those are single runs, not interleaved, so the gap is not a speedup.
INFERENCE. The first pass paid for a cold YARA-X compile. The corpus is a few hundred kilobytes, so the scan is bound by process startup and compile, not by disk throughput.
FACT. Every before-hit was a planted documentary file. 8 phrase files, 6 exfiltrate files, 6 conceal files, and 4 system-prompt files are the 24 injection hits. 6 PEM files are the base64 hits. 5 curl writeups are the download hits. The marker and CSS plants, and the other 206 files, matched nothing.

2% of 246 is 4.92 files. Five, six, and twenty-four are over the bar.

## Before the tighten

| Rule | Files hit | Rate | Over 2% |
| --- | ---: | ---: | --- |
| `agent_base64_blob` | 6 | 2.44% | yes |
| `agent_prompt_injection_phrases` | 24 | 9.76% | yes |
| `script_download_execute` | 5 | 2.03% | yes |
| every other local rule | 0 | 0.00% | no |

The tighten keeps an imperative phrase, a naked base64 run, and a real `curl | sh` command.
It drops a PEM block, a paper that says "the phrase ignore previous instructions", a bare "exfiltrate", a support line "do not tell the user" with no tool call, a "system prompt:" heading with no override verb, and a writeup that calls `curl | bash` a common lure.
A file that contains both a real command and the words "common lure" is suppressed. That is a bypass.

## After the tighten

One scan pass took 0.400 seconds. Incomplete scans stayed 0.

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
| `agent_hidden_html` | 0 | 0.00% | no |
| `agent_invisible_unicode` | 0 | 0.00% | no |
| `agent_persistent_instruction` | 0 | 0.00% | no |
| `agent_prompt_injection_phrases` | 0 | 0.00% | no |
| `agent_role_spoof_action` | 0 | 0.00% | no |
| `agent_secret_transfer_request` | 0 | 0.00% | no |
| `agent_tool_output_override` | 0 | 0.00% | no |
| `doc_external_template` | 0 | 0.00% | no |
| `script_download_execute` | 0 | 0.00% | no |
| `script_encoded_powershell` | 0 | 0.00% | no |
| `script_mshta_remote` | 0 | 0.00% | no |
| `script_regsvr32_remote_scriptlet` | 0 | 0.00% | no |
| `script_rundll32_mshtml` | 0 | 0.00% | no |
| `shortcut_mshta_remote` | 0 | 0.00% | no |
| `shortcut_powershell_encoded` | 0 | 0.00% | no |
| `web_clickfix_lure` | 0 | 0.00% | no |
| `web_html_smuggling` | 0 | 0.00% | no |
