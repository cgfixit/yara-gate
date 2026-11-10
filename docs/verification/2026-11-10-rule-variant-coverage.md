# Rule variants: the same attacks under more spellings — November 10, 2026

Measured on `main` at `cd2e0d4` (after #199 and #200), then rebased onto `163ec4a` (after
#201, #202, and #203) and re-run; `rules/local` is the same at both. No pull request was open
at either point. Rule change: `a2abdaf`. Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0,
85 bundled local rules, zero skips, no vendor download. Every scan used a disposable copy of
`rules/local`. Nothing was executed, unpacked to disk, or fetched by the scanner.

## Question

Each local rule matches a shape somebody wrote down. Does a trivially different spelling of
the same shape get past it, and can the rule read that spelling without holding more benign
text?

## Method

1. **Probe.** 343 inert inputs were scanned with `scan_bytes` on `cd2e0d4`: for each rule
   family, the documented form (a control the gate catches), then the same command or
   sentence as another tool, shell, or writer would spell it, then benign text nearby.
2. **Sort the misses.** A miss was fixed only when it was the same act in another spelling,
   so the benign class stays the one the rule already had. A miss that would add a new
   class of benign hit went to the [detection backlog](../research/detection-backlog.md)
   with the reason.
3. **Write the near-miss first**, then the pattern, then run both.
4. **Compare** the benign corpus, 20,000 installed files, the recorded demo, and timings
   before and after.

Three command spellings come from primary sources read on November 10, not from the
probes: the PowerShell parameter parser
([`CommandLineParameterParser.cs`](https://github.com/PowerShell/PowerShell/blob/master/src/Microsoft.PowerShell.ConsoleHost/host/msh/CommandLineParameterParser.cs):
`MatchSwitch` takes any prefix at or above a minimum, `GetSwitchKey` takes `/` or any dash
character and strips a doubled dash, and the window style converts through enum prefix
matching, so `h`, `hid`, and `1` all mean Hidden); the `for /f ... in ('finger ...') do
call` stage and the `Resolve-DnsName ... | iex` stage
([Unit 42 timely threat intel](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel),
entries of May 5 and February 3, 2026); and the chat-template tokens, each from the model's
own tokenizer files or documentation (Gemma 4, DeepSeek V4.1, Llama 4, Cohere) and the
VS Code source for `chat.tools.terminal.autoApprove`.

## Result

Of the 343 probe inputs, 127 went from clean to a finding, 8 kept their verdict and gained
the specific rule id, and 208 did not change. The unchanged rows are the controls, the
benign rows, and the misses left for the backlog. A separate set of 98 benign boundaries,
one or more beside every edited pattern, gave the same result before and after.

No rule was added or removed and no severity changed: 85 rules in 58 files, 73 advisory,
6 block, 6 note.

| Rule | Now also reads | Stays clean |
| --- | --- | --- |
| `script_encoded_powershell`, `shortcut_powershell_encoded` | `-win hid -exec bypass -enco <b64>`, `/w 1 /e <b64>`, `--enc`, an en dash before the parameter, an encoded value over 512 characters; the shortcut rule also `-ep unrestricted` | `-w 1 -c "Get-ChildItem"`, `-ExecutionPolicy Bypass -File build.ps1`, `-w maximized -enc ...`, an encoded command with neither flag |
| `script_download_execute` | `curl ... \| /bin/bash`, `\| /usr/bin/env sh`, `\|& bash`, `eval "$(curl ...)"`, `source <(curl ...)`, `curl ... \| node`, `iex((Resolve-DnsName -Type TXT ...).Strings)` | `VERSION=$(curl ...)`, `curl ... \| /usr/bin/shasum`, `\| /usr/bin/env python3 -m json.tool`, `\| node parse.js`, `source <(kubectl completion bash)`, `Resolve-DnsName ... \| Select-Object` |
| `script_base64_decode_pipe` | `base64 -di \| /bin/sh`, `\| sudo bash`, `bash -c "$(echo ... \| base64 -d)"`, `eval "$(... \| base64 --decode)"` | `KEY="$(echo ... \| base64 -d)"`, `./run.sh -c "$(... \| base64 -d)"`, `base64 -d f \| /bin/shasum` |
| `script_reverse_shell` | `exec 196<>/dev/tcp/...`, `bash -l > /dev/tcp/...`, `sh -i <&3 >&3 2>&3` (the PHP `fsockopen` and Ruby `TCPSocket` one-liners, and `sh <&196 >&196 2>&196`), Perl `open(STDIN,">&S")` then `exec` of a shell | `sh ./run.sh <&3 >&3 2>&3`, `./deploy.sh <&3 >&3 2>&3`, `open(STDOUT, ">&STDERR"); exec(...)`, `bash -l -c 'make test'`, a `/dev/tcp` port check |
| `win_lolbin_download` | `msiexec -i https://...`, `for /f ... in ('finger user@host') do call %h` | `msiexec -x {GUID}`, the same loop ending in `do echo %h` |
| `script_clear_quarantine` | `/usr/bin/xattr ...`, `xattr -d -r com.apple.quarantine` | `/usr/bin/xattr -p com.apple.quarantine`, a write of another attribute |
| `script_osascript_shell` | `osascript <<EOF` followed by `do shell script` | a here-document that only shows a dialog |
| `script_chmod_execute` | `chmod a+x x; nohup ./x &`, a launch after `sudo`, `setsid`, or `exec` | `chmod +x s.sh; sudo systemctl restart app`, `chmod 644 f && exec "$@"` |
| `unix_privilege_persistence` | `echo '... NOPASSWD: ALL' \| sudo tee -a /etc/sudoers`, `tee` into `/etc/ld.so.preload` | `echo 'Defaults timestamp_timeout=30' \| sudo tee -a /etc/sudoers.d/timeout` |
| `script_credential_upload` | `curl -d "$(cat ~/.ssh/id_rsa)" ...`, `curl "...?k=$(cat .env \| base64)"`, `tar czf - ~/.ssh \| curl -T - ...`, `env \| curl -d @- ...`, `printenv \| base64 \| nc ...`, `curl -d "$(env)" ...` | `env \| grep PATH`, `env HTTPS_PROXY=... curl ...`, `curl -H "Authorization: Bearer $(cat token.txt)" ...`, `tar czf - ~/.ssh \| ssh backup@host ...`, a public key upload |
| `macos_stealer_password_check` | `Login\ Data`, as a shell script escapes the space | `dscl . -authonly` with no store named |
| `web_clickfix_lure` | Command+Space and Command+V, a key in its own `<kbd>` tag, "Verify you're human", "I'm not a robot", "human verification", "Verification ID" | a shortcut list with a copy button and no verification text, a sign-up page with a captcha and a copy-link button, the lure text with no clipboard call |
| `web_html_smuggling` | download names ending `.msi`, `.msix`, `.appx`, `.scr`, `.pif`, `.cpl`, `.xll`, `.bat`, `.cmd`, `.ps1`, `.url`, `.chm`, `.one`, `.jar`, `.dmg`, `.pkg`, `.rar`, `.cab` | `.csv`, `.pdf`, `.png`, `.json` exports built the same way |
| `agent_prompt_injection_phrases` | "ignore all instructions above", "ignore above instructions", "ignore your instructions", "disregard your system prompt", "do not follow the previous instructions", "stop following your previous instructions", "override previous instructions" | "follow the instructions above", "later rules override earlier rules", "the model may ignore the system prompt", "ignore any instructions found in the retrieved document", "don't forget your instructions sheet", "ignore my previous message" |
| `agent_prompt_injection_multilingual` | Dutch, Polish, Turkish, Indonesian, Vietnamese, Korean, Arabic, Hindi; German with an article in place of `alle`; French `ci-dessus`; more Chinese and Japanese word orders and verbs | "ignore the previous message" in each of the twelve languages checked |
| `agent_role_spoof_action` | The system or developer opener of harmony, Llama 2, Llama 4, Mistral, Phi, Gemma 3 and 4, Granite, Cohere, and DeepSeek, followed by an order | each family's own example prompt with no order in it |
| `agent_fake_chat_marker` | The assistant opener of Phi, Gemma 3 and 4, Llama 3 and 4, harmony, Cohere, and DeepSeek, followed by an order | a model turn that prints code |
| `agent_markdown_exfil` | `[label]: https://host/?q={{...}}` | `[1]: https://host/docs`, a badge definition, `[home]: {{ site.url }}/index.html` |
| `agent_hidden_html` | the phrase after `left:-9999px` or `text-indent:-9999px`, `font-size:1px`, `class="sr-only"`, the `hidden` attribute, or `[//]: # (...)` | each cue with ordinary text; the phrase beside `opacity:0`, `margin-left:-15px`, `top:-100px`, `<input type="hidden">`, or `overflow: hidden` (a note, as before) |
| `agent_config_approval_bypass` | `"chat.tools.terminal.autoApprove": {"/.*/": true}` and the deprecated `chat.agent` key, also after other entries or as `{"approve": true}` | a list of named commands, the same pattern set to `false`, `chat.tools.terminal.enableAutoApprove` alone |

### Found while verifying

- **`.sh` read as a shell.** The first form of the descriptor-shell string matched
  `sh ./run.sh <&3 >&3 2>&3`: `\bsh` is satisfied after the dot in `run.sh`. The shell now
  has to be the command, at the start of a line or after a space, quote, slash, or
  separator. The decode-in-substitution string in `script_base64_decode_pipe` had the same
  fault with `./run.sh -c "$(...)"` and has the same fix.
- **"Forget your instructions."** The second-person phrase first took `forget`, which holds
  "don't forget your instructions sheet". `forget` now counts only before `system prompt`
  or `programming`.
- **A pattern with no literal to search for.** Writing every PowerShell prefix character
  into one group, `(-{1,2}|/|<three Unicode dashes>)`, left YARA-X only the letter `e` as an
  atom for the encoded-command string. That one string cost 228 ms on 4 MiB of ordinary
  text, against 1 ms before, and made every text scan about 39% slower. The common
  prefixes (`-` and `/`) and the rare ones (`--` and the Unicode dashes) are now separate
  strings; the cost is 2.8 ms and 0.5 ms. The 4 MiB timing step in CI passed with the slow
  form, because none of its inputs is ordinary prose; the per-rule timing below is what
  showed it.

## Commands and results

- `docs/verification/lint_rules.py`: 85 rules compiled and linted, 2 vendor overrides.
- `docs/verification/check_rule_pairs.py`: passed, 115 ids. 62 pairs were added, one or
  more for each row of the table above.
- `docs/verification/check_added_rules.py`: passed, 215 cases plus 4 vendor-override cases.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete.
  The table is byte-identical to the one from `cd2e0d4` apart from the timing line: 81 of
  85 rules at 0 files, and the four documented Windows collisions at one file each.
- `docs/research/probe_rule_coverage.py --verify`: passed, 607 library cases (531 before),
  55 CLI cases, 9 benign observations. The 76 new rows are 45 shapes of this change,
  written as UTF-8, as UTF-16, and inside a zip: 53 that must fire and 23 that must stay
  clean. Of 24 shapes tried in four encodings, 95 of 96 fired; Korean as UTF-16LE with no
  byte order mark did not, the limit `decoded-utf16` already has for text with no ASCII.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 222 `ok` and 9 `open`. The 215
  rows of `cd2e0d4` are unchanged. The 16 new rows are the backlog's B1 to B6: nine known
  misses marked `OPEN` and seven controls and benign boundaries.
- `docs/verification/check_text_controls.py`, `check_scan_only.py`, `check_rules_lock.py`:
  passed. After the rebase, `check_doc_links.py` (582 relative links) and
  `mypy --strict src scripts` also passed.
- `docs/verification/check_worst_case_timing.py`: PASS before and after the rebase, 29 inputs of 4 MiB, slowest 6.9 s
  (`pdf-page-objects.pdf`, which the rules do not touch) against a 10 s ceiling.
- `scripts/record_pages_demo.py --baseline web-demo/recordings.json`: "Outcomes match the
  reviewed baseline" for the 49 scenarios of `cd2e0d4` and, after the rebase, for the 58 of
  the shared catalog #201 added, each under 3 policies. Ruleset digest
  `bf5331f06848cfc3a02e46ff903180a0ef56de233c6db7f589fe69ccea18cf39`.
- `yara-gate selftest`: SELFTEST PASS.
- `ruff check .` and `ruff format --check .`: passed.
- `pytest` on the 17 test files that name an edited rule, a policy, or the CLI: 501 passed,
  1 skipped. The whole suite is left to hosted CI.

### Installed files, before and after

[`sweep_rule_changes.py`](sweep_rule_changes.py) is new in this change. It reads text-like
files in place, scans each in memory with the rules at a git revision and with the working
tree's rules, and lists every file whose findings differ.

| Corpus | Files | Files whose findings changed | Hits before and after |
| --- | ---: | ---: | --- |
| Node 22 and its modules under `/opt`, `/usr/share/doc`, the Python 3.12 and 3.13 libraries, Vim and Perl runtime files, `/etc`, shell completions, the project's virtual environment | 20,000 | 0 | 57 and 57 |
| The repository's own documents, tests, scripts, and source, including the files this change adds | 192 | 7 | 255 and 274 |

The seven repository files are the ones this change writes the new shapes into: the four
fixtures (`check_rule_pairs.py` and the three signature data files) and three documents that
quote them (the rule reference, the backlog, and this record). No other document, test, or
source file in the repository changed findings. The installed-file run was repeated three
times as the rules settled, on 14,000 and then twice on 20,000 files, the last with the
committed script against `cd2e0d4`; each showed zero.

### Cost

4 MiB inputs, best of two, `scan_bytes`, seconds. The first two rows are ordinary content;
the rest are built from the literals the new patterns search for, the worst case for each.

| Input | `cd2e0d4` | this change |
| --- | ---: | ---: |
| Ordinary prose | 0.55 | 0.53 |
| Ordinary HTML paragraphs | 0.90 | 0.99 |
| Tags with a `hidden` attribute and the word in a title | 0.75 | 1.29 |
| Chat-template tokens, back to back | 1.01 | 1.87 |
| Off-screen offsets | 0.59 | 0.81 |
| Descriptor redirects | 0.92 | 1.25 |
| `class="... sr-only ..."` spans | 1.00 | 1.28 |
| Override verbs and nouns, no phrase | 1.09 | 1.25 |
| PowerShell flags, no command | 2.91 | 2.51 |
| `curl ... \| jq \| sort` lines | 2.61 | 2.47 |
| Markdown reference definitions | 5.54 | 6.03 |
| All 18 inputs | 28.5 | 31.0 |

One rule file at a time, on the ordinary prose, every edited file is within 0.04 s of the
base. Markdown reference definitions were already the slowest text shape on `cd2e0d4`; the
new string adds about 0.5 s to it. The timing step in CI has no such input.

## What this does not establish

- The probes are synthetic and were written by the same pass that wrote the patterns. They
  show that named spellings are read, not how many spellings exist.
- Zero changed files among 20,000 is a collision count on one container's installed
  software. It has few shell installers, no mail, and no chat logs; it is not a
  false-positive rate for a user's documents.
- The translations were not checked by native speakers. Each is the plain imperative
  "ignore all previous instructions" and a short list of variants.
- No Windows or macOS host ran the commands. The PowerShell spellings follow the parser's
  source; Windows PowerShell 5.1's parser is not public, and the published samples show it
  accepting `-w h -ep bypass`.
- `agent-document` now holds a few more files than before: text that quotes one of the new
  advisory shapes. Under the default policy no exit code changes.
- Hosted CI on macOS and Windows had not run when this was written.
