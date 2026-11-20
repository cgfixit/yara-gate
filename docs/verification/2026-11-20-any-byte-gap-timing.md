# Any-byte gaps over 200 bytes in eleven rule files

Date: 2026-11-20. Base: `328f97f`, the head of
[#310](https://github.com/cgfixit/yara-gate/pull/310) on `main` at `353746b`. Engine: YARA-X
1.23.0, Python 3.12.3, x86_64 Linux container with 4 cores. Rules: the shipped `rules/local`
(89 rules, zero skips), no vendor packs. Every run below is a direct run on this container;
nothing here is hosted CI.

The lead was a row of the [detection backlog](../research/detection-backlog.md#further-candidates-not-yet-in-the-probe)
written by the [system-opener record](2026-11-20-role-spoof-timing.md#what-this-does-not-show):
eleven more rule files hold `[\s\S]{0,N}` with N over 200 inside one pattern, YARA-X splits
such a pattern into chained halves, and two of the eleven had been timed.

## What was slow

The eleven files hold 24 such patterns in 14 rules. Each was flooded with its first half
followed by its second half, repeated to 4 MiB, through `scan_bytes` with `timeout_s=30` and a
disposable copy of `rules/local`. The first pass ran three scans at a time; a row that did
not reach the deadline there was run again alone, and that time is the one shown. The
changed column is one scan at a time on an idle container.

| Pattern | Token, repeated to 4 MiB | Name | Base | Changed |
| --- | --- | --- | --- | --- |
| `agent_hidden_html` `$hidden` | `display:none ignore previous instructions ` | `notes.html` | incomplete (`timeout`) | 2.13 s advisory |
| the same, class cue | `class="sr-only" exfiltrate ` | `notes.html` | incomplete (`timeout`) | 1.26 s advisory |
| `$hidden_dan` | `display:none you are now DAN ` | `notes.html` | incomplete (`timeout`) | 1.56 s advisory |
| `$comment` | `<!-- ignore previous instructions ` | `notes.html` | 17.55 s advisory | 2.55 s advisory |
| `$comment`, closed comments | `<!-- --> ignore previous instructions ` | `notes.html` | 16.59 s advisory | 5.09 s advisory |
| `$comment_dan` | `<!-- you are now DAN ` | `notes.html` | incomplete (`timeout`) | 1.80 s advisory |
| `doc_external_template` `$rtf` | `{\*\template http://example.invalid/a}` and a line feed, inside `{\rtf1 ...}` | `a.rtf` | incomplete (`timeout`) | 4.78 s advisory |
| the same, not RTF | `\template http://a ` | `a.txt` | incomplete (`timeout`) | 4.61 s clean |
| `doc_svg_active_link` `$foreign` | `<foreignObject> <iframe ` after `<svg>` | `a.svg` | incomplete (`timeout`) | 2.55 s advisory |
| the same, closed first | `<foreignObject></foreignObject> <form ` after `<svg>` | `a.svg` | 13.60 s advisory | 2.28 s advisory |
| `script_launchagent_shell` `$args` | `<key>ProgramArguments</key><string>/bin/sh</string>` | `a.plist` | 28.13 s clean | 0.92 s clean |
| the same, with `<plist>` and `/usr/bin/curl` | | `a.plist` | 22.50 s advisory | 2.92 s advisory |
| `script_reverse_shell` `$py` | `socket.socket( os.dup2(s.fileno() ` | `a.py` | incomplete (`timeout`) | 0.68 s advisory |
| `$py`, pty | `socket.socket( pty.spawn( ` | `a.txt` | incomplete (`timeout`) | 0.65 s advisory |
| `$ps` | `Net.Sockets.TCPClient( .GetStream() iex ` | `a.ps1` | incomplete (`timeout`) | 2.46 s advisory |
| `linux_desktop_exec_fetch` `$exec` | `[Desktop Entry]`, line feed, `Exec=curl `, line feed | `a.desktop` | incomplete (`timeout`) | 1.14 s advisory |
| `win_amsi_bypass` `$utils_field`, `$field_utils` | `AmsiUtils amsiInitFailed ` | `a.ps1` | incomplete (`timeout`) | 0.85 s advisory |
| `$patch`, `$patch_reverse` | `AmsiScanBuffer VirtualProtect ` | `a.ps1` | incomplete (`timeout`) | 0.72 s advisory |
| `win_theme_remote_resource` `$style` | `[VisualStyles]`, line feed, `Path=\\h`, line feed | `a.theme` | incomplete (`timeout`) | 0.74 s advisory |
| `win_script_host_fetch_run` `$run` | `WScript.Shell .Run(` and a line feed | `a.vbs` | incomplete (`timeout`) | 2.37 s clean |
| the same, after `CreateObject("MSXML2.XMLHTTP")` | | `a.vbs` | incomplete (`timeout`) | 2.52 s advisory |
| `win_reg_run_interpreter` `$run` | a `\CurrentVersion\Run]` key and `"a"="powershell"` after `REGEDIT4` | `a.reg` | incomplete (`timeout`) | 0.97 s advisory |
| `$ifeo` | an `Image File Execution Options\a.exe]` key and `"Debugger"=` | `a.reg` | incomplete (`timeout`) | 0.95 s advisory |
| `win_internet_shortcut_launch` `$remote` | `[InternetShortcut]`, line feed, `URL=file:`, line feed | `a.url` | incomplete (`timeout`) | 0.93 s advisory |
| `$program` | the same with `URL=C:\a.exe` | `a.url` | incomplete (`timeout`) | 1.06 s advisory |
| `$workdir` | the same with `WorkingDirectory=\\h` | `a.url` | incomplete (`timeout`) | 1.01 s advisory |
| `win_shortcut_remote_icon` `$icon` | `[Shell]`, line feed, `IconFile=\\h`, line feed | `a.url` | incomplete (`timeout`) | 0.83 s advisory |
| `win_library_unc_location` `$unc` | `<libraryDescription <url>\\h\s ` | `a.library-ms` | incomplete (`timeout`) | 1.18 s block |
| `win_library_remote_location` `$location` | `<libraryDescription <url>https://h ` after one byte | `a.library-ms` | incomplete (`timeout`) | 2.78 s advisory |

- Every one of the 24 patterns was over the 10 s ceiling of `check_worst_case_timing.py` on
  the base, and 20 of them reached the 30 s deadline. None was fast enough to leave alone.
- The changed verdict is the verdict a 64 KiB copy of the same text has on both trees. A
  flood that was incomplete is now a finding or clean, as its smaller copy already was.
- `$field_utils` and `$patch_reverse` were not flooded apart from their mirror: in the
  repeated token each field is also followed by the class, and each `VirtualProtect` by an
  export.
- The UTF-16LE copy of every row was run on the changed tree only: 0.46 to 6.06 s, with the
  verdict of the UTF-8 row except the unbalanced RTF text, which is not RTF once it is
  UTF-16. The base was not run on the UTF-16 copies.
- The first RTF flood tried, `\template http://a ` after `{\rtf1 `, is incomplete on both
  trees for the reader's own reason (`rtf unbalanced groups`, as its 64 KiB copy is): 30 s on
  the base, 8.56 s changed. The table uses balanced groups instead.
- Half a file of first halves followed by half a file of second halves was slow on the base
  too: 6.1 s for the LaunchAgent key to the deadline, 13 s or more for every other pattern.

## What the engine does

Each of these was measured with `yara_x` directly before a rule was changed. None was read in
the engine's source; the split at 200 was, by #310.

- **A string reports the first alternative that matches, not the longest.** `/x(a|ab)/` on
  `xab` matches two bytes. A window measured from the end of a match therefore depends on the
  order of alternatives: `margin-left:-1234em` ends after the digits, because the pixel
  alternative is written before the em one.
- **A chained pattern reads its first half at every end the engine verifies.** On the base,
  `class="sr-only ignore previous instructions sr-only"` fires: the cue is read as ending at
  the first class name. A separate cue string reports one match per start, ending at the
  last class name, so the phrase would lie before its window.
- **A lazy chained pattern ends at the first second half the engine finds**, which is
  neither the nearest nor the shortest. `/<!--[\s\S]{0,256}?(QRST12WXYZ34|WXYZ)/` on
  `<!-- QRST12WXYZ34` matches 17 bytes, not 15, and with a real phrase list the later of two
  overlapping phrases can be the one reported.
- **`#x in (0..n)` walks the list.** One such count per match of another string took 1.6 s,
  8.9 s, and 38.0 s for 50,000, 100,000, and 200,000 matches of each. `$x in (lo..hi)` and a
  count over a short range took 0.03 s at 200,000. The conditions below use only those two,
  or a count over a list that a guard already keeps under 1,025.
- `[\s\S]` matches one byte in a wide pattern, as #310 measured, so every window is the same
  number of bytes for the UTF-16 copy.
- A range may start below zero (`$a in (@b[i] - 10..@b[i] - 4)` near the start of a file),
  `for 1025 i in (1..#x)`, `with`, and a loop inside a loop compile and format.

## The change

In all 14 rules the two halves are separate strings and the condition looks for a second half
that starts within N bytes after the end of a first half, with YARA-X's range lookup, as #310
and [#270](2026-11-16-code-relay-timing.md) do. No rule id, severity, or `verdict_on_match`
changed, and no word was added to or removed from a pattern. Each string has an `ascii` and
a `wide` copy where the pattern had `ascii wide`, so UTF-16 is paired only with UTF-16. Each
rule carries the match-cap clause of the [November 17 record](2026-11-17-match-cap-rules.md):
a full list of a placed string, with both halves present, counts as the pair.

Twelve rules are that and no more. The other parts needed more:

- **`script_reverse_shell` `$ps` has two gaps.** The condition starts from `.GetStream()`,
  whose length is fixed, and looks back 1,024 bytes for the 22-byte client and forward 1,024
  bytes for `iex`. The other eight strings of the rule are listed by name where the
  condition said `any of them`.
- **`win_library_unc_location` blocks.** The root must still start in the first four bytes
  (`@root[i] <= 3`), and its cap clause keeps that test.
- **`doc_external_template`** pairs `\template` with `http://` or `https://`, and with two
  backslashes that start a run (`/[^\\]\\\\/`, looked up one byte earlier). The byte before
  the window is the control word's last letter, so every run in the window starts in it. A
  string that matched every pair of backslashes filled its list on 4 MiB of backslashes in
  any file, and that scan went from clean to incomplete (`match cap reached`).
- **`agent_hidden_html`, cue then phrase.** `$cue` reports the last end of a cue. `$cue_first`
  is a lazy copy of the two cues that can end far apart, the class name and the `hidden`
  attribute, and reports their first end; both windows are read. The two ends are at most
  about 200 bytes apart, less than the window, so together they cover every end between.
  The other cues can end one to five bytes early (a size with or without its closing
  character, an offset with four to six digits or a unit); no phrase can start inside those
  bytes, since they are digits, unit letters, or the closing character. The phrases are one
  string for both tests, in the lazy spelling.
- **`agent_hidden_html`, comments.** A phrase is in a comment when an opener ends within 256
  bytes before the phrase starts and no `-->` lies from that opener to the phrase's end. The
  condition loops over phrases; a phrase with an opener in reach tries the 257 places the
  opener can start. `#comment > 1024` is now `for 1025 i in (1..#open_any)`: more than 1,024
  openers that each have a phrase in reach, counted over both encodings as the one string
  counted them. That guard bounds the inner loop.
- **`doc_svg_active_link`, foreignObject.** An opener counts when an embedding element starts
  within 4,096 bytes after it and before the first close that follows the opener. The first
  close is `@foreign_close[#foreign_close in (0..@foreign[i]) + 1]`; the count walks the
  close list, which the existing `#foreign_close > 1024` test keeps short. `$embed_closed`
  keeps one reading of the old pattern: an element name that runs straight into the close
  (`<iframe</foreignObject>`) is closed. `#foreign > 1024` became a `for 1025` loop.
- **`fragments.toml`** has the class and attribute cues as fragments of their own, which
  `hiding_cues` names, so the lazy copy is rendered from the same text.
  `check_rule_generator.py` now edits `$cue = /({{hiding_cues}})`, since the placeholder
  appears twice.

**Tried and taken back.** Writing the em offset before the pixel one in `hiding_cues`, so a
cue ends at its longest reading, held 28 of 20,000 generated inputs that the base clears
(`margin-left:-1234em` with a phrase starting 257 or 258 bytes after the digits). The order
is as it was.

## Same texts held

Old and new copies of each rule file were compiled alone and compared on generated inputs:
first halves and near-misses of them, second halves and near-misses, in either order, one to
three pairs per input, with gaps chosen around the bound, half the bound, 128, 200, and twice
the bound. The fill held spaces, line feeds, tabs, Latin-1 and CJK characters, and now and
then another half or a close. Encodings were UTF-8, UTF-16LE with and without a byte-order
mark, UTF-16BE, Latin-1, and mixed; a fifth of the inputs were cut at a random byte. The SVG
file was run under four settings of the extension and scope globals. Two seeds of 50,000
inputs per file:

| Rule file | Base fires | Held on base, clean now | Clean on base, held now |
| --- | ---: | ---: | ---: |
| `agent_hidden_html` | 52,280 | 0 | 3 |
| `doc_external_template` | 23,900 | 0 | 0 |
| `doc_svg_event_handler` | 70,855 | 0 | 421 |
| `script_launchagent_shell` | 24,436 | 0 | 0 |
| `script_reverse_shell` | 56,705 | 0 | 0 |
| `unix_launcher_lures` | 42,981 | 0 | 0 |
| `windows_defense_evasion` | 45,104 | 0 | 0 |
| `windows_remote_resource` | 19,515 | 0 | 0 |
| `windows_script_host_payload` | 26,320 | 0 | 0 |
| `windows_script_hosts` | 11,381 | 0 | 0 |
| `windows_shortcut_remote` (four rules) | 102,940 | 0 | 0 |

The comparison is of whether each rule fires, not of offsets. Nothing the base holds went
clean. The two files with gains:

- **`doc_svg_active_link`, 421 inputs, one shape:** a `meta` refresh whose `refresh` runs
  straight into the close, `<foreignObject><meta http-equiv=refresh</foreignObject>`. The base
  reads the foreignObject as closed and the change reads it as open. Every one of the 421
  holds that shape (checked with a regular expression over the gained inputs). The same test
  for `iframe`, `object`, `embed`, and `form` is kept by `$embed_closed`; a `meta` tag can
  hold `http-equiv=refresh` twice, and a string that read the second one as running into
  the close would clear a file the base holds. A gain on markup no parser reads as a tag was
  the safer side.
- **`agent_hidden_html`, 3 inputs, one shape:** two phrases overlap inside a comment
  (`you are now ... ignore` and `ignore all previous instructions`), and `-->` follows the
  later one at once. The base read the later phrase, whose end touches the close, and
  cleared the file; the change reads the earlier one, which ends before the close.

`check_rule_pairs.py` passes unchanged: no spelling changed, so no pair was added.

## Other shapes

On the changed tree, each row's first half alone, its second half alone, half a file of
second halves followed by half a file of first halves, and the reverse, at 4 MiB (124 scans,
three at a time): every scan has the base's verdict, or a finding where the base reached
the deadline, and all are under 6 s except those whose second half is `iex ` or `http://a `.
Those two tokens are slow on the base for another reason and are in the backlog now:

| Token, repeated to 4 MiB | Base | Changed |
| --- | --- | --- |
| `iex ` as `a.ps1` | 26.99 s clean | 27.74 s incomplete (`match cap reached`) |
| `http://a ` as `a.txt` | 9.65 s clean | 9.53 s clean |
| `http://` as `a.txt` | 19.90 s clean | 20.35 s clean |
| `.Run` as `a.vbs` | 0.65 s clean | 0.99 s clean, read again at 4,000,000 |
| A backslash as `a.txt` | 0.77 s clean | 0.67 s clean |
| `-->` as `n.html` | 1.19 s clean | 1.29 s clean (read again at 4,000,000 on both) |

- `iex ` is slow in `script_download_execute.yar` (the file alone: 1.6 s, 3.2 s, 6.7 s for
  256 KiB, 512 KiB, 1 MiB). 4 MiB holds 1,048,576 matches of the new `$ps_iex`, which fills
  its list, and no time is left to read it again.
- **This is the cost of placing a string.** A second half is now a string of its own, with a
  guard. A file with a million matches of one is scanned again at 4,000,000, and with four
  million it is incomplete, where the base was clean. #310 has the same cost for its verbs.

Shapes aimed at the new conditions, 4 MiB each, base against changed:

| Shape | Base | Changed |
| --- | --- | --- |
| 1,000 closed comments with 22 phrases after each, then phrases | 2.40 s clean | 2.27 s clean |
| The same, then comment openers | 1.70 s clean | 2.42 s clean |
| The same, then cues | 1.80 s clean | 2.12 s clean |
| 1,000 closed foreignObjects with 600 `<form ` after each, as `.svg` | 3.83 s clean | 3.26 s clean |
| The same as `.html` | 3.71 s clean | 3.53 s clean |
| 1,000 closes, then openers | 2.15 s clean | 2.04 s clean |
| 900 `<svg>` tags, 1,000 closed foreignObjects with a form, then openers, as `.html` | 2.09 s clean | 2.11 s clean |

## What a finding reports

A finding from one of these patterns used to span the first half through the second. It now
reports one of the two, both inside the view. From small files through `scan_bytes`:

| Rule | Base offset, length | Changed |
| --- | --- | --- |
| `agent_hidden_html`, `display:none` and a phrase | 25, 42 | 25, 12 (the cue) |
| `agent_hidden_html`, a comment with a phrase | 13, 31 | 13, 4 (the opener) |
| `doc_external_template`, RTF | 10, 17 | 10, 9 |
| `script_reverse_shell`, Python | 19, 53 | 19, 14 |
| `linux_desktop_exec_fetch` | 0, 41 | 0, 15 |
| `win_library_unc_location` | 0, 126 | 0, 41 |
| `win_theme_remote_resource` | 0, 7 (`[Theme]`) | 36, 9 (the `Path` line) |
| `win_script_host_fetch_run` | 8, 13 (`CreateObject(`) | 78, 6 (`.Run "`) |

The last two rules now read where a match lies, so the scanner reports the match that made
the rule fire instead of the first match of the first string. Second halves are declared
after first halves so the first half is reported where it decides.

## The timing step

`check_worst_case_timing.py` has four new inputs, each with a required verdict and no scaling
bound: `hidden-cue-phrases.html` and `comment-phrases.html` (advisory), `svg-foreign-embeds.svg`
(advisory), and `library-urls.library-ms` (block). They cover the three rules whose
conditions do more than pair two strings, and the one rule that blocks. The step now has 101
inputs.

| Run | Inputs | Result | Scan seconds, summed | Wall |
| --- | ---: | --- | ---: | --- |
| Base | 97 | PASS | 232.7 | not timed |
| Changed rules, before the new inputs | 97 | PASS, no verdict or reason differs from the base | 236.6 | 5 min 55 s |
| Changed, with the new inputs | 101 | PASS, slowest 7.39 s (`pdf-font-definitions.pdf`) | 244.1 | 6 min 04 s |

The four took 1.93 s, 2.01 s, 2.31 s, and 1.01 s. `html-comments.html`, 4 MiB of `<!--`, went
from 1.73 s to 2.35 s: its million openers fill the new opener strings and the view is read
again.

**Left out of the step**, for its budget ([November 14 record](2026-11-14-macos-timing-flake.md)):
the other twenty patterns' floods. A regression in one of them would show in a rerun of the
table above, not in CI.

## The bar

| Check | Result |
| --- | --- |
| `lint_rules.py` | 89 rules compiled and linted |
| `check_rule_generator.py` | passed, 22 checks |
| `check_rule_pairs.py` | passed, 120 rules |
| `check_added_rules.py`, `check_scan_only.py` | passed, 246 cases plus 4 vendor-override cases; 7 cases |
| `probe_rule_coverage.py --verify` | exit 0 |
| `measure_precision.py --fail-over` | 328 files, 0 incomplete; the report equals the base's apart from times and digests |
| `probe_detection_gaps.py --verify` | exit 0 |
| `sweep_rule_changes.py --jobs 4 --base-ref HEAD` | 0 of 10,131 installed files changed findings (323 hits before and after), over `/usr/share/doc`, `/usr/lib/python3.12`, `/usr/lib/python3/dist-packages`, `/usr/include`, `/usr/share/man`, `/usr/share/perl`, `/usr/share/vim`, the locked site-packages, and `docs` |
| `check_worst_case_timing.py` | PASS, 101 inputs of 4 MiB |
| `probe_match_cap.py` | 3,031 flooded texts over 84 rules, 0 with a cap blind spot; 25 new floods. With the new clauses switched off: 13 rules with a blind spot, every changed rule but `win_library_unc_location` |
| `record_pages_demo.py --baseline web-demo/recordings.json` | On the rule commit `4ff2a93` the outcomes differed in one place: the length of the `agent_hidden_html` finding of the `hidden_html` case, 42 to 12 under each policy, which is the cue instead of the cue through the phrase. Re-recorded at `4ff2a93`; the diff holds that length three times and the provenance fields. Then: outcomes match, 91 scenarios under 3 policies; `build_pages.py` validated 273 recordings; `tests/test_pages_build.py`, 11 passed; the built page loaded in Chromium with no console error |

The CLI with a disposable rules copy and home, files outside any inbox: a hidden-cue page
and the 4 MiB cue flood were advisory with exit 0 under `default` and held with exit 1 under
`agent-document` and `agent-ingest`; a library file with a UNC `url` and the 4 MiB library
flood blocked with exit 1 under all three; a page with `display:none` on a menu and a build
comment was clean with exit 0 under all three. The files stayed in place.

Not run locally: the broad pytest suite and `selftest` (hosted CI), and `mypy`, since no
Python contract moved.

## What this does not show

- A production false-positive rate, or timing on macOS or Windows. The timing step gained
  four workers and four scans; whether the macOS runner has room is for hosted CI to show.
- That no other input makes these rules slow. The shapes above are the ones that were tried.
- That the engine's reading of a chained pattern is what the observations above say in
  every case. They are measurements on a few inputs and 1,100,000 generated ones.
- **A base miss, found here and left as it is:** `<!--exfiltrate-->` is clean on both trees
  while `<!-- exfiltrate -->` is advisory. The comment test counts a `-->` that starts at the
  byte after the phrase as lying between the opener and the phrase. The change keeps that
  reading; closing it is a detection change and is a row in the backlog.
