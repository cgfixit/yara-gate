# Rules written for classic YARA, under YARA-X and inside the gate

Date: 2026-11-22. Base: `main` at `1883d28`. Engine: YARA-X 1.23.0 (the locked
dependency), Python 3.12.3, x86_64 Linux container with 4 cores, running as root. Reference
engine: classic YARA 4.5.4 through `yara-python` 4.5.4, added for these runs with
`uv run --with`; it is not in the lock and nothing in the gate imports it. Every run below
is a direct run on this container. No third-party rule file is committed here. Revised later
the same day to add what the classic manual says, once its host was reachable.

For [#236](https://github.com/cgfixit/yara-gate/issues/236): what YARA-X is beside the
YARA a Veeam YARA scan runs, and what happens to rules written for the older engine. The
issue's plan left one step open: compile Veeam-era rule files with YARA-X and record what
fails.

## Sources

Read, each opened on November 22:

- Veeam Backup & Replication user guide,
  [Performing YARA Scan](https://helpcenter.veeam.com/docs/vbr/userguide/secure_restore_yara_run.html)
  (page updated 2026-08-12, build 13.1.2.57). A rule file has the `.yara` or `.yar`
  extension and lives in `C:\Program Files\Veeam\Backup and Replication\Backup\YaraRules` or
  `/var/lib/veeam/yara_rules/`. For how to write a rule the page links the classic YARA
  manual, `yara.readthedocs.io/en/stable/writingrules.html`.
- The same guide,
  [How YARA Scan Works](https://helpcenter.veeam.com/docs/vbr/userguide/scan_backup_yara_hiw.html)
  (updated 2026-08-11). A rule tagged `SuppressMalwareDetectionNotification` raises no
  malware detection event, and a scan can look for sensitive data instead of malware.
- YARA-X, [Differences with YARA](https://github.com/VirusTotal/yara-x/blob/e4cc79c/site/content/docs/writing_rules/differences.md),
  read in the repository at `e4cc79c`, and later the same day the
  [published page](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/),
  which carries the same eleven sections.
- The classic YARA manual,
  [Writing YARA rules](https://yara.readthedocs.io/en/stable/writingrules.html) (the `stable`
  build, from `docs/writingrules.rst` at VirusTotal/yara `1a85738`), read later the same day
  once the host was reachable. What it says about the rows below is in
  [What the classic manual says](#what-the-classic-manual-says).
- Veeam community library: the
  [featured rule set](https://community.veeam.com/yara-and-script-library-67/featured-yara-rule-top-10-ransomware-threats-6267)
  (`Top10RW_YARArules.zip`, 11 `.yara` files, SHA-256
  `f86c4aba4ee49dd4b405fada241ec02e9f20aad23cdcd2e56dc3e5aef8725b30`) and the
  [rules repository post](https://community.veeam.com/yara-and-script-library-67/yara-rules-repository-10426),
  which lists signature-base, Yara-Rules/rules, and the maintainer's own
  `Veeam-PS1-Scanner-Yara-Rule-Detection-Onion-Links`.

Not established:

- **Which engine version Veeam ships.** The pages read do not say, and a web search on
  November 22 found no Veeam page that names a libyara release. The guide points rule
  authors at the classic manual, so this record compares against classic YARA 4.5.4, the
  release on PyPI. That is a reading of the documentation, not a statement about the
  product's binary.
- Whether a Veeam scan defines external variables. The pages do not mention any.

## The same language, with exceptions

`docs/research/probe_yara_compat.py` compiles each case the way the gate compiles a rule
file (`relaxed_re_syntax`, includes off, the `yara_gate_*` globals) and scans the few
bytes the case carries. `--classic` runs the same case on classic YARA. All 22 answered
as below on both.

| Case | In the gate (YARA-X 1.23.0) | Classic YARA 4.5.4 |
| --- | --- | --- |
| `"ab" base64` | E024, does not compile | compiles, matches |
| `1 of (fam_*)` over rule names | E001 | compiles, matches |
| `@a[-1]` | E007 | compiles (the value is undefined) |
| `private private rule` | E001 | compiles |
| `$a at entrypoint` | E017 | compiles |
| `/\p{L}+/` | E014 | compiles, reads `\p` as `p` |
| `/BADD\|Bad Error Happened\|/` (an empty alternative) | E014 | compiles, matches |
| `pe.exports("Crash") & pe.characteristics` (a boolean beside `&`) | E002 | compiles |
| `"mississippi" xor(1) fullword` on `{lhrrhrrhqqh}` | **no match** | **match** |
| `"This program cannot" base64` on the base64 of `xDhis program cannow` | **no match** | **match** |
| `/abc{/`, `/[0-9]{1:5}x/`, `/x64\Release\\create\.pdb/` | compile and match, because the gate compiles with relaxed regular expressions; strict YARA-X rejects all three | compile and match |
| `include "other.yar"` | E044: includes are off, so the ruleset digest covers every rule | reads the file |
| `filename matches /\.txt$/` | E009: the gate defines only its own globals | needs the caller to define `filename` |
| `import "magic"` | E010: not in the wheel | not in the `yara-python` wheel either |
| A tagged rule with `hash.sha256`, `pe` with `uint16` and `filesize`, `ascii wide nocase fullword`, a loop over `@a[i]`, a hex string with a jump and an alternative, a `global` rule | same answer | same answer |

The last two documented differences run the other way and break nothing here: YARA-X
accepts hex bounds in a jump and a `with` statement, which YARA 4.x does not.

Two rows are silent. A rule with `xor` and `fullword` together, or with `base64`, compiles
on both engines and can answer differently. The first can lose a match a rule relied on.
The second loses only false positives, which the YARA-X document says is intended. The
other failures stop at compile time, which the gate turns into an incomplete scan rather
than a missed one.

Two rows are not in the YARA-X document: the empty alternative and the boolean beside `&`.
Both were found in a public rule collection below.

## What the classic manual says

Read after the runs above, to check the rows that rested on running 4.5.4 alone. Each line is
what the manual says, then the row it bears on. None contradicts a row.

- Rule sets: `any of (Rule*)` over rule names is documented, and every rule in the set must
  be defined before the rule that uses it. The `1 of (fam_*)` row (E001 here).
- `@a[i]` is one-based, and an index past the number of matches gives NaN. The manual says
  nothing about a negative index; the `@a[-1]` row stays an observation of 4.5.4.
- `entrypoint` is deprecated in favour of `pe.entry_point`, with a warning since YARA 3.0.
  The `$a at entrypoint` row (E017 here).
- The escape sequences it lists are `\t`, `\n`, `\r`, `\f`, `\a`, and `\xNN`, plus the
  character classes; `\p` is not among them. The `/\p{L}+/` row, where 4.5.4 read `\p` as `p`.
- `base64`: because leading and trailing characters are stripped after encoding, one
  encoding of "Dhis program cannow" equals one of "This program cannot", and `base64` on a
  single character is not recommended. The `base64` row, which differs on exactly that.
  `xor`, `fullword`, and `nocase` beside `base64` are a compile error in 4.x.
- `xor` is applied after every other modifier. The manual does not say how `xor` and
  `fullword` together decide a word boundary; the `xor fullword` row, where the engines
  disagree, is measured, and the YARA-X document is the only text that describes it.
- `include` inserts the named file at compile time. External variables come from the caller
  (`-d` on the command line, `externals` in yara-python). The `include` and `filename` rows.

## Rule collections

Each file compiled alone, as the gate validates it
(`probe_yara_compat.py RULES_DIR --json`). Rule counts are by a line pattern.

| Collection | Files | Compile | Fail | Why |
| --- | --- | --- | --- | --- |
| The maintainer's Veeam rule file, `yara-malware-detection.yara` at `5c4bb08` | 1 (6 rules) | 1 | 0 | |
| Veeam's featured `Top10RW_YARArules.zip` | 11 (78 rules) | 11 | 0 | |
| signature-base at `78d979e` | 755 | 742 | 13 | all E009: the external variables `filename` (7), `filepath` (4), `extension` (2) |
| Yara-Rules/rules at `0f93570` (last commit April 2022) | 566 | 499 | 67 | the `androguard` module (46), `include` index files (12), a rule that reads a rule defined in another file (7), the empty alternative (1), the boolean beside `&` (1) |

By the probe's line patterns, none of the 1,333 files carries `verdict_on_match`, 284 carry
tags, 35 use `base64`, and none puts `xor` and `fullword` on one string.

## Do the two engines answer alike on those rules

`probe_yara_compat.py RULES_DIR --samples SAMPLES_DIR` scans each sample with each rule
file on both engines and prints every sample where the rule names differ.

| Rules | Samples | With a match | Disagreements |
| --- | --- | --- | --- |
| The maintainer's six rules | the 11 fixtures in that repository's `tests/fixtures` | 7 | 0 |
| The same | 477 generated variants: onion labels of 15, 16, 17, 55, 56, and 57 characters behind 15 leading and 11 trailing contexts, I2P, Freenet, and wallet shapes, each fixture in upper and lower case and with CRLF, each as UTF-8, UTF-16LE, and UTF-16LE with a byte-order mark | 144 | 0 |
| Veeam's featured 11 files | 2,450 files already on this machine: 50 PE, 900 ELF, 1,500 text and source files, each at most 4 MiB | 8 | 0 |

No disagreement in 2,938 samples. That is agreement on these rules and these files. It is
not a proof for a rule set that uses the two silent constructs, and neither rule set in
this table does.

## The same rules inside the gate

The maintainer's file, unchanged, was copied into the `local/` folder of a disposable
rules root beside the 89 bundled rules, and each of that repository's fixtures was scanned
with `scan_bytes` under the default policy, as it is and wrapped four ways. "Engine alone"
is the same six rules compiled as the gate compiles them and run on the same bytes.

| Fixture form | Engine alone names a rule | The gate names it | Gate verdict |
| --- | --- | --- | --- |
| 6 malicious, as they are | 6 of 6 | 6 of 6 | `block` |
| gzip | 0 of 6 | 6 of 6 | `block` |
| a zip member | 0 of 6 | 6 of 6 | `block` |
| base64 text | 0 of 6 | 6 of 6 (view `base64-decoded`) | `block` |
| UTF-16 with a byte-order mark | 6 of 6 | 6 of 6 | `block` |
| 4 benign, in all five forms | 0 of 20 | 0 of 20 | `clean` |

What the gate did with a classic rule file, observed with the CLI and a disposable root:

- A `.yara` file is loaded like a `.yar` file.
- A rule without `verdict_on_match` blocks on a match: the scan exits 1. A match that
  should only inform needs `verdict_on_match = "advisory"` or `"note"` in the rule's
  `meta`.
- A tag compiles and is not read. `SuppressMalwareDetectionNotification` suppresses
  nothing here.
- One file in `local/` that does not compile makes every scan `incomplete` with
  `local rule compile failed` and exit 2. The report counts it
  (`skipped_rule_files: 1`); neither the report nor the terminal names the file or the
  line. The probe does: `FAIL  legacy_ext.yar line 6: E009 unknown identifier` and a
  hint.

## What this does not show

- Detection of anything new. The engine is a pattern matcher on both sides; the
  difference measured above is the readers around it.
- That a rule set ported from classic YARA matches as it did. Compiling is not agreement,
  and agreement on 2,938 samples is not agreement on a file nobody tried.
- Anything about module fields beyond the `pe` and `hash` calls these rules make.
- Speed. No timing was taken here.

## Commands

```sh
uv run python docs/research/probe_yara_compat.py
uv run --with yara-python==4.5.4 python docs/research/probe_yara_compat.py --classic
uv run python docs/research/probe_yara_compat.py RULES_DIR --json
uv run --with yara-python==4.5.4 python docs/research/probe_yara_compat.py RULES_DIR --samples SAMPLES_DIR
uv run pytest tests/test_yara_compat_probe.py
```

The first and the last passed. `ruff check`, `ruff format --check`, `check_doc_links.py`,
and `check_text_controls.py` passed. Not run here: the full pytest suite and the Windows
job, which hosted CI runs. No scanner source changed, so no verdict, rule, or report can
differ.
