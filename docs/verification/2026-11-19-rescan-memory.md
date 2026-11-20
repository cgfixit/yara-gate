# The match-cap rescan's memory, measured

Date: 2026-11-19. Base: `e741cc1` (`main` after #290). Engine: YARA-X 1.23.0 (locked). Python
3.12, Linux x86-64, 4 cores, 15 GiB.

The [scanner record](2026-11-17-match-cap-scanner.md) estimated the rescan's worst case at
about 1.7 GB: four full lists at 4,000,000 matches, 107 bytes a match. That was arithmetic, not a
run. This is the run.

## Method

Each case is one `scan_bytes(data, name="t.txt", rules_dir=<tree>, timeout_s=600)` call in a
fresh process; the figure is the process's peak resident set (`ru_maxrss`), which also holds the
interpreter and the compiled rules (about 60 MiB with the bundled rules alone). Each tree is a
disposable copy of `rules/local` plus one test file. Its strings are `/[a-b]/`, `/[a-c]/`, and so
on, distinct patterns that each match at every byte of a run of `a`, so YARA-X cannot merge them.
A guarded rule reads the count (`#x > 0`); a presence rule tests only `$x`. Data: 3,999,000 bytes
of `a` (every list full on the first scan, none on the rescan) and 4,000,000 (full on both, so
the scan ends `incomplete`, `match cap reached`).

## Synthetic worst cases

| Rule tree | Rescan | `e741cc1`, 3,999,000 / 4,000,000 bytes | This branch |
| --- | --- | --- | --- |
| Bundled rules only | no | 71 / 59 MiB, clean | unchanged |
| 4 guarded rules | yes | 2,460 / 2,447 MiB; advisory / incomplete | **2,171 / 2,171 MiB**, same verdicts |
| 12 presence rules | no (none counted) | 1,269 / 1,255 MiB, advisory | unchanged |
| 4 guarded and 8 presence rules | yes | 6,193 / 6,180 MiB; advisory / incomplete | **5,352 / 5,353 MiB**, same verdicts |

Two things the estimate left out:

- **The first scan's result was alive through the rescan.** It holds a Python object for every
  match of every matching public rule. `_yara_findings` now drops it before the rescan: 11 to 14
  percent off the peak, with the same verdicts and findings. That is this branch's only code
  change.
- **`RESCAN_MAX_FULL` counts guarded lists, not lists.** The rescan raises YARA-X's limit for
  every pattern. A string a rule tests only for presence gets no guard, by design, because a full
  list still holds its first match and so cannot hide one. It therefore logs nothing, yet on the
  rescan it grows from 1,000,000 to 4,000,000 matches like the others. Eight such lists beside four
  guarded ones took the peak from 2.3 to 5.6 GB. Nothing bounds how many there are except the
  rules.

Per match, the 4-guarded case is about 130 bytes at the peak, against about 100 for the presence
case, which has no rescan. The difference is the first scan's freed memory that the allocator had
not returned.

## The rule sets that ship and install

The same probe, with `--rules` set to the bundled rules plus the three locked vendor packs
(elastic, signature-base, yara-forge; 1,868 rule files, downloaded once into the scratchpad for
the #289 sweep). 4,000,000 bytes of each fill, `name="t.bin"`, 600 s timeout:

| Fill | Result | Peak |
| --- | --- | --- |
| `a`, NUL, space, LF, `0`, `0xFF`, `A`, `<<`, `%%`, `0x90 0x90`, `0xCC 0xCC`, `00 00 FF FF` | clean, no rescan | 240 MiB (467 for `a`) |
| `QUJD` (base64), `MZ`, `//` | advisory, one rule, no rescan | 240 MiB |
| CRLF | clean, **rescan** | 290 MiB |

The one rescan is yara-forge's `SEKOIA_Apt_Gamaredon_Gammaload_Maliciouslnk`. A string it counts
matches at every CRLF pair, and its guard logged
`yara-gate match cap: SEKOIA_Apt_Gamaredon_Gammaload_Maliciouslnk 1000000`. No fill reached a
gigabyte. The synthetic peaks need several patterns that match at almost every byte, all in
matching public rules, and none of these sets has them for these fills. The `a` fill took 49.6 s
with the vendor packs, which is over the default 30 s timeout, so at default settings that file
would be held as `incomplete`, `timeout` (not measured here).

## What this leaves

- The measured bound for the case `RESCAN_MAX_FULL` was written for, four guarded lists, is
  2.3 GB (2,171 MiB), not 1.7.
- Presence-only lists that fill are not counted. The backlog row
  ([detection backlog](../research/detection-backlog.md#further-candidates-not-yet-in-the-probe))
  describes a guard that would count them. It would make some views `incomplete` that a rescan
  completes today, so it is for the maintainer to weigh.

## Checks

`ruff check`, `ruff format --check`, `mypy --strict src scripts`, `tests/test_match_cap.py` (9
passed), `docs/research/probe_match_cap.py` (2,589 flooded texts over 84 rules, 0 blind spots),
and `check_rule_pairs.py` (120 rules). The probe scripts are not committed:
the method above is the whole of each.
