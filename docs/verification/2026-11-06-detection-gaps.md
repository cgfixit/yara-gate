# Detection gaps on `main` (2026-11-06)

Source: `main` at `4b5b949`. Linux x86_64, Python 3.12.3, locked YARA-X 1.23.0, a disposable
copy of the shipped rules (84 local rules compiled, none skipped, no vendor packs). Nothing was
executed, unpacked to disk, or fetched. The probe is
[`docs/research/probe_detection_gaps.py`](../research/probe_detection_gaps.py); `--verify` fails
on a regression, and on a gap that no longer misses while it is still marked open.

Each gap sits beside a control the scanner already catches, so a miss is not a broken rule
copy. Fixtures are an English override phrase, harmless SVG handler bodies (`void 0`), and
container headers padded with zero bytes. The tables give the default-policy outcome;
`agent-ingest` and `agent-document` gave the same clean verdict on every miss.

## Still open from #145

| Item | Case | Outcome | Control |
| --- | --- | --- | --- |
| 3 | JSON `I` escape plus a `0` for `o`; Word run split plus the same substitution | clean | escape only, split only: note |
| 4 | Excel inline string split across rich-text runs | clean | inline string in one run: note |
| 5 | `<b>` inside the phrase in an HTML paragraph | clean | the same paragraph without the tag: note |
| 6 | SVG `onbegin` and `onerror` handlers | clean | `onload`: block |

## New gaps

| Id | Case | Outcome | Control | Cause |
| --- | --- | --- | --- | --- |
| G1 | base64 or percent-encoded text with a `0` for `o` | clean | the same text without the substitution: note | `text-folded` folds only the HTML-unescaped text; the decoded views are scanned unfolded (same cause as #145 item 3) |
| G2 | a zip holding the phrase, followed by a benign zip | clean | the phrase zip alone: note | `zipfile` reads the last end-of-central-directory record and its members only; 7-Zip opens the first archive |
| G3 | a PDF with a zip appended | clean, one unit | the zip alone: note | `archive_kind` reads a zip only when `PK` is at offset 0, so the members are never listed |
| G4 | `ESC[1m` immediately before the phrase | clean | a space after the escape: note | the escape's final `m` joins the first word, so the rules' `\b` anchor fails; `text-folded` removes `ESC` and keeps `[1m` |
| G5 | the phrase as variation selectors after an emoji (U+FE00-FE0F, U+E0100-E01EF), the encoding GlassWorm used | clean | the phrase as tag characters: block | `heuristic_unicode_tag` covers U+E0000-E007F only; `format-controls-removed` drops U+FE00-FE0F and keeps the supplement |
| G6 | zstd, CAB, CHM, LZ4, ar (`.deb`), cpio, and xar (`.pkg`) headers | clean | 7z, RAR, bzip2, xz: incomplete `unsupported archive` | only four compressed formats are recognized; any other is one opaque binary unit |

Real CLI intake under `agent-ingest` (`yara-gate scan PATH --home H --rules R`, disposable
home): the control zip went to `blocked/`, while the concatenated zip (G2) and the escape-glued log (G4)
went to `clean/`.

Boundaries the fixes must keep clean, all clean today: a zip with an APK-style signing block
between its last entry and its central directory, a Python zipapp that starts with `#!`, a
plain PDF, an ANSI-coloured test log, a Japanese ideographic variation sequence (U+845B
U+E0100) and an emoji presentation selector (U+2764 U+FE0F), and prose that names `MSCF` and
`ITSF`.

## Fixes on `claude/festive-curie-up7rx3`

Same host and toolchain. The probe marks each fixed case `ok`; its benign boundaries stayed
clean, and the zip end-record flood and the xz and bzip2 bombs below were checked beside it.

- **G6**: the formats above are `incomplete: unsupported archive`. xz and bzip2 are read with
  the standard library, and ar and newc/crc cpio as stored archives, so a gzip inside a `.deb` or
  an initramfs is opened. A 300 MiB run of zeros compressed with xz (45 KB) or bzip2 (2 KB) stops
  at `archive member exceeds 100MB` in 0.8 s and 0.4 s.
- **G2, G3**: every zip in a concatenation is read (the hidden archive is `zip:1` after the
  benign one), and a zip appended to a PDF, JPEG, or shell script is read as that zip. A stored
  nested zip is still read once (4 units, one finding). 80 MiB of end-record signatures inside a
  stored member costs 0.2 s, as on `main`; 200 fake records before an archive are `zip end
  records exceed 64`. CLI intake now files the concatenated zip under `blocked/`.

- **G1 and #145 item 3**: the `json-unescaped`, `base64-decoded`, `percent-decoded`,
  `mime-headers-decoded`, and `ooxml-text` views are also scanned folded, as
  `<view>+text-folded`, one step deep; the base64 rules stay with the raw bytes in every folded
  view. A JSON body with a leet handle and `\u0048ello`, and base64 of a sentence with version
  numbers and dates, stay clean.
- **G4**: `text-folded` removes ECMA-48 control sequences whole (CSI, intermediate escapes such
  as `ESC ( B`, and two-byte escapes, which include the OSC opener), and ESC no longer counts as a
  binary byte when a unit is sniffed, so a log with colour codes on every line is text. A
  coloured test log, an OSC 8 hyperlink, and a `tput sgr0` reset stay clean; a densely coloured
  log saved as `.txt` is no longer an advisory type mismatch.
- **G5**: `heuristic_variation_selector_run` blocks eight or more variation selectors in a row,
  in raw text and as HTML entities or JSON escapes. U+2764 U+FE0F, a doubled U+FE0F, seven
  selectors, and U+845B U+E0100 stay clean.
- **Cost**: `folded_text` filters with one `str.translate` over a table that
  `tests/test_text_fast_paths.py` compares with `unicodedata` for every code point, and its
  mixed-script and leet callbacks skip words and numbers they cannot change (50,000 random
  strings matched the previous fold). Median of three `scan_bytes` runs on 4 MiB inputs:

  | Input | `main` | Branch |
  | --- | --- | --- |
  | ASCII prose | 2.90 s | 2.58 s |
  | JSON with `\u00e9` escapes and leet tokens on every line | 2.04 s | 3.51 s |
  | One 3 MiB wrapped base64 run of such text | 0.93 s | 1.95 s |

  The last two are worst cases for the new folded view: every line both decodes and folds.
  The benign corpus pass (324 files) took 0.586 s on `main` and 0.573 s on the branch, and
  the 2,959 non-archive files of the sweep below 24.0 s and 24.4 s.

A sweep of 3,142 files on this host (system libraries and data, 186 jars, 72 zips, 16 wheels,
144 static libraries, 424 gzip files, the bzip2, xz, and zstd files present, and this
repository's tests, docs, and demo data), scanned in place with `scan_file` on `main` and on
the branch, changed only these results (the text-view changes added one more: `jansi-1.18.jar`, an ANSI
library whose coloured member was an advisory type mismatch, is now clean):

| Files | `main` | Branch |
| --- | --- | --- |
| 13 `.zst` (Go test data) | clean | incomplete, `unsupported archive` |
| 22 `.bz2` (Go test data) and 1 `.xz` (an apt log) | incomplete, `unsupported archive` | read: 15 clean; 4 advisory from a content rule (`agent_base64_blob` on the digits of e and a long tar header run, as the same bytes get uncompressed); 2 corrupt streams and 2 that run past the 30 s deadline incomplete |
| 3 empty Nix `.drv.bz2` logs | incomplete, `unsupported archive` | advisory `heuristic_empty_file`, as a gzipped empty `.drv` already is |
| `libc.a` | block (`heuristic_embedded_elf`) | incomplete, `archive members exceed 1000` |
| 1 corrupt Go test archive (`test_go1.11_999b.a`) | clean | incomplete, `archive unreadable or encrypted` |

## Sources

- Zip concatenation in the wild, and how 7-Zip, WinRAR, and Explorer read it:
  [BleepingComputer](https://www.bleepingcomputer.com/news/security/hackers-now-use-zip-file-concatenation-to-evade-detection/),
  [Dark Reading](https://www.darkreading.com/threat-intelligence/flexible-structure-zip-archives-exploited-hide-malware-undetected).
- Variation-selector payloads in VS Code extensions (GlassWorm):
  [Endor Labs](https://www.endorlabs.com/learn/invisible-threats-glassworm-unicode-vscode),
  [SecurityWeek](https://www.securityweek.com/supply-chain-attack-targets-vs-code-extensions-with-glassworm-malware/amp/).

## Not established

Vendor packs were not installed or measured. Only Linux was run. No 7-Zip, WinRAR, terminal, or
Office application was used to confirm what a reader sees; the reader behavior above comes from
the cited write-ups. These are scanner observations on synthetic inputs, not a false-positive
rate and not proof that any case is exploitable in a given consumer.
