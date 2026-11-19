# LibreOffice's printer setup in files from other writers

Date: 2026-11-19. Base: `e741cc1`. Engine: YARA-X 1.23.0 (locked).

The [November 18 record](2026-11-18-hidden-members-printer-setup.md) exempted the
`PrinterSetup` item from `agent_base64_blob` after counting LibreOffice's own test corpus. Two
questions were left. Do other OpenDocument writers store the item in another way, so their files
would be wrongly held? And should the exemption also require the driver data to have the form
real files use? This record answers both. It changes no code.

## Corpora

Read as data, never opened in an office suite. A file's writer is its `meta:generator`.

| Source | Revision | OpenDocument files |
| --- | --- | --- |
| LibreOffice core, `sw/qa`, `sc/qa`, `sd/qa` (the November 18 corpus) | `068c54d` | 2,089 |
| Apache OpenOffice, every `.od*`/`.ot*` | `ef350a5` | 2,659 |
| ODF Toolkit (`tdf/odftoolkit`) | `7cf7a0b` | 783 |
| odfdo (`jdum/odfdo`) | `d50bb97` | 82 |
| odfpy (`eea/odfpy`) | `7db707f` | 30 |
| ONLYOFFICE core (`OdfFile` test files) | `ed63e94` | 9 |

For writers with few or no files, their settings writer was read instead: ONLYOFFICE
`OdfFile/Writer/Format/odf_settings_context.cpp` (`ed63e94`), Calligra `libs/odf` (`6110f12`),
and AbiWord `plugins/opendocument/exp/xp/ODe_SettingsWriter.cpp` (`972381b`).

## Finding the item

The counter parses `settings.xml` with an XML parser and takes every `config:config-item` named
`PrinterSetup`, whatever its prefix or attribute order. Then it records:
- whether the exact opening tag the exemption tests is present;
- whether the base64 decodes to the structure `_job_setup` accepts;
- what `base64_run_signals` (the check behind the rule) says about the whole `settings.xml`.

Of the 5,652 files, 3,126 hold a non-empty item:

| Writer | Files | Non-empty items | 400 base64 characters or more | Exact tag and exact structure | `settings.xml` still a blob |
| --- | --- | --- | --- | --- | --- |
| StarOffice 8 and 9 | 1,773 | 1,273 | 1,263 | 1,273 | 0 |
| OpenOffice.org | 1,077 | 855 | 756 | 855 | 0 |
| LibreOffice, including developer builds under other product names | 2,087 | 667 | 642 | 667 | 0 |
| Apache OpenOffice | 320 | 260 | 255 | 260 | 0 |
| Collabora Office and Online | 69 | 32 | 32 | 32 | 0 |
| IBM Lotus Symphony | 30 | 20 | 16 | 20 | 0 |
| odfdo, lpOD, ODFDOM (files whose settings came from the suites above) | 39 | 17 | 3 | 17 | 0 |
| NeoOffice, Oracle Open Office, other OpenOffice.org builds | 14 | 2 | 0 | 2 | 0 |
| Microsoft Office (89), no generator (106), ONLYOFFICE, KOffice, odfpy, Gnumeric, others | 243 | 0 | | | |
| Total | 5,652 | 3,126 | 2,967 | 3,126 | 0 |

Every non-empty item in every corpus uses the exact tag and the exact structure. Microsoft Office
(89 files) and ONLYOFFICE write no item. ONLYOFFICE's writer has no `PrinterSetup` at all: its
only `base64Binary` items are a protection salt and hash, far under 400 characters. Calligra's and
AbiWord's settings writers do not write it either. Empty items take two forms:
`<config:config-item ... config:type="base64Binary"/>`, and a 4-character item that some
Collabora and LibreOffice builds write. Both are too short to be a blob.

### The scanner on the new corpora

`scan_file` with the bundled rules on all 3,563 new files: 3,362 clean, 112 advisory, 85
incomplete, 4 block. Not one has an `agent_base64_blob` finding on `settings.xml`. The 15 blob
findings are document signatures (11), object replacement images (2), and `content.xml` (2).

The 85 incomplete files are a different matter, not this one:
- 80 are `archive member escapes the archive`: 79 Apache OpenOffice template sources under
  `main/extras/source` whose members are named with a leading `/` (`/Configurations2/...`), and
  one ODF Toolkit test file. An absolute member name is held by the gate's contract.
- 3 are `archive unreadable or encrypted`.
- 2 are `archive members exceed 1000`.

## Requiring the driver data's form

The proposal: exempt the item only when the driver data is CUPS `JobData` text or a Windows
`WNT3` block with a `DEVMODE`. Not built, because of what the corpora hold.

- **The forms are more than two.** Besides CUPS text and `WNT3`:
  - macOS builds write 4 bytes (`h/DV`, `Renv`, zeros, and others);
  - some Windows builds write none.
  Those items are all under 400 characters, so today they never reach the exemption.
- **The `WNT3` header has changed.** LibreOffice now writes a signature as wide as a pointer, then
  the offset of the `DEVMODE` (`SalDriverData` in `vcl/inc/win/salprn.h`), so 8 bytes on a 64-bit
  build and 4 on a 32-bit one. An older layout puts a version before the offset. In LibreOffice's
  corpus, 282 of 290 Windows blocks fit the current header, 7 the older one, and 1 neither. In the
  OpenOffice.org and StarOffice corpus, 409 of 1,880 fit one of the three and 1,471 fit none. A
  form check would hold those 1,471 real files unless it learned layouts no source here
  documents.
- **The form would not close the channel.** Where the `DEVMODE` does parse, the bytes after it
  (`dmDriverExtra`) belong to the printer driver and are opaque by design. They run to 29,916 bytes
  in LibreOffice's corpus and 10,796 in the other, with 188 blocks over 4 KiB. A payload written
  there passes a form check just as it passes today. The bound stays the item's u16 total, 64 KiB.
  The checks that hold today stay in place: no executable header and no base64 run in the decoded
  bytes.
- CUPS `JobData` is the one form a check could read fully: lines of printable text, NUL-ended, at
  most 253 bytes here. Constraining it alone would leave the Windows form, which is larger, open.

The key and value strings after the driver data were 149 bytes at most in either corpus, all
`COMPAT_DUPLEX_MODE`, `PRINTER_NAME`, and `DRIVER_NAME`. They are bounded by the same total.

## Decisions recorded

- Other writers: no change needed. No writer counted here stores the item another way.
- The driver data's form: declined, with the reasons above, in the backlog's declined list.
- A zip with local headers and no directory stays held as `archive unreadable or encrypted`. The
  maintainer decided this on November 19.

## Checks

The counts come from scratchpad scripts that read each package with `zipfile` and
`xml.etree.ElementTree`, then call `heuristics.base64_run_signals` and `heuristics._job_setup`
from this checkout. The scan used `scanner.scan_file`. None is committed; the method above is
the whole of each. `check_doc_links.py` passes.
