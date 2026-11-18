# Unlisted zip entries, V7 tars, and LibreOffice's printer setup

Date: 2026-11-18. Base: `669d618` (`main` after #289). Engine: YARA-X 1.23.0 (locked).
Two backlog rows: "Zip entries with a local header and no directory record; tar with no
`ustar` magic" and "LibreOffice's `PrinterSetup` item makes its own `.odt` or `.ods`
advisory". The maintainer asked for the second only after a count of real files, and without
an exemption broad enough to hide base64 in.

## Archive members other unpackers read

### Reproduced on the base

Inert samples built in the scratchpad from `samples.injection_markdown()` (the phrase rule's
note) and `samples.mini_pe()`. Each was read with the tools installed here, then scanned with
`scan_file` and the bundled rules.

| Sample | Java `ZipInputStream` / GNU tar, `tarfile` | Info-ZIP `unzip`, `zipfile` | `669d618`, default / `agent-ingest` | This branch |
| --- | --- | --- | --- | --- |
| A deflated entry ahead of a valid one-member zip | both entries | the listed one (`unzip` warns of 98 extra bytes) | **clean / clean** | advisory / block, `zip:1` |
| A deflated entry between two listed members, the directory's offsets correct | all three | the two listed | **clean** | advisory, `zip:2` |
| Control: the same payload as a listed member | | | advisory / block | unchanged |
| Local entries and no directory at all | the entry | refused | incomplete, `archive unreadable or encrypted` | unchanged |
| V7 tar (no `ustar` magic): a zip member, then 200 KB of log | both members | | **clean / clean** | advisory / block, `tar:0/zip:0` |
| Control: the same tar with `ustar` magic | | | advisory / block | unchanged |
| V7 tar: a PE named `invoice.pdf` | | | block (`heuristic_embedded_pe` only) | block, and `filetype_mismatch_pe` on `tar:0` as for ustar |

A V7 tar was read as one unit, so plain text in it was still matched; what went unread was a
member that needs opening (a zip, an Office file) away from the end of the archive, and every
member check.

### What changed

- `archive_kind` in `src/yara_gate/content.py` returns `tar` for a file whose first block
  `tarfile.TarInfo.frombuf` accepts with a name: the header test, checksum included, that
  `tarfile` and GNU tar make. The existing tar reader then reads it.
- `_unlisted_zip_entries`: after the listed members of every archive in the file are read, the
  bytes that no listed member or directory covers (`_zip_spans`) are searched for `PK\x03\x04`.
  A header counts when it is stored or deflated, has a 1 to 1,024 byte name, and its data fits
  in the file and inflates (a deflated entry with a data descriptor is inflated to its end, as
  `ZipInputStream` does; a stored one with a descriptor is refused, as there). Each counts as a
  member: the 1,000-member count, the name check (`..`, absolute, NUL), the encryption check,
  and the 100 MiB and 500 MiB limits through `Budget.read`. Ordinals continue after the listed
  members. A header that does not hold up is skipped as ordinary bytes.
- The stream-only zip stays incomplete. Reading it would turn a held file into a verdict,
  which is a change the maintainer would weigh.

### Checks on the change

`tests/test_hidden_members.py` holds the zip and tar cases. Edge cases run through
`scan_bytes`: an encrypted unlisted entry and one named `../notes.md` are incomplete as listed
ones are; 1,000,000 fake headers (method 8, sizes zero) ahead of a 2-member zip, 29 MB, scan
clean in 1.3 s with no extra member.

- **LibreOffice's test corpus** (2,089 OpenDocument files, all zips; below): 0 unit-count
  changes, so none holds an unlisted entry.
- **Every zip, jar, wheel, tar, and Office file installed here under 100 MiB** (655 found, 653
  readable: 365 jars, 135 zips, 123 tars, 21 wheels, 11 Office files), scanned on `669d618` and
  on this branch: 0 changed verdict, reason, or findings. 3 changed their unit count, from 1 to
  3: copies of Go's own `archive/tar/testdata/v7.tar` in two toolchains and the module cache,
  now read as the V7 tar they are. All stay clean.
- BROAD_RESULTS

## LibreOffice's PrinterSetup item

### The count of real files

Source: LibreOffice's own repository (`github.com/LibreOffice/core` at `068c54d`, 2026-11-18),
sparse checkout of `sw/qa`, `sc/qa`, and `sd/qa`: 2,089 `.odt`, `.ott`, `.ods`, `.odp`, and
`.odg` files, many of them documents attached to bug reports. Read as data; none was opened in
an office suite.

- 694 hold `<config:config-item config:name="PrinterSetup" config:type="base64Binary">` in
  `settings.xml` (456 `.ods`, 132 `.odp`, 77 `.odt`, 25 `.odg`, 4 `.ott`). 674 of those items
  are 400 base64 characters or more; the longest is 40,500.
- On `669d618`, 673 of the 694 are advisory. In 667 the only `agent_base64_blob` match is
  `settings.xml`, and all 667 hold the item; 655 have no other finding at all. `agent-document`
  and `agent-ingest` hold all of them.
- LibreOffice's bundled templates (120 here) hold none, as the backlog row said; the item is
  written when a document is saved with a printer set up.

### The format, from the writer

`WriteJobSetup` in `vcl/source/gdi/jobset.cxx` (read at `068c54d`): a u16 total length, a u16
system (`JOBSET_FILE605_SYSTEM` 0xFFFE, or 0xFFFF from older versions), `ImplOldJobSetupData`
(printer, device, port, and driver names, 160 bytes), `Impl364JobSetupData` (22 bytes, its own
size first and the driver data length at offset 4), the driver data, then length-prefixed UTF-8
key and value strings to the end. Of the 694, all 685 that are not the 4-character empty item
decode to exactly that: every length agrees and the strings end where the total says.

The driver data is the printer driver's own: 384 hold CUPS `JobData 1` text, the rest a
Windows `WNT3` block with a `DEVMODE`. It runs to 30,146 bytes, and to more than 4 KiB in 120
files. So the structure alone does not bound what the item can carry.

### What changed

`_printer_setup` in `src/yara_gate/heuristics.py`: a base64 run is not a blob for
`agent_base64_blob` when all of these hold:

1. it is the whole text of that exact `config:config-item` (the opening tag directly before
   it, at most two `=` and the closing tag directly after);
2. it decodes to exactly what `WriteJobSetup` writes (`_job_setup`);
3. the decoded bytes hold no executable header (`embedded_exec_offset`, the check behind
   `heuristic_embedded_pe`, at every offset) and no base64 run of 400 or more characters.

`agent_base64_executable` is unchanged. The rule's description and `docs/rules.md` say so, and
`check_rule_pairs.py` keeps the pair: the item with a PE in its driver data fires, the plain
item does not (`samples.printer_setup_settings`, written from the format above, not copied from
a LibreOffice file).

### Results

- **The corpus on the base and on this branch**: 0 findings added; 704 `agent_base64_blob`
  findings removed (one per view), all from the item. Advisory files 703 to 41: 662 now clean,
  13 keep another finding, 1 stays incomplete. The 8 blob findings left are other data: embedded
  fonts, signatures, object data, and a 17 KB base64 value in a spreadsheet formula
  (`tdf139974.ods`, `content.xml`).
- **Tampered copies of a real file** (`sc/qa/extras/testdocuments/ForEachInSelection.ods`, 3,514
  bytes of Windows driver data), through `scan_bytes`: unchanged, clean (advisory on the
  base); a PE written into the driver data, a base64 run written into it, the total off by one,
  and the same item under the name `PrinterSetupX` each stay advisory.

### What is left

- The driver data is opaque. Bytes that are neither an executable header nor a base64 run,
  such as encrypted data, pass inside a valid item, up to the 64 KiB the u16 total allows. An
  OpenDocument package already carries opaque binary without this advisory (pictures,
  embedded objects), so this is not a new kind of place, but it is one more.
- The test reads the bytes around the run, not the member name, so the same element in any
  file is exempt under the same three conditions.
- The 120 bundled templates and this corpus are LibreOffice's own; documents saved by other
  ODF writers were not counted.

## Checks

CHECK_RESULTS
