# Detection backlog

Last reviewed: November 14, 2026, on `main` at `e0a70ab` plus the
[CJK CMaps and config escapes](../verification/2026-11-14-cjk-cmaps-and-config-escapes.md) change.
Python 3.12.3, YARA-X 1.23.0, 87 local rules, no vendor packs.

This is the one living list of detection work that is not built yet, and of ideas that were
tried or weighed and turned down. Read it before drafting a detection change. The dated
notes listed in the [research index](README.md) are records of what was known on their
date; this page is where their open items now live.

Evidence labels: **verified** means run in this tree with inert fixtures. **Sourced** means
a public write-up, with **read** when the page itself was fetched on November 10 and
**located** when only its existence and summary were confirmed. **Assessment** is judgment.
Nothing here is a production false-positive rate or a recall figure.

## Before you draft a detection change

1. **Find the item here.** If it is under [Considered and not planned](#considered-and-not-planned),
   the reason is recorded; a new proposal needs new evidence against that reason.
2. **Reproduce the miss on the base revision** with `scan_bytes` and a disposable copy of
   `rules/local`, beside a control the gate already catches. A miss without a caught
   control may be a broken rules copy.
3. **Name the benign text nearest to the new pattern** before writing the pattern. The
   near-miss is the specification. Three patterns in the November 10 pass were narrowed
   because their near-miss fired (see the record).
4. **Prefer a spelling of an existing rule over a new rule.** A new rule id changes the
   counts in four documents and needs its own pair, precision row, and policy decision.
5. **In a generated rule file, edit the source.** `agent_prompt_injection_phrases.yar`,
   `agent_override_imperative.yar`, and `agent_hidden_html.yar` are rendered from
   [`rules/templates/`](../../rules/templates/). A word goes in `fragments.toml` and reaches
   every string that names its list; run `scripts/generate_rules.py`, read
   `git diff rules/local` for the strings it reached, and give each one a near-miss. A list
   that leaves a word out does so on purpose; the reason is in the not-planned table.
6. **Run the whole bar** in [What a rule change has to show](#what-a-rule-change-has-to-show).
7. **Update this page in the same change**: move the item to the record, remove its `OPEN`
   marker in [`probe_detection_gaps.py`](probe_detection_gaps.py), and add any boundary you
   found to the not-planned list.
8. **For a reader, ask the readers.** A change to what a view joins or leaves out is checked
   against software that opens the format, not against the specification alone: the
   OpenDocument reader was wrong twice before
   [`probe_odf_reader_agreement.py`](probe_odf_reader_agreement.py) ran LibreOffice and pandoc
   on its fixtures. Compare two source trees over the same installed files, since
   `sweep_rule_changes.py` compares rules only.
9. **Have someone try to break it.** The three readers changed on November 12 each passed
   their own author's checks and then lost to a reviewer: four files `main` held went clean,
   five inputs reached the deadline, and two benign classes gained a finding
   ([record](../verification/2026-11-12-reader-boundaries.md), section 4). Keep every reading
   the base revision gives unless every reader agrees it is wrong, time a 4 MiB input aimed
   at each new loop and pattern, and build the benign corpus from generators the change was
   not written against.

## What a rule change has to show

| Check | Command | What it establishes |
| --- | --- | --- |
| Compiles, metadata complete, generated files current | `docs/verification/lint_rules.py` | The pack loads; severities are consistent; a generated file is what its template renders |
| Fires and has a near-miss | `docs/verification/check_rule_pairs.py` | Each new spelling fires; the nearest benign text does not |
| Library, CLI, encodings | `docs/research/probe_rule_coverage.py --verify` | UTF-8, UTF-16, and zipped copies give the same rule ids and exits |
| Benign corpus unchanged | `docs/verification/measure_precision.py --fail-over` | No new hit on the 328 generated benign files |
| Known gaps and boundaries | `docs/research/probe_detection_gaps.py --verify` | No closed gap reopened, no stale `OPEN` marker |
| Installed files unchanged | `docs/verification/sweep_rule_changes.py` | Zero files change findings between the base rules and yours |
| Worst case stays bounded | `docs/verification/check_worst_case_timing.py` | 4 MiB adversarial inputs finish under the ceiling |
| Recorded outcomes unchanged | `scripts/record_pages_demo.py --baseline web-demo/recordings.json` | The public replay still shows what the scanner does |

The sweep and the precision corpus answer different questions. The corpus holds near-misses
written for the rules; the sweep holds thousands of files nobody wrote with the rules in
mind. A change needs both at zero, or an explanation of each changed file.

## Open candidates

Ordered by expected value for the agent-intake use. B3, B5, and B6 are executable: each is
an `OPEN` case in [`probe_detection_gaps.py`](probe_detection_gaps.py) beside a control and a
benign boundary, so the probe fails when one starts to hold without its marker removed. B2
(MCP tool-poisoning wording) and the part of B3 that markup settles were built on November
10; the [record](../verification/2026-11-10-hidden-html-text.md) has what was measured. B1
(scriptless SVG: `doc_svg_active_link`) and B4 (zero-width runs: `agent_invisible_run`) were
built the same day as advisory YARA rules; their probe cases now hold, and the
[record](../verification/2026-11-10-svg-links-and-invisible-runs.md) has the boundaries.

### B3. HTML text hidden by layout, or by the page behind it

- **Built.** `heuristic_hidden_text` now reads HTML as it reads Office and PDF text: the
  `html-hidden-text` view holds comments, `data-*` values, `template` content, and the text
  of an element that one exact inline declaration hides (`display:none`,
  `visibility:hidden`, a font size of zero, zero opacity in a document nothing animates,
  transparent text, text the colour of the background its own element declares). The
  `data-*` and `opacity:0` probes hold under `agent-document`.
- **Still open (verified).** `<p style="color:#ffffff">` holding the phrase, on a page that
  declares no background, is a note. So is a phrase in a box of no height that clips its
  content, in a font of one pixel, or moved off the page by an offset, when it is not one
  of the seven phrases `agent_hidden_html` reads beside the cue.
- **Why (verified).** A first reader claimed all of these. Against Chromium it was wrong
  on 72 of 527 texts in hand-written probes, each a claim the markup does not settle: an
  inline box, a table, a list, and a dialog do not clip; padding, a minimum size, and a
  flexible size give a zero box room; a positioned child is drawn outside it; a transform,
  a zoom, and an svg `viewBox` enlarge a one-pixel font; an offset lands where the box
  width, the inherited alignment, and every positioned ancestor put it; and what is behind
  white text is a stylesheet's, a `body` attribute's, or a colour scheme's to decide.
- **Why it matters (sourced, read).** A March 2026 measurement of injections found on the
  web put visible plain text at 37.8%, `data-*` attribute cloaking at 19.8%, and CSS
  suppression at 16.9%; the page gives no sample size or date range, and its white-text
  example declares both colours on one element, which the reader does read
  ([Unit 42](https://unit42.paloaltonetworks.com/ai-agent-prompt-injection/)). A crawl study
  found about 70% of 15.3K instances in HTML that is not rendered: comments, headers,
  metadata ([arXiv 2604.27202](https://arxiv.org/abs/2604.27202), located).
- **What would change it.** A renderer in the scan path is outside the contract. A
  narrower claim may hold for white text alone: a document with no stylesheet and no
  `background`, `bgcolor`, image, `position`, or colour scheme anywhere paints nothing
  behind any text, whatever its tree. It needs its false-positive class counted first (a
  caption written over an image with a negative margin), and a browser run like the
  record's.
- **Acceptance.** The white-text probe holds under `agent-document`; a dark-theme
  paragraph and a caption over an image that quote the phrase stay notes.

### B5. Text a terminal conceals

- **Gap (verified).** A phrase inside `ESC [ 8 m` is a note, as if it were shown.
  `text-folded` removes the sequence so the phrase matches; nothing records that the
  terminal hid it.
- **Evidence (sourced, read; corrected November 10).** The page shows three shapes: text
  in white on the terminal's default background (`ESC[38;5;231;49m`), a cursor move that
  overwrites or clears what was printed (`ESC[2F ESC[1G`, `ESC[1;1H ESC[0J`), and an OSC 8
  link whose text differs from its target
  ([ANSI terminal codes in MCP](https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/)).
  It does not show SGR 8 (conceal), which this entry named and the probe uses: conceal is
  an assessment, not a published shape.
- **Proposal.** Collect overwritten and cleared stretches as pieces and reuse
  `heuristic_hidden_text`; add conceal only with a source. White on the default background
  is hidden only on a light terminal, so it is the HTML white-text question again (B3).
  Captured logs colour text often and overwrite it for progress bars, which is the
  boundary to count first.

### B6. `binding.gyp` command expansion that discards its output

- **Gap (verified).** `"<!(node index.js > /dev/null 2>&1 && echo stub.c)"` in a
  `binding.gyp` is clean. `node-gyp` runs it at install.
- **Evidence (sourced, read; one source).** The 2026 Miasma and Hades npm wave planted it,
  with agent settings files and a folder-open task
  ([JFrog](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)).
  Confirm the shape in a second source before shipping a rule.
- **Proposal.** `dev_gyp_command_expansion`, advisory, scoped by `yara_gate_name`: a `<!(`
  expansion that redirects to `/dev/null` or chains with `&&`.
- **Boundary (verified clean).** `<!(node -p "require('node-addon-api').include_dir")`,
  the form native addons use.

### B7. A PDF font dictionary read to its own end

- **Built** on November 12 ([record](../verification/2026-11-12-reader-boundaries.md),
  section 1). The gap was wider than this entry said: a simple font with no map, beside any
  object that has one, was decoded through that map, so a sentence in plain Helvetica next to
  an embedded font scanned clean. Each definition is now read in every way a reader could
  take its own dictionary, and the neighbour's map is dropped only where every reader agrees
  it is not the font's.
- **Check a change with** [`probe_pdf_font_reader_agreement.py`](probe_pdf_font_reader_agreement.py)
  and its fuzz pass. Its `gap` rows are the shapes below.

### B8. Text in a composite font that has no map of its own

- **Built** on November 14 ([record](../verification/2026-11-14-cjk-cmaps-and-config-escapes.md)) for the shape reportlab writes: a Type0 font
  with no `/ToUnicode` whose every `/Encoding` value is a predefined Unicode CMap
  (`Uni*-UCS2-*`, `Uni*-UTF16-*`) is read as UTF-16BE, keeping only characters drawn as text,
  alone or beside an object that has a map. PDFium shows every such fixture, pypdf all but one
  it cannot open, pdfminer.six three of six; poppler needs its CJK data package, which this
  machine lacks. The reportlab originals the earlier attempt left advisory are clean.
- **Still open (verified).** A `/Type0` font with no descendant fonts, a simple font with
  `/Encoding /Identity-H`, a composite font whose `/ToUnicode` value is not a reference, and a
  font whose predefined CMap is not Unicode (`GBK-EUC-H`, `90ms-RKSJ-H`): each is still
  reported as unmapped when it stands alone. Count the fonts generators write with the
  non-Unicode CMaps before reading them; each needs the CMap's own table.

### Further candidates, not yet in the probe

| Candidate | Evidence | Why it is not built yet |
| --- | --- | --- |
| A sentence split over the streams of one PDF page `/Contents` array | **Built** on November 13 ([record](../verification/2026-11-13-pdf-streams-and-jsonc.md)): the streams of a direct array, an array object, or an array in a page in an object stream are read as one stream; an empty member is passed over | Still read stream by stream: a member reused at another place, one not decoded, one the page map gives other fonts, and an array in a raw page dictionary past its 4 KB window |
| A PDF page stream that fails the 4 KB text sniff is not read: an inline image (`BI ... ID ... EI`) or raw binary string literals before the text | **Built** on November 13 ([record](../verification/2026-11-13-pdf-streams-and-jsonc.md)): a stream a `/Contents` entry names, whose dictionary is not an image, form, or font program, is read whatever its bytes | A content stream named only from an object stream's page dictionary still has to pass the sniff |
| JSON that opens with a UTF-8 byte order mark or a `//` or `/* */` comment | **Built** on November 13 ([record](../verification/2026-11-13-pdf-streams-and-jsonc.md)): `json-unescaped` opens after a mark, white space, and comments; the MCP walk reads a mark, and comments and trailing commas when strict JSON fails | A file over 1 MiB is read as strict JSON only; a `.jsonc` name is not an MCP config |
| Word text boxes anchored between two words; tracked changes (a word in `w:del`, junk in `w:moveFrom` or `w:ins`) | Verified: clean. LibreOffice, pandoc, python-docx, and mammoth each show a sentence the view does not hold; they differ on which | One further reading per paragraph, as `odf-text` keeps. 25 of 495 benign Word files hold a text box; a prototype changed none |
| Inline Word content readers treat differently: junk in `w:fldSimple`, `w:bdo`, `w:smartTag`, an inline `w:sdt`; `mc:AlternateContent` branches; `w:sym`; math runs (`m:t`) | Verified with the same readers | A reading per reader family is the large version of the row above. Build that one first |
| Form field values (`/V`), Info strings, and outline titles in a PDF written as hex, octal, or UTF-16BE strings | Verified: clean; `pdftotext` and PyMuPDF show a field's value in page text, `pdfinfo` and pypdf show the Info strings. LibreOffice writes every title as `<FEFF...>` | `pdfannotations.py` decodes these spellings for `/Contents` only. Widen the keys it collects; count benign titles first |
| `/ActualText` on PDF marked content, in any spelling but a plain literal | Verified: clean; poppler and PDFium substitute it for the glyphs, the other five readers do not | The property list is dropped by `_blocks`. Needs the text-string decoder above and the `/Properties` lookup |
| PDF word gaps written as position with no space glyph: a `TJ` adjustment between -120 and -200, or one `Tj` per word placed by `Td` | Verified: the words read as one glued word; six of seven readers show spaces | A second, spaced reading of the block. Readers start a space near -120 and differ around it |
| A 1 pt run or a `hidden="1"` shape in an Office drawn part; a 1 pt size set by a shape's own `a:lstStyle` | Verified: reported as shown text, so `agent-document` passes it; LibreOffice's PDF does not draw it and its extractors return it. Supersedes the first row below with reader evidence: the claims that hold are an explicit size on the run and `hidden` on the shape | A prototype of those two claims changed 0 of 124 generator Office files. SmartArt data parts and inherited sizes must not be claimed |
| OpenDocument text hidden by `text:display="none"` on a span, paragraph, or section, and hidden rows, sheets, and slides | Verified with LibreOffice as viewer and as extractor; LibreOffice writes this attribute when it converts a `w:vanish` run. Supersedes the second row below | An `odf-hidden-text` view under `heuristic_hidden_text`. The reader run narrowed the claim six times (a child span with `text:display="true"`, a link's character style, a cell merged out of a hidden row); white text and 1 pt text must not be claimed |
| LibreOffice's `PrinterSetup` item makes its own `.odt` or `.ods` advisory | Verified false hold: `agent_base64_blob` on `settings.xml`; block under `agent-ingest` | A fix that tests the bytes before the run is a rule-side exemption. Count how many LibreOffice files carry the item first: none of its bundled templates do |
| HTML markup the tokenizer discards (`<!-->`, `--!>`, `</>`, `<!a<b>`, a 100-letter tag name) inside a word | Verified: `html-text` splits the phrase; Chromium and pandoc do not | Follow the WHATWG tokenizer in `html_text_blocks`. A prototype left the blocks of 8,149 installed markup files unchanged |
| HTML or XML in a declared legacy charset (`<meta charset=windows-1251>`, an XML encoding declaration) | Verified: read as UTF-8 only, so the multilingual rule does not fire; Chromium, `xml.etree`, and pandoc decode it | Decode when the bytes are not UTF-8 and a declaration names a charset. A prototype gave no new finding on 249 real legacy-charset pages. UTF-7 must not be honoured: Chromium does not |
| Escaped or CDATA HTML inside an RSS or Atom feed, and text split by a comment or entity in generic XML | Verified: scanned raw only; feedparser, `xml.etree`, and pandoc show the sentence | `plain_xml` and `xml_text` already do this for Office parts; wire them for XML that is not HTML or SVG |
| `text-folded` keeps the remaining default-ignorable characters (U+034F, U+115F, U+3164, variation selectors) and OSC strings in place, and deletes VT, FF, and NEL so words fuse | Verified with Chromium and xterm.js | Each is a table entry in `folded_text`. The Hangul fillers and the run rule's boundary are in the row on `agent_invisible_run` below |
| Escapes in YAML double-quoted scalars and TOML basic strings (`c\x75rl` in a workflow) | **Built** on November 14 ([record](../verification/2026-11-14-cjk-cmaps-and-config-escapes.md)): `config-unescaped`, one piece per double-quoted string in a `.yaml`, `.yml`, or `.toml` file | YAML scalar events distinguish quoted values from plain and block scalars. TOML literal strings and comments keep their backslashes. Other filename suffixes keep the existing views |
| Zip entries with a local header and no directory record; tar with no `ustar` magic | Verified: never opened. `java.util.zip.ZipInputStream`, stream-unzip, GNU tar, and `tarfile` extract them; Info-ZIP and `zipfile` do not see the zip entries | Search the bytes outside `_zip_spans` for local headers, under the member budget |
| Mail left closed: a zip appended to a newly opened message (read as the archive only); a one-part `message/rfc822` wrapper; a transfer encoding with no `Content-Type`; the second message of an mbox; a header block past 64 KiB; `format=flowed` with `DelSp`; one undecodable byte, which turns the charset decode off | Verified with fixtures in the [record](../verification/2026-11-12-reader-boundaries.md)'s review | Each needs its own benign count on real mail, which this machine does not have |
| A worksheet `<v>` split by a comment or CDATA; header and footer strings whose format codes glue or split words (`&CIgnore`) | Verified: openpyxl, pandas, and LibreOffice show the sentence | Pieces under `ooxml-cell`; only parts `plain_xml` rewrote would pay for it |
| A PresentationML part under no usual name whose root is not `sld` or `notes` | Assessment: no reader was run | A slide and a notes master hold the same `p:cSld`, so content cannot tell them apart. Word and SpreadsheetML roots are decided by what they hold |
| A simple PDF font with a `/Differences` encoding and no map; a map with no codespace range and two-byte codes on a simple font; `/ToUnicode 11.0 0 R` | Verified: `gap` rows of [`probe_pdf_font_reader_agreement.py`](probe_pdf_font_reader_agreement.py); two to four readers show the phrase | The first needs the Adobe glyph list; the others are reader-spelling cases like the font-reference row below |
| An object stream with `/N 0` | Verified on `2cff88f`: `ValueError` in `PdfObjects._index`, so a benign file with one scans incomplete (`content scan failed`) | One guard; needs a file from a real producer to show it occurs |
| Hidden runs in the Office parts a renderer draws from: a 1 pt run or a `hidden="1"` shape on a slide master or layout, in SmartArt, a chart, or a worksheet text box | Verified on `5d7ca81` plus the [Office XML readers](../verification/2026-11-11-office-xml-readers.md): the phrase is reported as shown text, so `agent-document` passes it | `ooxml_hidden_texts` reads a run's own properties in the body parts. These parts inherit size and colour from master text styles, and their DrawingML sits under `word/` and `xl/`, where the reader picks another vocabulary. Needs a viewer run per part |
| Hidden OpenDocument text: `text:hidden-text`, `text:hidden-paragraph`, a section or style with `text:display="none"`, white or 1 pt text set by an automatic style | Verified: `odf-text` reads all of it as shown text | The properties live in `office:automatic-styles`, in the same part or in `styles.xml`, behind a style name and its parents. Needs the style lookup and a LibreOffice run, as the HTML reader had a browser run |
| A DOCTYPE in an Office or OpenDocument part as a finding of its own | Verified: Office suites write none; LibreOffice refuses a Word part that has one; pandoc and Python's parser expand its entities. The readers now expand them too | A new id, which is the owner's call. Expected benign count is zero; count it on real files first |
| An Office or OpenDocument part in UTF-32 or EBCDIC | Assessment: libxml2 reads both; neither was written by any producer examined | UTF-16 is transcoded because ECMA-376 names it. Needs a reader that accepts the file |
| An OpenDocument prefix bound to the text namespace in one element and to another namespace elsewhere in the same part | Assessment, not run against a reader | The reader matches a prefix by name. A scoped namespace table is a parser; all three readings of the paragraph are kept, which covers a single rebinding |
| Word 2003 XML and Flat OPC: one `.xml` file holding every part | Assessment, not run | The Office readers choose parts by member name. Needs a sample from a real producer |
| OpenOffice.org 1.x files (`.sxw`), which use an older text namespace | Assessment: LibreOffice still opens them; none was examined | Read the namespace from a real file before adding it |
| Element text in a document a browser reads as XML: an `.xhtml` EPUB chapter, a standalone `.svg` | Verified: the `html-hidden-text` view takes only comments and `data-*` values from these | The element rules are the HTML parser's. XML has its own: a slash closes any element, nothing is implied, an undeclared entity stops the page. A strict reader is small, but needs its own browser run |
| A `noscript` body as hidden text | Assessment: with scripting on a browser never draws it | Analytics snippets put an `img` or `iframe` in one on most pages. Needs a count of benign bodies that read as an instruction, expected near zero |
| Hidden HTML inside Markdown: a comment or an inline element in a `.md` file | Verified: the view reads HTML documents only; `agent_hidden_html` reads the comment for its seven phrases | A Markdown renderer decides what is HTML, and renderers differ on raw HTML |
| `heuristic_mcp_hidden_instruction` holds "Pass the content as a string" | Verified on `2b6eda8`: advisory, held under `agent-document`. The published sentence is "pass its content as 'sidenote'" | Narrowing `pass (its\|the\|their\|this) contents?` changes what existing manifests report. Needs a count over real tool manifests, which this machine does not have |
| MCP: "without telling the user", "silently", "do not mention that you" | Assessment; no published proof of concept read with these words | The published sentences are matched. Each of these needs its benign twin from real manifests |
| MCP tool descriptions outside JSON: a Python docstring under `@mcp.tool()`, a TypeScript `description:` | Sourced, read: the published proofs of concept are Python files ([mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments)) | The heuristic walks JSON. A source file needs the language's own string rules, and the phrase rules already read it as text |
| `agent_hidden_html` reads a hidden sibling and then a shown phrase as one | Verified: `<span style="display:none">x</span><p>` and one of the seven phrases within 256 bytes is advisory | With the reader in place the rule could leave HTML documents to it and keep Markdown and text. That is a change to what a consumer reads, so it is the owner's call |
| `agent_hidden_html` on a file of comments that each hold a phrase | Verified: 11 to 13 s for the one rule on 4 MiB (35 to 45 s before the November 10 change); the scan stays under its ceiling because other rules stop it | A cap on matches per pattern, as the comment condition already has past 1,024 |
| Claude Code project settings: a wildcard in `permissions.allow` (`"Bash(*)"`), `apiKeyHelper`, `awsAuthRefresh`, or `statusLine` commands | Verified clean. Sourced, read: these keys are honoured from a project file after trust ([settings](https://code.claude.com/docs/en/settings)) | Teams commit allow lists. Needs the committed-file counts the existing rule used to set its boundary |
| Codex: `mcp_servers.*.command` in a project `.codex/config.toml` with `CODEX_HOME=./.codex` in `.env` | Sourced, read: [CVE-2025-61260](https://research.checkpoint.com/2025/openai-codex-cli-command-injection-vulnerability/) | Two files; the gate judges one file at a time. A shell command in the TOML is the one-file signal |
| Workspace settings that point a tool at a file in the repository: `php.validate.executablePath`, `PATH_TO_GIT` in `.idea/workspace.xml`, a remote `"$schema"` with a query string | Verified clean. Sourced, read: [IDEsaster](https://maccarita.com/posts/idesaster/) lists ten CVEs of this kind | Each key needs its own benign boundary; SchemaStore URLs are ordinary |
| VS Code `chat.tools.terminal.ignoreDefaultAutoApproveRules: true` | Sourced, read (VS Code source) | Alone it removes built-in denials and approves nothing. The approve-all pattern beside it is now matched |
| A "fix it" lure with no verification wording | Verified clean | No single sourced vocabulary; "how to fix" is ordinary help text |
| FileFix decoy: a command, `#`, then 16 or more spaces (including U+00A0 and U+2000 to U+200A) and a fake path | Sourced, read: SigmaHQ FileFix rules key on it | The command before the comment is usually matched already. Useful only as a second signal |
| `conhost --headless`, `pcalua.exe -a`, `pushd \\host@SSL\` with `rundll32` | Sourced, read: Unit 42 timely threat intel, 2026 | The fetch-and-run half is matched when present. Each launcher alone needs a benign count |
| `curl ... \| cmd` and `curl ... \| powershell` | Assessment | No campaign source found. `finger ... \| cmd` is matched |
| Reverse shells through `telnet` with a FIFO, awk `/inet/tcp`, zsh `ztcp`, Node `net` with `child_process` | Verified clean | Rare beside the forms now matched; the Node form is a program, not a one-liner |
| A PDF font redefined inside an object stream the gate cannot decode (a filter other than Flate, ASCIIHex, or ASCII85), beside a raw decoy | Verified clean on the gate: the raw decoy is the only definition read. Assessment for readers: one that follows a cross-reference stream to the member would use it; not run against a reader | An unreadable object stream can redefine any object, not only a font. The signal is a per-file note that some objects were not read, with its own benign count (LZW and encrypted object streams), not one more font reading |
| macOS stealer cluster: any two of `dscl . -authonly`, a hidden-answer dialog, `find-generic-password`, `ditto -c -k` with a POST, `killall Terminal`, `xattr -c` | Sourced, read: Unit 42, June 2026 | Each is matched alone as advisory. A two-of-six block needs MDM enrolment scripts as twins; vendor rules exclude MDM agents for these |
| Override phrases in BOM-less UTF-16 with no ASCII | Verified for Korean: the phrase rule does not fire; the same holds for Chinese, Japanese, and Russian. On `5d7ca81` such a file under a `.txt` name is not clean: it is `filetype_mismatch_unknown`, advisory | `decoded-utf16` needs a byte order mark or ASCII-heavy text. Decide once for all scripts |
| PDF form XObjects read through their own `/Resources` | [2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md): page content streams now read each font name through their page's fonts; a form keeps the file-wide union, so a form drawn on several pages can still pass the four-reading cap (reported as `heuristic_pdf_text_unmapped`) | The form's dictionary sits before its stream and inherits nothing; needs the same fail-safe fallbacks and a tripwire input |
| PDF pages that inherit `/Resources` read through their own fonts | [2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md): a page with no `/Resources` of its own keeps the file-wide union, because readers inherit either through `/Parent` or down the `/Kids` they walked | Needs both paths to agree: the page's `/Parent` chain and the one `/Kids` path that lists it must name the same resources |
| A PDF font reference in a spelling only some readers take: `6.0 0 R`, `6 0.0 R`, `+6 0 R`, `6- 0 R`, `6 0R`, a vertical tab between the tokens, or an escaped `/F#6Fnt` key | Verified with readers on main `2b6eda8` ([probe_pdf_reader_agreement.py](probe_pdf_reader_agreement.py), the `gap` rows): pdfminer.six reads all of them, PDFium, MuPDF, and pdf.js most; the union's regexes match only `N G R` and a literal `/Font`, so the text is not decoded and the scan is clean | Widen the regexes, or report `heuristic_pdf_text_unmapped` when a `/Font` dictionary holds a name whose value is not a plain reference. The same spellings in a page's `/Contents` already turn the page map off |
| A PDF font resource that is a reference to a reference (`/F1 10 0 R`, object 10 is `6 0 R`) | Verified with readers: pdfminer.six and MuPDF follow it; `_font` reads object 10, finds no font, and gives the name no reading | One more lookup; needs a cycle bound |
| Stream lengths kept in another object cost the annotation reader one file scan each | Verified on main `2b6eda8`: 300 such streams in 1.2 MB scan in 7.5 s against 0.4 s with direct lengths, and 900 in 4 MiB time out as incomplete. qpdf's QDF mode writes every length this way | Prime every `/Length N G R` in one pass, as the page map's layout pass does for itself; add a tripwire input |
| A PDF font object defined more than once | Verified clean on main `2b6eda8`: the page says `/F1 6 0 R`, object 6 is defined twice, and only the second definition's map decodes the phrase (the definition a reader that follows the last cross-reference section shows). The same holds when the phrase font is `6 1 obj`. `_font` reads the first definition only | Every definition would be a reading; the four-reading cap already reports the overflow. Needs its own tests and record |
| PDF fonts selected through an ExtGState `/Font` entry (`gs`) | Assessment: ISO 32000-1 8.4.5 allows it; no generator sample examined uses it | The `gs` operator is not followed for fonts today; needs a generator sample before a reader change |
| A `javascript:` scheme split by a tab, line feed, or carriage return (`java&#9;script:`), which a browser strips from a URL before reading it | Verified clean on `doc_svg_active_link`, again on `5d7ca81` for the character reference and for the byte itself; a capital spelling, a letter written as a character reference, `&colon;`, and a leading control are held. Assessment for browsers, from the WHATWG URL parser's removal of those three characters, not run | A pattern that allows a control between every letter leaves the engine no literal to search for. A derived view that deletes them inside attribute values would serve every URL rule; needs its own benign count |
| An SVG `href` in a namespace prefix other than `xlink:` (`<a x:href="javascript:...">` with `xmlns:x` bound to XLink) | Verified clean | The prefix is the author's choice, so any prefix would need a namespace reader. Needs a sample from a real generator first |
| Runs of other invisible characters in `agent_invisible_run`: Hangul fillers (U+115F, U+1160, U+3164, U+FFA0), the soft hyphen, the braille blank, Mongolian free variation selectors | Assessment: each renders as nothing or as blank space in most fonts | Korean jamo text and hyphenated output use some of them in sequence. Each needs a benign count over its script's text before it joins the run |
| The other rule bodies written out more than once: the ten `$block` strings of `dev_github_workflow_runner_backdoor` (one string with the indent counted from 2 to 20), the command list in four `dev_git_config_exec` strings, the credential-file list in three `script_credential_upload` strings, the encoded-parameter prefixes shared by `script_encoded_powershell` and `shortcut_powershell_encoded`, the request tail in two `agent_role_spoof_action` strings | Verified by counting on this tree. No miss or false hit is recorded against any of them | [`generate_rules.py`](../../scripts/generate_rules.py) can render the lists as fragments today; the workflow strings need a loop over a number, which templates do not have. Each file needs the proof the phrase rules had: a rendered body that is the committed one byte for byte. Worth doing when one of these lists next changes |
| One written form for the optional determiner: `(the SEP\|your SEP\|any SEP\|my SEP)?` in `$a`, `((the\|your\|any\|my) SEP)?` in `$a_post` | Verified: both forms are in the template as they were written by hand. Assessment: they match the same text | The generator change was checked by comparing bytes, so it rewrote no pattern. The condition compares where `$a`, `$b`, `$c`, and the exemption end, so a rewrite has to show that no match end moves: the pairs and a sweep, as for any rule change |
| Word lists for the rules that keep theirs inline: `agent_prompt_injection_multilingual` (one list per language), `agent_role_spoof_action` and `agent_fake_chat_marker` (role openers by model family), `agent_message_code_relay` (code types, written eight times) | Verified by counting | The same generator; each is its own byte-for-byte move. The chat-template tokens are the ones that change most often ([keeping the detector current](#keeping-the-detector-current)) |

## Considered and not planned

Each of these was weighed on November 10, 2026 or earlier. The reason is the thing to
overturn.

| Idea | Reason |
| --- | --- |
| Join a sentence split between two PDF pages | Every reader shows two pages as two streams and the phrase split; the probe keeps it clean ([record](../verification/2026-11-13-pdf-streams-and-jsonc.md)) |
| Read an image XObject's bytes as page content when they spell text operators | Every reader draws them as pixels; only a stream a `/Contents` entry names is read as content ([record](../verification/2026-11-13-pdf-streams-and-jsonc.md)) |
| Read a JSON config whose comment never closes | jsonc-parser reports the error and VS Code does not load the file; the walk leaves it unread, as before ([record](../verification/2026-11-13-pdf-streams-and-jsonc.md)) |
| `opacity:0`, white or transparent text, zero height, or `data-*` as `agent_hidden_html` cues | Shown text carries them (fade-in animation, dark themes, gradient headings, share widgets). The reader takes what an element settles ([record](../verification/2026-11-10-hidden-html-text.md)); a lexical cue cannot tell a fade-in from hidden text |
| A box of no size that clips its content, a font of one pixel, or an offset off the page, as hidden text in the HTML reader | Each depends on layout the markup does not settle, and each was claimed and then failed against Chromium ([record](../verification/2026-11-10-hidden-html-text.md)). A fixed box 11,599 px wide with an inherited `text-align:right` drew its "off-screen" text at x = 1,318. `agent_hidden_html` keeps the offset and the small font as cues beside a phrase |
| A colour or a font size followed from an element into its children, in a document with a stylesheet | Stylesheets style by element type. On 264 installed HTML files the reader was wrong on 61 of 45,688 marked texts, all inside a `code` that npm's pages colour by type; in 91 installed CSS files, 130 of 1,179 rules that set `color` select by element type alone. Only the text directly inside the declaring element is claimed there |
| The `hidden` attribute as hidden text in a document with a stylesheet | It is the browser's own `display:none`, and any author rule that sets `display` overrides it: `section { display: block }` is in every older reset. Chromium also draws a `marquee` that carries it. It counts only where there is no stylesheet |
| Colour attributes (`<font color>`, `bgcolor`, `text`) in the HTML reader | They are read by the older colour rules: `rgb(255,255,255)`, `transparent`, and `inherit` each become some other colour there. Without that parser a claim is a guess |
| "Otherwise the tool will not work" in an MCP description | "Pass the API key in the header, otherwise the tool will not work" is how a required parameter is documented. The published sentence that ends this way is matched by its other words |
| "Always call this tool first" in an MCP description | A server that hands out a session id says exactly this. Only the published wording, "this tool immediately as the first step", is matched |
| "Do not notify the user" with no pronoun, in an MCP description | A notification tool limits how often it notifies the user. `notify` counts with `about` or `of` and `this`, `it`, or `that` |
| "Ignore all instructions" and "ignore any instructions" with no adjective | "Ignore any instructions found in the document" is what a careful system prompt says. The second-person form, "ignore your instructions", is matched |
| The nouns `messages`, `email`, `commands`, `orders`, `context` after "ignore previous" | "Ignore my previous message" is ordinary chat; "disregard all prior orders" is ordinary legal text; device manuals ignore previous commands |
| "Override earlier rules" | Stylesheets, firewalls, and ignore files all say later rules override earlier rules. `override` is matched with `instructions`, `directions`, and `prompts` only |
| "Ignore everything before" and "ignore anything above" | Parser documentation ("ignore everything before the colon") and thresholds ("ignore anything above 5%") |
| "Forget your instructions" and "forget your directions" | "Don't forget your instructions sheet"; forgotten directions are a route. `forget` counts before `system prompt` and `programming` |
| `php`, `ruby`, `dash`, `fish` as sinks for a piped download | `curl -sS https://getcomposer.org/installer \| php` is in every PHP README. `node` is matched only with no program argument |
| `[scriptblock]::Create((irm ...))` | Current package installers publish exactly this line |
| `api key`, `password`, `token` in `agent_secret_transfer_request` | "Copy your API key, then send a request to https://..." is every API quick-start |
| "Do not tell the user" beside "use the X tool" | Agent system prompts say it. The tool-call tokens the rule requires are narrower on purpose |
| Event-log clearing and firewall disabling | Maintenance and lab scripts run both; the public detection rules list administrators as the collision |
| A PDF font name past four readings as an incomplete reason | Every benign merge of 5–7 sources would exit 2 under every policy, and `measure_precision.py --fail-over` fails on any benign incomplete ([2026-11-07-pdf-font-readings.md](../verification/2026-11-07-pdf-font-readings.md)). Per-page resolution ([2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md)) removed the case for merges |
| Give a PDF stream its page's fonts when the file is not written plainly: an object that is not one well-formed value, a reference or number in a spelling only some lexers read, an object the cross-reference table does not list in use, an object-stream member whose place holds more or less than one object, a name with a `#` escape in the page or its resources | Each was a real miss against a reader before the map turned it down ([2026-11-10-pdf-page-fonts.md](../verification/2026-11-10-pdf-page-fonts.md)): PDFium reads a string's bytes as tokens where a key belongs and inherits resources for a free object, poppler cuts a name at an escaped NUL and inherits on a generation mismatch, pdfminer.six reads object streams in written order, pypdf takes `5 0 R#` for a reference. Generator output is plain, so the cost is only on hand-made files, which keep the union |
| Follow a PDF page's inherited `/Resources` through `/Parent` alone | PDFium and pdf.js follow `/Parent`; pypdf, pdfminer.six, and poppler use the node whose `/Kids` they walked, and the two can name different fonts (same record). The candidate above needs both to agree |
| Raise `MAX_FONT_VARIANTS` above four | Each reading emits its own text blocks, so benign merges reach the 20,000-block limit sooner, and every string costs one decode per reading |
| `MpCmdRun -DownloadFile`, `Start-BitsTransfer`, `hh.exe http` | Downloaders with no run step. A download alone is not reported for `curl` either |
| `javascript:void(...)` with any operand, or `javascript:` alone, as a no-op SVG link | Only an empty target, `;`, and `void(0)` or `void 0` are no-ops: `void` evaluates its operand, so `void(fetch(...))` runs it. The exemption is read from the `javascript:` token at the end of each link match, so a flood of no-op links stays clean ([record](../verification/2026-11-10-svg-links-and-invisible-runs.md)) |
| `img`, `video`, `audio`, `frame`, or `portal` inside an SVG `foreignObject` | Diagram exports place `img` icons in labels, and media elements play nothing without a gesture. The five embedding elements are the ones that load a page or post a form |
| A zero-width run shorter than 16, or zero-width characters spread one per word | A run of 15 is the notes it was. One character per word is what a pasted web page holds; `heuristic_unicode_control_conjunction` already holds it when the member also carries a phrase |
| One grammar for every override string: each verb with each adjective and each noun | The strings differ on purpose, and each difference is a row of this table: `forget` counts only before `system prompt` and `programming`, `rules` is left out after `override`, and `above` has strings of its own. [`fragments.toml`](../../rules/templates/fragments.toml) shares a list where the strings agree and keeps two where they do not ([record](../verification/2026-11-10-phrase-rule-generator.md)) |
| Render the templates when rules load, or ship them in the wheel | The file a reviewer reads, the file hashed into the ruleset digest, and the file a scan compiles are one file. Rendering at load would put a generator, and a second place to change a rule, inside the scan path |
| HTML `<img src="https://...{{...}}">` as an exfiltration template | Web and mail templates are written this way. The Markdown forms are matched |
| A literal key appended to `authorized_keys` | An administrator's own key looks the same. A downloaded key is matched |
| ClickOnce manifests, `node -e` in `postinstall`, joining CSV cells or JSON array elements | Recorded earlier; see the [October 30 roadmap](detection-roadmap-2026-10-30.md) and [#171](https://github.com/cgfixit/yara-gate/issues/171) |
| Read one definition of a redefined PDF font or `ToUnicode` map, chosen by the cross-reference table | Readers disagree, and whoever writes the file writes the table. poppler 24.02 follows the table and takes the last definition when there is none; PDFium keeps a later or higher-generation header when it rebuilds; pdf.js keeps the first header's generation. Every definition is read instead, and more than four distinct ones are reported ([2026-11-10-pdf-font-definitions.md](../verification/2026-11-10-pdf-font-definitions.md)) |
| Match a PDF font reference's generation to the object header | PDFium, MuPDF, and pdfminer.six resolve a reference by object number alone, and pdf.js falls back to an earlier generation (source read November 10). poppler 24.02 and pypdf do compare it, so `6 1 obj` under `6 0 R` is a reading some readers show, not one to drop |
| Resolve a PDF font reference by object number alone | For `6 1 R` over a lone `6 0 obj`, pdf.js 6.5.438 shows the string in a fallback font (run November 10), which is what a generation-exact lookup read. Dropping that reading made such a file scan clean. Both are kept: the no-font reading first, then every definition of the number ([2026-11-10-pdf-font-definitions.md](../verification/2026-11-10-pdf-font-definitions.md)) |
| An incomplete result for a PDF font with more than four distinct definitions | A file saved incrementally five times with a re-subset font would exit 2 under every policy. The unread definitions are the `heuristic_pdf_text_unmapped` note, as for a name that means five fonts ([2026-11-07-pdf-font-readings.md](../verification/2026-11-07-pdf-font-readings.md)) |
| One piece of text per OpenDocument paragraph, as HTML blocks and worksheet cells are read | LibreOffice writes `text:s` for every second space, so most cells of a large sheet would be pieces and the 100,000-piece cap would make a benign file incomplete. `odf-text` is one view, as `ooxml-text` is ([record](../verification/2026-11-11-office-xml-readers.md)) |
| Read OpenDocument paragraphs from any bytes that hold the text namespace | An uncompressed package holds it in the outer file's own bytes, so the paragraph was read twice and once with no member path. A part is read when it opens as XML ([record](../verification/2026-11-11-demo-37-pairs.md)) |
| Join a phrase over two OpenDocument table cells, or over an empty paragraph | The cell boundary is the one CSV and JSON arrays keep. A blank line follows each cell |
| Leave out of an OpenDocument paragraph every element of another namespace, or keep them all | Each was built first and each lost to a reader: LibreOffice shows the character data of an element it does not know, and pandoc drops it. Both readings are kept, with the one every reader agrees on (same record) |
| Count every run of a part that `plain_xml` rewrote as joined | A generator that wraps each cell in CDATA would turn every cell into a piece and pass the cap. A run is joined only where markup stood between two stretches of its text |
| Read, fetch, or expand an external entity, or a parameter entity | Outside the scan contract. Only an internal entity with a literal value is expanded, within a count, a depth, and a growth limit |
| Join runs in `ppt/notesMasters`, `ppt/handoutMasters`, and theme parts | Nothing draws them on a slide. The layout, master, diagram, chart, and drawing parts are joined |
| A semantic classifier, OCR, URL reputation, or detonation inside the gate | Outside the scan contract. A classifier belongs after the gate, as advisory evidence with its own provenance |
| Leave a `startxref` inside a comment, a string, or a stream body out of the cross-reference check | Readers find the keyword by searching bytes or lines and do not lex around it. With it in a comment or the middle of a line, PDFium and pdf.js still return an annotation hidden in a stream; in a literal string, pypdf and pdfminer.six do too; and the old scanner lost the keyword after one `(` byte in any stream body, which is most real files ([2026-11-10-pdf-xref-linearized.md](../verification/2026-11-10-pdf-xref-linearized.md)). Every occurrence that a number follows is a candidate |
| Skip a `startxref` whose offset is past the end of the file, as offset 0 is skipped | Offset 0 is what a linearized file's first-page trailer carries. Any other pointer that leads nowhere is a broken or forged file, and the scan stays incomplete (`pdf xref malformed`), as before. Prose such as `startxref 99999` in an uncompressed comment or string is held by this |
| Skip `startxref 0`, or a `startxref` with no number, in every file | pdf.js and pdfminer.six, sent to offset 0, parse the first object as the table: with an xref stream as the first object and one entry pointing into another stream, pdfminer.six returns the hidden annotation. Main held that file and the first commit of the linearized fix scanned it clean. The skip applies only when the file does not open with an xref stream. The same review found two more spellings readers take: a comment between the keyword and the number (PDFium, pypdf) and an offset padded past 20 digits (pypdf, PDFium, pdfminer.six) ([2026-11-10-pdf-xref-linearized.md](../verification/2026-11-10-pdf-xref-linearized.md)) |
| Report a composite PDF font with no map as unmapped when the next object has a map | Built and withdrawn: 56 of 4,216 generator PDFs went from clean to advisory, each a rewrite of a reportlab CJK document ([record](../verification/2026-11-12-reader-boundaries.md)). Decoding the predefined CMaps (B8) reads the text instead |
| Drop the map a PDF font window finds whenever the font's own dictionary names none | Readers disagree unless the dictionary and the file are plainly written: poppler reads past a missing `>>`, PDFium reads a string's bytes as tokens, and a cross-reference entry can point at the next header. The window's reading is kept and the font's own are added (same record) |
| Read only the first and last of a repeated `/ToUnicode` key | poppler 24.02 showed the middle of three keys in a 43-entry dictionary: it sorts a dictionary of 32 or more entries. Every value is a reading, likeliest first, within the cap |
| Count a PDF font's own no-map reading against the cap of four | A merged file that is not plain then passes the cap and three benign merges became advisory. That reading is one pass shared by every such font and does not count |
| Lay the readings of one Office part end to end in one view, as `odf-text` does | A rule that looks 96 characters ahead reached from a slide's last line into the next reading: 4 of 1,049 benign files became advisory. Each reading is its own `ooxml-text` view and a rule is reported once per unit and view |
| Give an Office part a role by its name alone, or by its root alone | A package names its parts, so a body can be `word/doc.xml`; and a slide can be stored under a layout's name. Both are read where they differ |
| A bounded optional prefix in the run patterns instead of resolving namespaces | It reads `ns0:t` but also a `w:t` that an inner declaration binds to another namespace, which is how one junk run hides between two words. Prefixes are resolved through the declarations in scope |
| Join the words on either side of a DrawingML `<a:br/>`, or only break there | python-pptx, markitdown, and LibreOffice show two lines; `main` joined them and holds `previ<a:br/>ous`. Both readings are kept |
| Open every one-part mail message as a container | One `text/plain` part in UTF-8 or ASCII with no encoding reads the same in a mail reader and a text editor. Opening it adds a member and changes every report for plain mail. It stays one unit |
| Open a one-part message for a body declared UTF-16, punycode, `idna`, or `unicode_escape` | Python's own generator writes UTF-16 bodies that do not decode, and a unit with a byte order mark that does not decode is incomplete. punycode decodes in quadratic time (2 MiB in 36 s) and the escape codecs are not charsets |
| Report the direction marks of Hebrew and Arabic mail in a legacy charset | 22 of 785 benign mails in windows-1255, windows-1256, and iso-8859-8 gained `agent_invisible_unicode`. A newly opened part in those three charsets is transcoded without U+200C to U+200F |
| Treat a header the mail library raises on as "not mail" | It left the body unread and the scan clean, while the same headers on a multipart message are incomplete. The one-body message is incomplete too |

## Keeping the detector current

**Chat-template tokens.** `agent_role_spoof_action` and `agent_fake_chat_marker` list role
openers by model family. Read the tokenizer's own `chat_template` when a family ships; the
closing token changed shape between Gemma 3 (`<start_of_turn>`) and Gemma 4 (`<|turn>`),
and DeepSeek's bars are U+FF5C, not `|`. Read on November 10: ChatML and Qwen
(`<|im_start|>`), Phi (`<|system|>`), Llama 3 (`<|start_header_id|>`), Llama 4
(`<|header_start|>`), Mistral (`[SYSTEM_PROMPT]`), Gemma 4, harmony
(`<|start|>system<|message|>`), DeepSeek, Granite (`<|start_of_role|>`), and Cohere
(`<|SYSTEM_TOKEN|>`). Llama 2 and Gemma 3 files are gated and were not read.

**Agent settings.** The keys that turn approval off move with each release. Read the
product's settings reference, not a write-up. On November 10 the VS Code source named
`chat.tools.terminal.autoApprove` (with `"/.*/": true` documented as "Allow all commands")
and the deprecated `chat.agent.terminal.autoApprove`; Claude Code ignores
`bypassPermissions` from a project file in current releases.

**Measuring recall and benign holds.** The corpus and the sweep measure collisions, not
recall. Whether to measure against a public corpus is still the owner's decision from
[#171](https://github.com/cgfixit/yara-gate/issues/171): a download is outside the
no-download default. If it is taken, keep the corpus out of git, record hashes and counts,
and report per policy. Candidates read on November 10:

| Corpus | License | What it adds |
| --- | --- | --- |
| [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) | Card states both Apache-2.0 and CC-BY-4.0 | 662 direct prompts in English and German, with benign rows |
| [NotInject](https://huggingface.co/datasets/leolee99/NotInject) | MIT | 339 benign prompts built around trigger words: a hold-rate test |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | MIT | Indirect injections in mail bodies, with 203 false-positive mails |
| [BrowseSafe-Bench](https://huggingface.co/datasets/perplexity-ai/browsesafe-bench) | MIT | 14,719 HTML pages with injections and benign distractors: the test for B3 |

A lexical gate's recall on paraphrase corpora is a floor to report, not a target to tune.

**Engine.** YARA-X 1.23.0 (November 5, 2026) is the newest release and the locked version.
Its regular expressions have no lookahead, lookbehind, or backreference, and an alternation
holds at most 255 branches; write an exemption as a second string and an offset test, as
`script_download_execute` does. A pattern cannot mix greedy and non-greedy quantifiers, so a
string with one lazy gap needs every quantifier lazy; in a generated rule file `{{lazy name}}`
derives that copy from the greedy fragment instead of a second hand-written one. Unreleased commits change the compiled-rule serialization
version, so the next release starts with a cold cache; the cache key already includes the
engine version. A compiled cache is trusted input
([GHSA-2jx3-ff3v-j7jj](https://github.com/VirusTotal/yara-x/security/advisories/GHSA-2jx3-ff3v-j7jj));
it is written under the user cache directory, which someone who can only supply files
does not control. Gaps of up to 8,192 bytes in the
shipped rules were checked on this engine and match.

**Vendor packs.** `rules.lock` pins YARA Forge core `20261004` and one commit each of
signature-base and Elastic protections-artifacts. `rules update --allow-network` resolves
new pins and compiles before swapping. Compare the skip list and a sweep before and after;
an unattended update is not planned.

**Standards to cite.** OWASP Top 10 for LLM Applications 2025 (LLM01 Prompt Injection) and
the [Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/);
MITRE ATLAS v2026.10: AML.T0051.001 (indirect prompt injection), AML.T0068 (prompt
obfuscation), AML.T0080 (agent context poisoning), AML.T0081 (modify agent configuration),
AML.T0086 (exfiltration via tool invocation), AML.T0110 (agent tool poisoning).

## What the research pass could not confirm

These were reported by secondary sources only, or their pages could not be fetched from
this environment. Do not build on them without reading the primary: the `nslookup`-based
ClickFix stage (February 2026), the Windows Terminal `Win+X` campaign (March 2026), the
Rules File Backdoor write-up, ShadowLeak and the Gemini mail-summary injection, AgentFlayer,
the postmark-mcp backdoor, the ToxicSkills scan, and the approval-bypass flags attributed
to the Nx postinstall script (they are not in the advisory text). The CVE often printed
beside CamoLeak, CVE-2025-59145, is the record for a different npm incident.
