# Conformance kit

`yara-gate conform` checks an installed copy of the gate against fixtures and expected
verdicts that ship in the same package. Run it in your own CI when you move your
`yara-gate` pin, and run its agreement mode when you change the reader that turns a file
into text for your model. It answers two different questions, and keeps them apart:

- **Did the gate change its answer?** The plain run. A fixture whose verdict or exit code
  moved fails the run.
- **Does my reader show my model what the gate judged?** Agreement mode. It sets a scan of
  your extracted text beside the scan of the file it came from.

The kit version is the package version you pinned. Nothing is downloaded, executed, admitted,
or moved, and no gate home is used.

## The plain run

```sh
yara-gate conform
```

It builds 124 inert fixtures from the installed package: every pair of the
[demo catalog](../src/yara_gate/showcase.py) (an attack beside a benign near-twin, across
messages, web pages, PDFs, Office files, archives, tool results, and repository files), the
catalog's two scans that cannot finish (a JSON tool document past the structure limit and a 7z
archive the scanner does not open, both incomplete under every policy), and a PDF pair whose
page content the gate cannot decode, for the
[`pdf_content_unread` route](integrations.md#pdfs-and-other-compressed-documents). It then:

1. Checks each fixture's SHA-256 against the packaged manifest
   ([`conformance.json`](../src/yara_gate/conformance.json)). A fixture that builds other
   bytes stops the run.
2. Scans each fixture under `default`, `agent-ingest`, and `agent-document` with a
   disposable copy of the bundled rules only. Your installed vendor packs and your own local
   rules are not loaded in this pass.
3. Compares each result with the manifest.

| Exit | Meaning |
| --- | --- |
| 0 | Every fixture has its recorded verdict and exit code under every policy |
| 1 | A verdict or an exit code changed |
| 2 | The kit could not run or did not finish: a fixture's bytes changed, the manifest or the bundled rules are missing or damaged, a scan that should answer was incomplete, an agreement line gave no record, standard output could not be written, or an error the kit did not expect (`incomplete: <Type>`) |

Standard output is JSON Lines; standard error carries one line for a person
(`CONFORM PASS: 124 fixtures, 372 checks, …`).

| Record | When | Fails the run |
| --- | --- | --- |
| `mismatch` | A verdict or exit code differs. It names the fixture, the policy, the expected and observed pair, and the rule ids and views that were added or lost | Yes, in the `bundled` section |
| `difference` | The verdict and exit are the same and a rule id, a view, an incomplete reason, or the unread count differs | No |
| `summary` | Always last: `result` (`pass`, `fail`, `incomplete`), the counts, the manifest's SHA-256, and the rule and detector identity that ran | |

A record never holds fixture text. A run that meets an incomplete scan where the manifest
records an answer stops there with `result: "incomplete"`: rules that do not compile fail
every scan the same way.

### Installed vendor packs

When the rules tree (`--rules`, or the default one) records installed vendor packs, the kit
scans the fixtures a second time with that whole tree and prints the same records under
`"section": "installed"`. This section **never changes the exit code**. Vendor rules block
unless [`vendor-overrides.json`](../rules/vendor-overrides.json) grades them, and they move with every
`rules update`, so a benign twin a vendor rule holds is information about your install, not
a failed kit. No vendor expectation is shipped: the comparison is against the bundled
expectations, and the summary carries the installed tree's `ruleset_sha256` so two runs can
be told apart. A recorded vendor file that is missing or cannot be read skips the section
(`"installed": null`).

## Agreement mode

A consumer that scans the text its own reader extracted, instead of the file, can lose
findings that depend on the file. The kit shows which.

```sh
yara-gate conform --export kit                      # write the fixtures to an empty directory
python docs/examples/conform_agreement.py kit > extraction.jsonl   # your reader goes here
yara-gate conform --agreement extraction.jsonl > agreement.jsonl
```

The capture is the format [`replay`](integrations.md#replaying-captured-model-input) reads.
`source_id` is the fixture id from `kit/fixtures.jsonl`, `text` (or `text_base64`) is what
your reader took from it, and `original_sha256` is the fixture's hash. A line may name its
own `policy`; `--policy` sets the one for lines that do not, and is `agent-document` unless
you say otherwise. Each line is scanned in a child process by the replay core, with the
bundled rules, and compared with the scan of the fixture file under the same policy.

| `result` | Meaning |
| --- | --- |
| `same` | Both sides give the same decision with the same rule ids |
| `findings-differ` | The same decision, different rule ids |
| `file-holds-only` | The gate holds the file and would admit your extraction. If you scan only the extraction, this input reaches your model |
| `extraction-holds-only` | The reverse: your reader produced text the file scan does not hold |
| `failed` | No record to compare: an unknown fixture id, an `original_sha256` that is not the fixture's, a malformed line, a scan that was killed, or a fixture the plain run never reached because an earlier scan gave no answer (`fixture was not scanned`). The run exits 2 |

`only_in_file` and `only_in_extraction` list the rule ids behind a difference. A decision is
the read rule `replay` uses: `agent-ingest` admits a complete clean record, and
`agent-document` admits that or the exact notes-only record. A `failed` line is never an
admit: its `extraction` side keeps the verdict and rule ids of any scan that ran, and its
`decision` is always `hold`, as `replay` proposes `hold` for a failed item.

The output holds no timings, so two runs over the same capture and detector print the same
bytes. **Commit `agreement.jsonl` and fail your CI when it changes** (`git diff --exit-code`):
a divergence is often expected, and what you need to see is one that is new. The plain
section still runs first, so a changed gate verdict (exit 1) is never mistaken for a changed
reader.

A direct run with two stand-in readers is in the
[verification record](verification/2026-11-20-conformance-kit.md#agreement-with-two-real-readers):
a text-node HTML reader that never reads `style` kept a hidden instruction and dropped the
markup that hid it, so the file was held and the extraction was a quoted note.

The exported fixtures are inert and are written like attacks. Keep the export out of any
folder an agent or a sync client reads, and expect an antivirus product to react to some of
them.

## When to run it

| Event | Run |
| --- | --- |
| You move your `yara-gate` pin | `yara-gate conform`. Exit 1 means a verdict you may rely on changed: read the [changes](#changes) below before accepting the pin |
| You change your extractor, or move the pin | `yara-gate conform --agreement` over a fresh capture, then diff the committed report |
| You install or update vendor packs | `yara-gate conform`, and read the `installed` section |

## Changing the manifest

The manifest is generated. After a change that moves a fixture's bytes, a verdict, or what a
fixture reports:

```sh
uv run python scripts/build_conformance.py
```

It refuses to write when a scan disagrees with the verdict the catalog lists. Then add a row
under [Changes](#changes) with the first 16 digits of the new file's SHA-256 (the summary
prints the whole digest as `manifest_sha256`); a test fails a manifest whose digest has no
row. A changed verdict needs a reason a consumer can read. Hosted CI runs `yara-gate conform`
on macOS and Windows, which is where a fixture that builds different bytes on another system
shows.

## Changes

| Date | Manifest | What changed |
| --- | --- | --- |
| 2026-11-20 | `e0f77f72e5cff1af` | First manifest: the 90 catalog fixtures that scan with the bundled rules, and the unread-content PDF pair. Schema version 1 |
| 2026-11-21 | `422a27b3bd76a2a1` | Two fixtures added, no fixture moved: `chat_header_override`, a page a browsing tool returned as text that opens a Llama 3 system turn and orders a ranking (`agent_role_spoof_action`, an advisory: held by both agent policies), and its near-twin `chat_header_benign`, the same opener quoted in a model guide, clean under every policy |
| 2026-11-21 | unchanged | Agreement output only: a `failed` line whose extraction was scanned (an unknown fixture id, an `original_sha256` that is not the fixture's, or `fixture was not scanned`) now gives `"decision": "hold"` on its `extraction` side instead of the extraction's own `admit`. Its verdict and rule ids are unchanged. A committed `agreement.jsonl` that holds such a line changes on that field only; the run still exits 2 |
| 2026-11-25 | `8a4f1594a812a558` | Added two synthetic Quartz-style print proofs. The margin instruction produces a note in `pdf-annotation`; the copy editor’s revision is clean under every policy. Existing fixtures retain their bytes and outcomes. |
| 2026-11-26 | `f918ea119da51298` | Two fixtures added, no fixture moved: `ps_download_run`, a PowerShell bootstrap script that passes a download straight to `iex` (`script_download_execute`, an advisory: held by both agent policies), and its near-twin `ps_alias_table`, a highlighter's alphabetical alias table that names `iex` ahead of `irm` and `iwr` with only other aliases between them, clean under every policy. A gate older than this manifest reports that twin as `script_download_execute`; the [record](verification/2026-11-26-powershell-alias-lists.md) has the change |
| 2026-11-26 | `0c6ec8989324b7c6` | Added the PDF tooltip, PDF choice label, and UTF-32 text pairs. Each ranking instruction holds under both agent policies. All nine policy recordings of their benign twins are clean, and existing fixtures keep their bytes and outcomes. |
| 2026-11-26 | `760e3d2591bbed2d` | Four fixtures added, no fixture moved. Two attacks: `syntax_page_svg_script`, a help page credited to a mail address in angle brackets whose inline logo holds a script (`doc_svg_active`, a block), and `word_dde_field`, a Word file whose one field is a `DDEAUTO` instruction (`heuristic_ooxml_dde`, a block). Their near-twins, clean under every policy: `syntax_file_svg_tags`, an editor syntax file that names the svg and script tags, and `dde_scanner_source`, a DDE scanner's own source. A gate older than this manifest reports the two twins as `doc_svg_active` and `heuristic_ooxml_dde`; the [SVG record](verification/2026-11-26-svg-scope-text.md) and the [DDE record](verification/2026-11-26-dde-source-and-priority-claims.md) have the changes |
| 2026-11-27 | `e639684d06c0bc2d` | Added three PDF pairs covering sticky-note subjects, field names, and pushbutton captions. The model-addressed ranking request produces an advisory in `pdf-string` and both agent policies hold it. Each ordinary comparison is clean. |
| 2026-11-27 | `67448984eee4648b` | Added calendar, vCard and saved notebook HTML pairs. The three ranking requests are advisory under default and held under both agent policies. All three ordinary comparisons are clean. |
| 2026-11-28 | `68392f1c22354e22` | Two fixtures added, no fixture moved: `word_dde_split_field`, a Word report whose DDEAUTO field type is split across three runs with a comment and a character reference (`heuristic_ooxml_dde`, a block), and its near-twin `word_page_split_field`, the same report with a page-number field split the same way, clean under every policy. A gate older than this manifest reports the attack as clean; the [record](verification/2026-11-28-dde-field-instructions.md) has the change |
| 2026-11-28 | `2ecb04746b013e5a` | Two fixtures added, no fixture moved: `extracted_ole_object`, a compound file named `oleObject1.bin` whose one stream packages an inert note (`heuristic_ooxml_oleobject`, an advisory: held by both agent policies), and its near-twin `office_menu_oleobject`, an office suite's popup-menu file named `oleobject.xml`, clean under every policy. On `0480d67` the near-twin was advisory and held by both agent policies, because the check read the name alone. |
