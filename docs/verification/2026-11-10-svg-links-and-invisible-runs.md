# Scriptless SVG and zero-width runs: two backlog items built — November 10, 2026

Measured on `main` at `838b11d`. One pull request was open,
[#210](https://github.com/cgfixit/yara-gate/pull/210) (the cost of reading PDF fonts); it
changes `pdftext.py` and adds a record, and shares no file with this change.
Linux 6.18 x86_64 container, Python 3.12.3, YARA-X 1.23.0, 87 bundled local rules (85 on the
base), zero skips, no vendor download. Browser check: headless Chromium 153.0.8010.12 through
Playwright 1.63.0 on Node 22.23.4. Every scan used a disposable copy of `rules/local`.
Nothing was executed, unpacked to disk, or fetched by the scanner, and the browser answered
or aborted every request itself.

## Question

The task was to review every shipped rule and widen any whose detection can improve without
new benign hits. Which of the open items can be built that way, and does each new pattern
leave every benign file it meets where it was?

## Every rule, reviewed

Each of the 58 files was read against the [detection backlog](../research/detection-backlog.md).
Most families were widened on the same day by the
[rule variants](2026-11-10-rule-variant-coverage.md) pass, and what each still misses is
listed in the backlog with the reason it is not built. Two open items had a probe case, a
named false-positive class, and nothing recorded against them: B1 and B4. They are the two
changes here.

| Files | Outcome |
| --- | --- |
| `doc_svg_active.yar`, `doc_svg_event_handler.yar` | New sibling rule `doc_svg_active_link` (B1), below |
| `agent_invisible_unicode.yar` | New sibling rule `agent_invisible_run` (B4), below |
| `agent_prompt_injection_phrases.yar`, `agent_prompt_injection_multilingual.yar`, `agent_override_imperative.yar`, `agent_persistent_instruction.yar`, `agent_secret_transfer_request.yar`, `agent_tool_hijack_directive.yar`, `agent_tool_output_override.yar`, `agent_message_code_relay.yar` | No change. Widened on November 10; the nouns, verbs, and orders not matched are on the not-planned list with the benign text that collides. The backlog asks for the phrase rules to be generated from one word list before the next phrase is added |
| `agent_fake_chat_marker.yar`, `agent_role_spoof_action.yar` | No change. Openers were read from each model's own template on November 10; no new family was read here |
| `agent_hidden_html.yar`, `agent_markdown_exfil.yar` | No change. The HTML hidden-text reader now owns layout claims; the remaining cue ideas are declined with the browser evidence |
| `agent_config_autoapprove.yar`, `dev_*.yar` | No change. The settings keys that remain (an allow-list wildcard, Codex `mcp_servers` commands, workspace tool paths) each need committed-file counts; B6 (`binding.gyp`) needs a second source |
| `agent_bidi_*.yar`, `agent_eicar.yar`, `agent_base64_blob.yar` | No change. Fixed byte sets, an exact marker, and scanner-set globals |
| `script_*.yar`, `unix_*.yar`, `macos_*.yar`, `credential_store_theft.yar`, `win_*.yar`, `windows_*.yar`, `shortcut_interpreter.yara`, `web_*.yar` | No change. Command spellings were widened on November 10 from the parsers' own source; the remaining shapes in the backlog's table need a benign count or a second source |
| `doc_*` (other), `container_disk_image.yar` | No change. Structural offsets and format markers with no recorded miss |

## 1. SVG that runs or loads something with no script and no handler (B1)

**Miss (verified on `838b11d`).** Each of these SVG documents was clean under every policy,
beside `<script>` (blocked) and `onbegin` (advisory) controls: an `a` whose `href` or
`xlink:href` is `javascript:...`, quoted or not, upper-case, with leading space, or
namespace-prefixed; a `set` or `animate` whose `to` or `values` writes `javascript:` to the
link; and a `foreignObject` holding an `iframe`, `object`, `embed`, `form`, or `meta`
refresh. The same shapes inside an svg element of an HTML page were clean too.

**Near-misses written first.** An `https` or fragment link; `javascript:void(0)`,
`javascript:void 0`, `javascript:;`, and an empty `javascript:` (legacy no-op links); a
`data-href`; `<a-scene href=...>`; an icon sprite of `use` elements; draw.io- and
Mermaid-style `foreignObject` labels of `div`, `span`, and `p`; checkbox and button labels;
`meta charset`; an `iframe` after its `foreignObject` closed; animations of `fill`; a page
link with a `javascript:` target, an `iframe`, or a `form` outside the svg; and prose that
names the shapes.

**Browser check (direct runtime).** [`svg_active_oracle.js`](../research/svg_active_oracle.js)
loads each shape in Chromium with every request answered locally or aborted:

| Shape | Chromium |
| --- | --- |
| `a` with `href` or `xlink:href` `javascript:<script>`, clicked | ran |
| `a` with `javascript:void(0)`, clicked | did nothing |
| `a` with `javascript:void(<script>)`, clicked | ran: `void` evaluates its operand |
| `set` or `animate` writing `javascript:` to the link's `href`, clicked | ran |
| `foreignObject` holding `iframe`, `object`, or `embed` | each requested its URL |
| `foreignObject` holding a `form`, submitted | navigated to the action |
| `foreignObject` holding `meta http-equiv="refresh"` | navigated, as a standalone SVG and inline in HTML |
| `foreignObject` holding a `div` label | nothing |

So every element in the rule is active in a browser, and the exemption is exactly the
no-op: empty, `;`, and `void(0)` or `void 0`, and nothing else.

**Rule.** `doc_svg_active_link`, advisory, in `doc_svg_event_handler.yar`. It uses the scope
test the two SVG rules use: in an `.svg` or `.svgz` file, an svg-rooted document, or markup
the scope proof declines, any match counts; elsewhere the match must sit inside an svg
element. A link is read twice per tag, once lazily and once greedily, so both of a tag's
possible `href` attributes are checked; a link counts unless the `javascript:` token at the
end of its match starts a no-op target, which is one offset lookup.

**Found while verifying.** The first condition tested the exemption by looping over every
no-op match for every link, and dropped the exemption past 1,024 no-op matches to bound that
loop. A 4 MiB page of `<a href="javascript:void(0)"><svg>...</svg></a>` icon buttons then
fired. Anchoring the no-op string at the `javascript:` token made the exemption a lookup, and
the same page is clean.

## 2. A run of zero-width characters (B4)

**Miss (verified on `838b11d`).** Forty alternating U+200B and U+200C characters gave two
notes (`agent_invisible_unicode`, `heuristic_invisible_joiner`) and exit 0 under
`agent-document`, beside a run of eight variation selectors that blocks. So did 16 mixed
U+200B to U+200D and U+2060, word joiners U+2060 to U+2064, alternating U+FEFF, and the same
run as UTF-16.

**Rule.** `agent_invisible_run`, advisory, in `agent_invisible_unicode.yar`: 16 or more
consecutive characters from the backlog's list (U+200B to U+200D, U+2060 to U+2064, U+FEFF,
U+180E, U+034F) in a text unit. It is a YARA rule rather than the proposed
`heuristic_invisible_run` because a fixed byte run needs no context the engine cannot see.

**Near-misses.** A run of 15 (the notes, as before); Persian with a ZWNJ inside two words; a
family emoji with three ZWJs; Devanagari conjuncts; a ZWSP between each pair of letters.

**Two scanner sets, each with an observed effect.** `scanner.py` treats the Unicode-control
notes specially in two places, and the run joins both:

- *Not an instruction.* On the base, a zero-width run in hidden Word text raised
  `heuristic_hidden_text`, the finding for an instruction in hidden text. The run is now
  in the set of matches that are not instructions, beside the notes and the base64 rules.
- *Image samples.* In a decoded PDF stream, a match is kept only when the 16 bytes on one
  side read as UTF-8. On the base, a run of exactly 16 between non-UTF-8 bytes fired; now it
  is dropped. A longer run keeps matching, because the run's own characters are UTF-8 on one
  side of every match inside it.

Each is a case in [`probe_detection_gaps.py`](../research/probe_detection_gaps.py); with
`scanner.py` reverted, both fail and every other case passes.

## Commands and results

- `docs/verification/lint_rules.py`: 87 rules compiled and linted, 2 vendor overrides.
- `docs/verification/check_rule_pairs.py`: passed, 117 ids. Four pairs added.
- `docs/verification/check_added_rules.py`: passed, 242 cases plus 4 vendor-override cases.
  Nine added, including a commented `</svg>` that makes the scope proof decline and a zipped
  SVG.
- `docs/research/probe_rule_coverage.py --verify`: passed, 617 library cases (607 before), 55
  CLI cases, 9 benign observations. The ten new rows give the same ids as UTF-8, UTF-16, and
  inside a zip; the no-op link and the diagram label are clean.
- `docs/research/probe_detection_gaps.py --verify`: exit 0, 275 `ok` and 4 `open` (B3, B5, B6,
  B7). The B1 and B4 markers are removed; eight boundary cases were added.
- `docs/verification/measure_precision.py --fail-over`: exit 0, 328 files, zero incomplete;
  both new rules hit 0 files, so 83 of 87 rules hit nothing and the four documented Windows
  collisions are unchanged.
- `docs/verification/check_worst_case_timing.py`: PASS, 36 inputs of 4 MiB; slowest
  `pdf-page-fonts.pdf` at 7.39 s against the 10 s ceiling. That input failed `check (macos-15)`
  on `838b11d` and is what #210 addresses; best of three, the base and these rules give
  7.28 s and 7.14 s on it, and 6.52 s and 6.67 s on `pdf-font-definitions.pdf`, so this
  change neither adds to nor removes that cost.
- `scripts/record_pages_demo.py --baseline web-demo/recordings.json`: "Outcomes match the
  reviewed baseline" for the 64 scenarios under 3 policies, recorded with 87 rules; ruleset
  digest `7f99e59f6ae7ef5490b83cf7c4089b339929e5d6a47ea3bde83d4377f545843f`. The committed
  baseline is unchanged; a deployment refreshes its provenance.
- `yara-gate selftest`: SELFTEST PASS. `check_text_controls.py` (304 files),
  `check_doc_links.py` (656 relative links), `check_scan_only.py`, `check_rules_lock.py`:
  passed. `ruff check .`, `ruff format --check .`, and `mypy --strict src scripts`: passed.
- `pytest` on the files that name the scanner's control rules, SVG scope, the rules loader,
  and the Pages build and deploy: 14, 61, and 32 passed. The whole suite is left to hosted CI.

### Installed files, before and after

[`sweep_rule_changes.py`](sweep_rule_changes.py), base `838b11d`:

| Corpus | Files | Files whose findings changed | Hits before and after |
| --- | ---: | ---: | --- |
| `/opt`, `/usr/share`, the Python 3.12 library, `/etc` | 20,000 | 0 | 120 and 120 |
| Node 22, `/usr/share/doc`, Python 3.12 and 3.13, Vim and Perl runtime files, `/etc`, shell completions, the project's virtual environment | 8,116 | 0 | 36 and 36 |
| Icon themes under `/usr/share/icons` (5,540 regular SVG files; the sweep keeps one per name and size) | 4,142 | 0 | 0 and 0 |

### Cost

4 MiB inputs, best of two, `scan_bytes`, seconds. The first row is ordinary prose; the rest
are built from the literals the new strings search for, the worst case for each.

| Input | `838b11d` | this change |
| --- | ---: | ---: |
| Ordinary prose | 0.61 | 0.60 |
| SVG of `javascript:void(0)` links | 2.10 | 2.57 |
| SVG text full of `javascript:` and `href=`, no link | 2.27 | 3.10 |
| SVG `foreignObject` openers never closed | 1.87 | 2.08 |
| HTML of inline icons with no-op links inside the svg | 2.39 | 2.95 |
| HTML of icon buttons with no-op links around the svg | 2.46 | 3.17 |
| Zero-width characters between letters | 2.81 | 2.71 |
| One zero-width run of 4 MiB | 3.56 | 4.85 |
| Zero-width runs of 15, back to back | 0.63 | 1.63 |

Each no-op flood stays clean.

## Boundaries

- A `javascript:` scheme split by a tab or line feed, which a browser strips from a URL, and
  an `href` under a namespace prefix other than `xlink:`, are clean; both are in the backlog.
  An entity-encoded colon (`javascript&#58;`) is read through `html-unescaped` and fires.
- In an HTML page the scope proof declines (one holding a `foreignObject`, for one), a
  `javascript:` link outside the svg fires, as a script beside the icon blocks for
  `doc_svg_active`. A no-op link there stays clean.
- A tag that writes a third `javascript:` `href` is not well-formed XML; the rule reads its
  first and last.
- The zero-width list is the backlog's. Hangul fillers, the soft hyphen, and the braille
  blank are not members; that is in the backlog with the benign count it needs.

## What this does not establish

- The probes are synthetic and were written by the same pass that wrote the patterns.
- Zero changed files on this container's installed software is a collision count, not a
  false-positive rate. It has 4,142 icon SVGs from three themes and no SVG mail attachments.
- The browser check is one Chromium build. Other browsers, mail clients, and image viewers
  that render SVG without script were not run; an image viewer that runs no script makes
  every one of these shapes inert.
- Hosted CI on macOS and Windows had not run when this was written.
