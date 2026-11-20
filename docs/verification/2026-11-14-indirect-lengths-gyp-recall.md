# Indirect PDF lengths, `binding.gyp` expansions, and a recall floor — November 14, 2026

Base: `main` at `50f404a`. Linux 6.18 x86_64 container, 4 CPUs, Python 3.12.3, YARA-X 1.23.0,
bundled local rules only (87 before, 88 after), no vendor download. Every scan used a
disposable copy of `rules/local` and the real `scan_bytes` API. Nothing was executed, and
the scanner fetched nothing. The container was shared with other runs, so wall times here
are comparisons on one machine, not benchmarks.

Three items from the [#171](https://github.com/cgfixit/yara-gate/issues/171) and
[#231](https://github.com/cgfixit/yara-gate/issues/231) trackers: the backlog row for stream
lengths kept in another object, backlog item B6, and the owner's decision to measure recall on
public corpora.

## 1. Stream lengths and `/Contents` arrays kept in their own objects

**Gap (verified on `50f404a`).** qpdf's QDF mode writes every stream's `/Length` as a
reference to an object of its own. reportlab 5.1.0 wrote 60, 300, and 900 pages of ordinary
text (40 lines a page, page compression off), and pikepdf 10.18.1 (libqpdf 12.4.2) saved
each plain and in QDF mode. The QDF saves were slow and the largest timed out:

| File | Pages | Size | `50f404a` | This change | Verdict on both |
| --- | --- | --- | --- | --- | --- |
| `report60-qdf.pdf` | 60 | 0.3 MB | 1.37 s | 0.33 s | clean |
| `report300-plain.pdf` | 300 | 0.2 MB | 3.92 s | 1.67 s | clean |
| `report300-qdf.pdf` | 300 | 1.6 MB | 23.81 s | 2.13 s | clean |
| `report900-plain.pdf` | 900 | 0.7 MB | 16.55 s | not rerun | incomplete, `pdf text blocks exceed 20000` |
| `report900-qdf.pdf` | 900 | 4.7 MB | 30.02 s, incomplete `timeout` | 2.18 s | incomplete, `pdf text blocks exceed 20000` after; `timeout` before |
| `report900.pdf` (reportlab's own file) | 900 | 4.5 MB | incomplete `timeout` | incomplete, `pdf text blocks exceed 20000` | |

The 900-page files hold 36,000 text blocks, past the existing 20,000-block cap, so every save
of them is incomplete; the change makes the QDF save and reportlab's original stop at that cap
instead of at the deadline. The plain-file times moved with the container's load.

**Cause (verified).** A profile of `report300-qdf.pdf` on `50f404a` spent 23.2 s of 26.4 s in
601 calls of `PdfRawObjects.prime`, each a regular-expression pass over the whole file: 300
from the annotation reader's `stream_span` (one per `/Length N G R`) and the rest from the text
reader's `_other_contents` (one per `/Contents N 0 R`). The page map already primes its own
lengths in one pass.

**Change.** `pdf_annotation_texts` primes every `/Length N G R` it finds (the page map's
pattern, up to `MAX_PDF_STREAMS` references) before it walks the file, and `_other_contents`
primes every `/Contents N 0 R` (up to `MAX_OTHER_CONTENTS`) before it reads them. `prime`
records the definitions one lookup would find, so what is read does not change; a reference
past either bound is looked up on its own as before.

**Same results.** Each file was scanned under all three policies on `50f404a` and with the
change, comparing verdict, incomplete reason, findings (rule, severity, view), and views
scanned. Of 261 PDFs (141 written by `probe_pdf_reader_agreement.py fixtures --keep`, 107 by
`probe_pdf_font_reader_agreement.py fixtures --keep`, and the 13 generated here), 259 are
identical. The other two are `report900.pdf` and `report900-qdf.pdf` above. A QDF save with an
override phrase on page 61 of 120, in the page text and, separately, in a text annotation's
`/Contents`, is advisory / block / advisory on both revisions; its benign twins are clean on both.

**Regression guard.** `tests/test_pdfannotations.py` scans 200 pages whose lengths and
`/Contents` are references and counts whole-file `prime` passes: 401 on `50f404a`, 3 now. A
4 MiB input of 943 such pages took 30.06 s (incomplete, `timeout`) on `50f404a` and 1.34 s to
1.65 s with the change. It was tried in `check_worst_case_timing.py` and taken out again: that
step reached 307 s against its five-minute limit on an 81-input run
([timing record](2026-11-14-macos-timing-flake.md)), and the pass count tests the cause
without adding a worker to it. The full timing check, run with that input added, passed all
82 inputs on this container; the slowest was `pdf-font-readings-winansi.pdf` at 7.3 s.

## 2. `binding.gyp` command expansions that hide their output (B6)

**Gap (verified on `50f404a`).** `"<!(node index.js > /dev/null 2>&1 && echo stub.c)"` in a
`binding.gyp` was clean under every policy. npm runs `node-gyp rebuild` for a package that has a
root `binding.gyp` and no install script, and GYP runs each `<!(...)` and `<!@(...)` expansion as
a shell command while it configures.

**Sources.** Read: [JFrog](https://research.jfrog.com/post/shai-hulud-miasma-redhat-cloud-services/)
(June 1, 2026, updated June 4) shows the expansion inside a `"sources"` array of a `"type":
"none"` target. Read: the OpenSSF malicious-packages record MAL-2026-6526 (alias
GHSA-r4r5-rj2h-xfvg, from `raw.githubusercontent.com/ossf/malicious-packages`) quotes Amazon
Inspector: a root `binding.gyp` whose `targets`/`sources` hold a `<!(...)` expansion, with no C
or C++ source beside it. It does not quote the command, so the `/dev/null` and `echo stub.c`
spelling has one source. Located only: Snyk's write-up, through a search summary; its host was
not reachable from this container.

**Benign shapes (verified).** 75 npm tarballs of native addons (the registry's latest version
of each on November 14, and `sharp@0.32.6`) were downloaded to a scratch directory, and every
`.gyp` and `.gypi` member was copied out in memory: 91 files from 63 packages (67 `binding.gyp`),
12 packages shipping none. Their expansions are `node -p`/`node -e` lookups, `pkg-config` and
`curl-config` calls, and platform tests. Three come near the attack:

- nodegit's `binding.gyp`: `<!(node -p "os.platform() == 'aix' && os.type() == 'OS400' ? 1 : 0")`,
  `&&` inside JavaScript;
- node-pty's `winpty.gyp`: `<!(cmd /c "cd shared && GetCommitHash.bat")`;
- fibers' `binding.gyp`: `<!(ldd --version 2>&1 | head -n1 | grep "musl" | wc -l)`.

None sends output to `/dev/null` or echoes a source file name. The backlog's proposal, "a `<!(`
expansion that redirects to `/dev/null` or chains with `&&`", would have held nodegit, so the
rule keeps the two parts that hide the run.

**Rule.** `dev_gyp_command_expansion` in `rules/local/dev_package_hooks.yar`, advisory, for a
file whose suffix is `gyp` or `gypi` (`binding.gyp` has the suffix `gyp`, also as an npm `.tgz`
member). On one line, a `<!(` or `<!@(` expansion followed within 240 bytes by `>` and
`/dev/null`, or by `&&`, `||`, or `;` and `echo` of a `.c`, `.cc`, `.cpp`, or `.cxx` name.

| Input | `50f404a` | This change |
| --- | --- | --- |
| JFrog's line in `binding.gyp` | clean | advisory / block / block |
| `>/dev/null; echo shim.cc`, `\|\| echo stub.c`, a `.gypi` with `&>/dev/null` | clean | advisory / block / block |
| The same line in a `.tgz` at `package/binding.gyp` | clean | holds (`check_added_rules.py`) |
| The `node-addon-api` include lookup, nodegit's `&&`, fibers' `2>&1`, `pkg-config ... \|\| echo` | clean | clean |
| JFrog's line quoted in a `README.md`, or in `build.json` | clean | clean |

**Checks.** `check_rule_pairs.py` (118 rules, two new pairs), `check_added_rules.py` (246 cases),
`lint_rules.py` (88 rules), and `measure_precision.py --fail-over` (the new rule hits 0 of 328;
84 of the 88 rules hit nothing) pass. `probe_detection_gaps.py --verify`: 541 ok and 2 open
(B3, B5); the B6 marker is removed and three benign cases were added beside it.
`sweep_rule_changes.py` over `/usr/share/doc`, `/usr/lib/python3.12`, `/usr/include`, and the 91
gyp files: 4,188 files, 0 with changed findings. All 75 tarballs scanned whole: no hit.
`record_pages_demo.py --baseline web-demo/recordings.json`: outcomes match (82 scenarios × 3
policies). `probe_rule_coverage.py --verify` passes.

**Cost.** Each input 4 MiB, named `binding.gyp`, bundled rules before and after:

| Input | Before | After |
| --- | --- | --- |
| Ordinary English lines | 0.49 s | 0.47 s |
| `<!(` repeated on one line | 0.65 s | 0.57 s |
| `<!(` and 239 letters, repeated, no close | 0.43 s | 0.59 s |
| `<!(a && echo ` repeated | 0.74 s | 0.61 s |
| `<!(node x > /dev/nul` repeated | 0.78 s | 0.68 s |

Both strings start with the literal `<!`, so the engine has an atom to search for.

## 3. A recall floor on two public corpora

The owner decided on November 14 to measure recall
([#171](https://github.com/cgfixit/yara-gate/issues/171),
[#236](https://github.com/cgfixit/yara-gate/issues/236)). The corpora were downloaded to a
scratch directory outside the repository, pinned to a dataset commit; none of their text is in
git or in this record. Each item was scanned once per policy as `scan_bytes(text, name="message.txt")`,
the way a consumer scans a chat or mail body, with the 88 bundled rules.

| Corpus | Revision | Files read | SHA-256 |
| --- | --- | --- | --- |
| [NotInject](https://huggingface.co/datasets/leolee99/NotInject) (MIT) | `847ae76` | `NotInject_one`, `_two`, `_three` parquet | `5b1d3a8e…`, `a5a8c1b3…`, `d5c685b1…` |
| [LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) (MIT) | `1063bdf` | `emails_for_fp_tests.json` | `4ddd950b…` |
| | | `labelled_unique_submissions_phase1.json` | `691dfa15…` |
| | | `labelled_unique_submissions_phase2.json` | `f89af984…` |

NotInject is 339 benign prompts built around words injection detectors key on. LLMail-Inject
holds 203 ordinary emails for false-positive tests and the unique email bodies that players
submitted to a mail agent behind LLM defenses (160,741 in phase 1, 37,303 in phase 2), each
labelled by the challenge: `api_triggered` (the submission made the defended model call its
send tool), or a judge's `True`, `Unclear`, or `False` for whether it was an attack attempt.

| Set | Label | n | default: any finding | `agent-ingest`: block | `agent-document`: block |
| --- | --- | --- | --- | --- | --- |
| NotInject | benign | 339 | 1 (0.3%) | 1 (0.3%) | 0 |
| LLMail-Inject | false-positive emails | 203 | 0 | 0 | 0 |
| phase 1 | `api_triggered` | 21,394 | 374 (1.7%) | 374 (1.7%) | 149 (0.7%) |
| phase 2 | `api_triggered` | 3,165 | 207 (6.5%) | 207 (6.5%) | 83 (2.6%) |
| phase 1 | judge: attack | 105,982 | 2,918 (2.8%) | 2,918 (2.8%) | 702 (0.7%) |
| phase 2 | judge: attack | 17,842 | 970 (5.4%) | 970 (5.4%) | 158 (0.9%) |
| phase 1 | judge: unclear | 23,911 | 212 (0.9%) | 212 (0.9%) | 24 (0.1%) |
| phase 2 | judge: unclear | 13,796 | 212 (1.5%) | 212 (1.5%) | 206 (1.5%) |
| phase 1 | judge: not an attack | 9,452 | 170 (1.8%) | 170 (1.8%) | 84 (0.9%) |
| phase 2 | judge: not an attack | 2,500 | 54 (2.2%) | 54 (2.2%) | 45 (1.8%) |

Over every attack-labelled body (148,383), the gate reports a finding on 4,469 (3.0%) and
`agent-document` holds 1,092 (0.7%); over the 24,559 that triggered the tool, 581 (2.4%) and
232 (0.9%). Under `agent-document` a body whose only findings are notes passes, which is why
that column is lower. On attack-labelled bodies the rules that fired most were
`agent_prompt_injection_phrases` (2,898), `agent_invisible_unicode` (642),
`agent_role_spoof_action` (519), `agent_fake_chat_marker` (270), `agent_base64_blob` (204), and
`heuristic_unicode_tag` (169). The one NotInject hold is a note from
`agent_override_imperative`. The judge's "not an attack" rows are players' submissions, not a
benign corpus; they are listed so no row is left out.

**What this is.** A floor for the lexical layer on English mail-body injections that were
written to beat LLM defenses, not this gate: nobody adapted to it, and an adaptive attacker
would push the figure lower. It is not a production recall figure, and the corpus must not
become a tuning target; the rules stay with the near-miss discipline in the
[backlog](../research/detection-backlog.md). It measures the premise of #236: this gate catches
known shapes, and nearly every paraphrased injection passes it. Whatever stands behind it (an
action policy, a reader separated from the actor) carries the rest.

**Run.** 198,586 bodies, three policies each, in 596 s on three worker processes. Six results
first came back incomplete, `no rules compiled`: the disposable rules copy the workers read
was replaced while they ran (for the B6 condition above). Each of the six, rescanned on its
own, is clean under all three policies with 88 rules, and the table counts it that way. The
manifest of hashes, labels, verdicts, and rule ids stays outside the repository.
