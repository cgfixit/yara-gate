# HTML and feed reader bounds

[Issue #253](https://github.com/cgfixit/yara-gate/issues/253) on `main` at
`334157681b8c3e9d50a35e6271e77dfcaa246a34`. Verified November 15, 2026
(America/New_York) on arm64 macOS, Python 3.12.12, and YARA-X 1.23.0 with 88
bundled rules and no vendor packs. The candidate changes the readers and keeps
the same rule bodies, severities, and policies. All fixtures were inert.

## Text and verdicts

- Atom plain text keeps literal angle brackets after XML decoding. HTML fields
  render escaped markup. XHTML fields read inline elements within each block.
  XML comment and CDATA joins still work. RSS descriptions and
  `content:encoded` retain their HTML view. Adjacent fields and entries stay
  separate. The declared Atom types follow [RFC 4287 §3.1.1](https://www.rfc-editor.org/rfc/rfc4287.html#section-3.1.1).
- feedparser 6.0.14 classified explicit and default Atom text as `text/plain`
  and preserved the literal markup. It classified the corresponding Atom HTML,
  XHTML, and RSS fixtures as markup and exposed their separate fields. The
  scanner's derived pieces agreed with those plain-text and markup distinctions.
- Across 89 directed HTML and feed fixtures under three policies, comparing
  verdict, reason, rule ID, severity, view, and offset with current `main`
  produced two expected changes. Atom titles containing literal markup had
  produced a derived note and were held under `agent-ingest`. Both are now clean
  under all three policies. HTML/XHTML controls and XML text joins still match
  in their original views. The older `e761133` and `d6558f3` trees reproduced
  the original coverage gaps or intermediate behavior where expected.
- A source-to-source sweep over the same 2,500 Homebrew, Python library, and
  repository text files found zero changes under all three policies, including
  finding order, namespace, view, offset and length. This is a sample of
  installed text, with no estimate of production precision.

## Bounds and partial findings

Both HTML lexical passes and the hidden-text reader use forward comment searches
that check the deadline during long reads. The second pass preserves the
first pass's blocks and adds distinct blocks it finds. With the same generated
inline fixtures, the old and new HTML readers returned identical ordered
pieces. Chromium 157 agreed on all 16,293 comparable single-block results from
19,025 generated and directed cases. The exact historical fuzz inputs were
unavailable, so this comparison used the same seeds and corpus sizes with a
reconstructed fragment set. The hidden reader's output matched the baseline
on those cases and the repository's 447 directed hidden-reader cases.
These results cover the tested lexical cases.

Median reader time across three runs was 0.08, 0.15, and 0.30 seconds at 1, 2,
and 4 MiB. The old second pass took 7.82 and 27.29 seconds at 1 and 2 MiB and
hit the probe deadline at 4 MiB. These timings are from the lexical reader,
separate from the complete scan and comparable only on this host.

Fresh-process peak RSS and wall time on 4 MiB inputs, with identical rules and
a 30-second scan budget. Peaks include the interpreter, warmed rules, and
input. The before-and-after HTML peaks reflect different outcomes.

| Input | `e761133` | `d6558f3` | `3341576` | Candidate |
| --- | --- | --- | --- | --- |
| HTML comment recovery | 67.9 MiB, timeout | 67.4 MiB, timeout | 67.4 MiB, timeout | 87.1 MiB, 1.50 s, clean |
| Atom HTML feed | 78.3 MiB, 0.37 s | 78.5 MiB, 0.69 s | 78.7 MiB, 0.76 s | 79.2 MiB, 0.88 s |
| JSON | 153.1 MiB, 0.45 s | 153.2 MiB, 0.44 s | 153.8 MiB, 0.45 s | 153.3 MiB, 0.43 s |
| Notebook-shaped JSON | 167.9 MiB, 0.63 s | 167.9 MiB, 0.61 s | 167.9 MiB, 0.65 s | 168.1 MiB, 0.62 s |

Matching starts as the reader yields pieces. Deduplication retains seen text
and folded spellings may wait for the folded pass. The feed measurement showed
no peak RSS reduction. The separate whole-document JSON allocation reproduced
and is tracked in [#258](https://github.com/cgfixit/yara-gate/issues/258).

From an installed wheel, the actual 100,000-piece cap and a one-second scan
deadline each returned exit 2, the matching incomplete reason, an earlier
`html-text` note, and a JSON report. Both inbox copies stayed in quarantine.
Findings from pieces already matched remain attached. Unread or pending
pieces can be absent.

## Runtime and browser

- The direct scanner and intake probe passed 617 library observations, 9
  benign observations, 55 CLI observations, and 3 injected failure paths.
  Focused tests passed the reader regressions and the invariant guard.
  All 83 four-MiB timing tripwire cases passed the existing 10-second
  per-scan ceiling. The slowest took 2.83 seconds.
- The wheel installation's reader files matched the tested source by SHA-256.
  Computer Use exercised its loopback workbench with Atom text and HTML,
  inline HTML comment reconstruction, a benign HTML control, Clear, and the
  full `agent-ingest` catalog. All 81 live results matched. The freshly built
  static replay showed the HTML pair and the expected exits after switching
  between default and agent-ingest.
- The focused checks used bundled rules on macOS. Hosted CI covers the
  broader platform matrix. No vendor packs or consumer integrations were run.
