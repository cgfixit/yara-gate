# Final combined acceptance — October 19, 2026

After all implementation, dependency and initial documentation changes were
finished, the four current draft heads were integrated without conflicts in an
owned disposable worktree. Final Computer Use and HTTP checks ran against that
candidate before publishing this evidence. No application code, rules or
dependencies changed after capture; only this record, screenshots and links were
added. All PRs remain independent drafts against main.

| Source | Exact revision |
| --- | --- |
| Main | `d72efc1566513ff40fc407d79db0404416cba0bc` |
| [#19 — tailored skills](https://github.com/cgfixit/yara-gate/pull/19) | `a4025352c44a5ba18e05ee72e4f37a685cc4d272` |
| [#20 — PDF name fast path](https://github.com/cgfixit/yara-gate/pull/20) | `ab77098f18e0622b7bd79063a819b50a9e8ced78` |
| [#21 — malformed JSON encoding](https://github.com/cgfixit/yara-gate/pull/21) | `6b705382a3aac0b6328ae226cd3c66e580da3b0b` |
| [#22 — dependencies and screenshots](https://github.com/cgfixit/yara-gate/pull/22) | `a4bb3f42de68863ba2cd21cd0443308a185bfce8` before this evidence-only update |
| Combined staged Git tree (uncommitted trial merge) | `f83424ed2a8120565bbfaeb9bdc77a0353b1130f` |

## Final Computer Use

Captured on October 19, 2026, approximately 21:13–21:18 EDT, using the macOS
in-app browser, Python 3.12.12 and YARA-X 1.21.0. The freshly frozen environment
ran `yara-gate demo --port 0 --rules <disposable-rules>` at
`http://127.0.0.1:50656/`, with copied local rules and a disposable cache. The
demo scanned inert input only; it did not relocate files or download vendor packs.

| Browser action | Observed result |
| --- | --- |
| Built-in plain note | Clean, exit 0, default policy |
| `<p>Ignore previous&#32;instructions.</p>`, default | Advisory, exit 0; `html-unescaped`, offset 3, length 28 |
| Same input, agent-ingest | Block, exit 1; policy reason displayed, finding severity remains advisory |
| PDF text with `/J#61vaScript /OpenAction` | Block, exit 1; raw findings at offsets 9 and 23, lengths 13 and 11 |
| PDF names `/JavaScripted /OpenActionable /OrdinaryName` | No PDF action findings; only the expected extension-mismatch advisory for PDF bytes pasted as `paste.txt`, held by agent-ingest |
| Built-in PE saved as PDF | Block, exit 1; `filetype_mismatch_pe` |
| Empty paste after the blocked result | `empty text`; previous verdict cleared |

| Default policy | Agent-ingest policy |
| --- | --- |
| ![Final default advisory](../../screenshots/yara-gate-final-default.jpg) | ![Final agent-ingest block with advisory severity](../../screenshots/yara-gate-final-agent-ingest.jpg) |

| PDF original-byte offsets | Rejected input |
| --- | --- |
| ![Final PDF findings](../../screenshots/yara-gate-final-pdf.jpg) | ![Final empty-input rejection clears verdict](../../screenshots/yara-gate-final-rejection.jpg) |

These original viewport JPEGs are 1265 × 712 pixels, saved without editing or
re-encoding. The narrower earlier strict-policy capture remains the README image
because its result is more readable at README width. The user attachment and all
earlier originals remain in the [complete gallery](../../screenshots/README.md).

| Capture | SHA-256 |
| --- | --- |
| `yara-gate-final-default.jpg` | `e735d6e74481483dbfe491c72c15204a03ee8a2d862b88a0cad45988e3d74ced` |
| `yara-gate-final-agent-ingest.jpg` | `c419ac862e0a8ef74f14a02e3ffc881a047b06d9f58630dc4a167ddf0d824a77` |
| `yara-gate-final-pdf.jpg` | `98781e599876fa6548d8ff13b42520e424ec0fbef5bbad869719b8f842090408` |
| `yara-gate-final-rejection.jpg` | `8ada9ec66b7802ec81db7587858128ea93bb2ce3f92901225b2facb100dbbdda` |

## Final HTTP checks

Python's `http.client` posted invalid UTF-8 `b'{"text":"\xff"}'` and truncated
UTF-16 `b'\xff\xfe\x00'` to the same live `/api/scan` endpoint. Each returned
HTTP 400 and `{"error":"bad json"}`. A subsequent plain-sample request after each
rejection returned HTTP 200, clean, exit 0. Assertions checked both the error and
recovery responses. These are direct transport checks, separate from browser
evidence: ordinary browser text entry does not send these malformed bytes.

## Source identity and prior checks

The final candidate retained the application and lock hashes already verified
independently and together earlier in this session:

| File | SHA-256 |
| --- | --- |
| `src/yara_gate/demo.py` | `f8fc91aec64372e0ab711e6dc78ea9e543b929fccb0db88aa48444ece7b10c72` |
| `src/yara_gate/heuristics.py` | `7deb6b3b8da4fba1c5c2ffb3e68cf320091c9da36290f266ea4ac55a074dbbca` |
| `src/yara_gate/demo_page.html` | `8ffa81c34bfeb64b946e0f02e5719addd51eb727d11dccbec85d1f94c4daa1b3` |
| `uv.lock` | `74adb38968047e8a9ffc630271d39e68960d476625b9aa403e442450bbdd2fe9` |

Earlier combined verification passed the maintained direct runtime probe (120
library cases, 24 CLI operations, nine benign observations, three failure checks;
20 compiled rules, zero skips), 18 focused PDF/demo/trust-boundary regressions,
Ruff lint/format, strict mypy and dependency compatibility. Those checks were not
repeated for screenshot and prose changes. Independent evidence remains in each
draft, including the [dependency record](dependency-refresh.md).

Hosted Ubuntu/macOS and CodeQL jobs remain blocked by GitHub account billing or
spending limits; no hosted pass is claimed. CodeQL upload remains disabled.
No full local suite, native Windows acceptance, vendor-pack validation or
production accuracy claim is included. Browser evidence verifies the live demo;
the earlier direct CLI probe covers disposition. This trial integration does not
merge any draft or modify main.
