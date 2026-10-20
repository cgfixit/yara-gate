# Verification screenshots

This directory preserves original Computer Use captures from the live loopback demo. The current README uses the two ClickFix policy captures below. The earlier HTML-decoding capture remains tied to its original implementation.

The [October 19 PDF fast-path capture](../docs/verification/pdf-name-fast-path.md#computer-use)
records the candidate source hash, inert input, observed offsets and original image hash.

## ClickFix detection and consumer policy

| Default policy | Agent-ingest policy |
| --- | --- |
| ![ClickFix advisory under default policy](yara-gate-clickfix-advisory.jpg) | ![The same ClickFix advisory held by agent-ingest policy](yara-gate-clickfix-agent-ingest.jpg) |

- **Captured:** October 8, 2026, approximately 09:02–09:03 EDT (America/New_York), using Codex Computer Use in the in-app browser on macOS 27.0.1 ARM64.
- **Source:** `055500594b46432daea9a48e8a9efefb0005e6ae` in [draft PR #7](https://github.com/cgfixit/yara-gate/pull/7). Tracked files were clean when the demo started; the screenshots and README edits were added afterward. Scanner and rule code were unchanged during capture.
- **Application:** an owned `127.0.0.1` demo process using Python 3.12.12, YARA-X 1.21.0, and a disposable copy of all 16 shipped local rules. No vendor packs were downloaded and no operator gate home was used.
- **Input:** the two-line inert text below, scanned as bytes only. The script fragment was never executed. Both responses returned sample SHA-256 `9d56787f3ea03f7210b6208866119991681c619ac68e00715bbe263df478e901`.
- **Observed:** default policy returned `advisory`, exit 0; `agent-ingest` returned `block`, exit 1 with `agent-ingest holds advisory findings`. Both retained `web_clickfix_lure` with advisory severity, raw view, offset 67, and length 30.
- **Capture scope:** full-page browser screenshots, saved directly without cropping or re-encoding. These demonstrate scan and policy results; the demo does not perform drop-folder relocation. CLI disposition evidence is in the [delivery-rule verification](../docs/research/modern-delivery-rules.md#executed-verification).

```html
<p>Verify you are human. Press Win + R, then Ctrl + V.</p>
<script>navigator.clipboard.writeText("INERT_PLACEHOLDER");</script>
```

| Original image | Dimensions | SHA-256 |
| --- | --- | --- |
| [yara-gate-clickfix-advisory.jpg](yara-gate-clickfix-advisory.jpg) | 458 × 915 | `5323625a6d8ffaa285cde24822148168910d3bd8d36fb7d1ad956a2a86871c9b` |
| [yara-gate-clickfix-agent-ingest.jpg](yara-gate-clickfix-agent-ingest.jpg) | 458 × 933 | `4bcefa51b9c4e2c2b3a70b53250b40b2f0e372ae9061549f326090b1ca59c5f7` |

## Agent-ingest policy and decoded HTML

This earlier capture comes from local verification of [PR #3](https://github.com/cgfixit/yara-gate/pull/3), whose implementation commit is `866e0afd36a595e7b6150362b212897c061cd74c`.

![Live demo showing an HTML-decoded instruction held by the agent-ingest policy](yara-gate-agent-ingest.jpg)

- **Captured:** October 7, 2026, America/New_York, using Codex Computer Use in the in-app browser on macOS 27.0.1 ARM64.
- **Application:** the live loopback demo calling the real scanner with a copied local rules tree, Python 3.12.12, and YARA-X 1.21.0.
- **Input:** the inert synthetic text `<p>Ignore previous&#32;instructions.</p>`.
- **Observed:** `agent_prompt_injection_phrases` matched the `html-unescaped` view with advisory severity; `agent-ingest` promoted the overall verdict to block, exit 1, and displayed the policy reason.
- **Original image:** `yara-gate-agent-ingest.jpg`, JPEG, 598 × 1238 pixels. Copied without editing or re-encoding.
- **SHA-256:** `d84d0158ecea598d90e0f5dac9268c952665bea2479ddde8f4fd6c0ad071b1a5`.

This is the one retained screenshot from that verification session. It shows the live HTTP demo, not the standalone JavaScript illustration. The other exercised cases and verification limits are recorded in the [intake coverage verification](../docs/verification/intake-coverage.md).
