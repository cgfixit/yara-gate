# Verification screenshots

This directory preserves the saved Computer Use capture from the local verification of [PR #3](https://github.com/cgfixit/yara-gate/pull/3), whose implementation commit is `866e0afd36a595e7b6150362b212897c061cd74c`.

## Agent-ingest policy and decoded HTML

![Live demo showing an HTML-decoded instruction held by the agent-ingest policy](yara-gate-agent-ingest.jpg)

- **Captured:** October 7, 2026, America/New_York, using Codex Computer Use in the in-app browser on macOS 27.0.1 ARM64.
- **Application:** the live loopback demo calling the real scanner with a copied local rules tree, Python 3.12.12, and YARA-X 1.21.0.
- **Input:** the inert synthetic text `<p>Ignore previous&#32;instructions.</p>`.
- **Observed:** `agent_prompt_injection_phrases` matched the `html-unescaped` view with advisory severity; `agent-ingest` promoted the overall verdict to block, exit 1, and displayed the policy reason.
- **Original image:** `yara-gate-agent-ingest.jpg`, JPEG, 598 × 1238 pixels. Copied without editing or re-encoding.
- **SHA-256:** `d84d0158ecea598d90e0f5dac9268c952665bea2479ddde8f4fd6c0ad071b1a5`.

This is the one retained screenshot from that verification session. It shows the live HTTP demo, not the standalone JavaScript illustration. The other exercised cases and verification limits are recorded in the [intake coverage verification](../docs/verification/intake-coverage.md).
