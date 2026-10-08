# Intake coverage verification

Verified locally on October 7, 2026, America/New_York, using macOS 27.0.1 ARM64, Python 3.12.12, yara-gate 0.2.0, and locked YARA-X 1.21.0. The starting revision was `3667747ee4394a4453d16a6d9e6ecf8eb1660ef2`. The runtime probe records the checked-out revision and hashes of the Python source and rule files it exercises.

This record preserves the first 12-rule implementation and its browser evidence. The [October 8 delivery-rule expansion](../research/modern-delivery-rules.md) records the later 16-rule pack, 70 library cases, 16 CLI operations, and three compilation/deadline checks. The screenshots and counts below describe the earlier implementation; they do not establish browser acceptance for the added delivery patterns.

## Delivered behavior

- Twelve shipped local rules: six existing rules plus directional-formatting, role/action spoofing, secret-transfer requests, selected base64 instruction variants, external OOXML/RTF templates, and download/execute chains. New families are advisory.
- Ordinary emoji/language joiners no longer block; directional isolates are advisory and explicit bidi overrides still block, including in decoded UTF-16 text.
- ZIP, tar, and gzip members receive YARA and document heuristics. Member identity survives into findings. Reads have per-member, cumulative-byte, member-count, and depth limits; recognized unsupported/encrypted containers are incomplete.
- UTF-16, HTML-unescaped, and format-control-removed views are scanned without altering originals. Reports label their views and do not attribute their offsets to the outer file.
- `--policy agent-ingest` blocks every advisory, records the policy reason, and retains the finding's advisory severity. Default exits and disposition remain compatible. Repeated inbox submissions return existing files to quarantine before rescanning.
- Required active local-rule compile failures make scans incomplete; optional vendor skips are counted. Results include engine/ruleset identity.

## Direct execution

`uv run python docs/research/probe_rule_coverage.py --verify` exercises the actual scanner and installed CLI. It creates only inert synthetic content, copies local rules, uses disposable homes, and performs no target execution or network calls. All 37 library cases, eight CLI intake/rescan cases, and three compilation/deadline checks met their expectations. The probe is also wired into the existing macOS/Linux GitHub Actions workflow.

Important comparisons include benign Unicode and UTF-16; quoted versus encoded instructions; a role marker without a requested action; unrelated XML relationship attributes that must not combine; reordered external-template attributes; a PDF directly, in ZIP, in tar, and in gzip-compressed tar; Office macro content in ZIP; malformed/encrypted/unsupported archives; and the 1,001-entry limit. CLI runs check process exit, JSON verdict, physical destination, report redaction, derived-offset attribution, and default → agent-ingest → default rescans of identical bytes.

Additional direct byte-limit runs used real compressed streams:

| Input | Result |
| --- | --- |
| Gzip expanding to 100 MiB + 1 byte | Incomplete, `archive member exceeds 100MB` |
| ZIP containing six 90 MiB members | Incomplete, `extracted size exceeds 500MB` |
| Three nested ZIP containers | Clean |

The byte-limit checks exercise actual bounded reads without changing limit constants or mocking the scanner. They establish these resource-limit outcomes, not a throughput benchmark.

## Computer Use

The live loopback demo was exercised through Codex Computer Use in the in-app browser. It called the real scanner, with a copied local rules tree. Observed outcomes:

- Plain sample and a combined emoji/Persian paste: clean, exit 0.
- Synthetic secret-transfer request: advisory/exit 0 under default; block/exit 1 under agent-ingest, with the policy reason displayed.
- HTML-encoded instruction: block under agent-ingest, with the finding labeled `html-unescaped`.
- PE disguised as PDF: block, exit 1.
- Empty submission: `empty text`, with the previous verdict cleared.

After the final scanner changes, a fresh demo process confirmed the benign Unicode and strict HTML-decoding cases again. The rendered strict-policy result was inspected and saved in [screenshots/yara-gate-agent-ingest.jpg](../../screenshots/yara-gate-agent-ingest.jpg), with [capture provenance and its original image hash](../../screenshots/README.md). Chrome automation was unavailable; the in-app browser supplied the browser evidence. This does not establish native Windows or a separate product's WKWebView behavior.

The standalone illustration's JavaScript passed `node --check`. Rendering its local `file:` URL was blocked by the browser URL policy; that optional preview was not attempted through another route. Browser acceptance above applies to the live HTTP demo.

## Checks and existing limitation

Ruff 0.16.10 lint and formatting, mypy 2.4.0 strict checking, actionlint 1.7.12 on both workflows, and `git diff --check` passed. No pytest or selftest suite was run locally. Existing hosted regression jobs remain enabled.

The live `watch --policy agent-ingest` process detected a newly created inbox file, blocked its advisory finding, and wrote the expected policy report. Its SIGINT shutdown exited with SIGSEGV (`-11`) and left its temporary PID file. The identical shutdown failure was reproduced from unchanged upstream `3667747` with the same environment and locked watchdog 6.0.0. That baseline reported an FSEvents stream startup error. Watcher shutdown on this macOS 27 host remains a pre-existing platform limitation; it is not reported as passed and was not worked around by switching observer implementations. Both probe processes exited and their owned temporary homes were removed.

## Remaining research

The broader P2 proposals remain follow-up work: parsed package lifecycle and shortcut detectors, semantic PDF/Office action analysis, optional sensitive-material policy, a held-out real benign/malicious corpus, and pinned vendor-pack comparisons. The new lexical template signatures do not replace an XML/RTF parser. The existing conservative PDF token behavior still blocks a navigation-only OpenAction. General document text extraction, arbitrary decoding, OCR, and multilingual semantic instruction detection are not implemented.

The shared deadline is checked between bounded reads and scan operations; third-party metadata/Office parsing is not preempted by an OS process deadline. No production false-positive rate, comprehensive prompt-injection coverage, live CyClaw/Harness integration, or native Windows acceptance is claimed.
