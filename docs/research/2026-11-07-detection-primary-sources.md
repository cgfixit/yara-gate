# Detection improvements: primary-source research

Research date: 2026-11-07. Repository context: `main` at
`05f94caaf596413a2011612821f3d7d2916e3e16`; open PR #182 was supplied for
context at `8f6b29f6b1e311d94bef4a7480090999dfd5b7b5`; the accompanying runtime
review refreshed it to `0fa5098ee2860ebd254d5566c2541b55de868588`. This note evaluates
directions for an offline file gate before AI ingestion. It is not a runtime
verification, PR approval, or measurement of detection effectiveness.

The recommendations below are engineering judgments derived from the cited
sources and the repository's existing contracts. They do not establish that an
external consumer currently violates those contracts.

## 1. Enforce the actual reader handoff first

The existing [integration guide](../integrations.md#pdfs-and-other-compressed-documents)
already says to scan both the original document and the consumer's extracted
text. Turn that contract into acceptance evidence in each real integration:
gate the exact post-conversion text buffer before chunking or indexing, and
bind its digest to the source digest, extractor version/options, policy, and
ruleset. Reuse `scan_bytes`; a new parser framework is unnecessary.

The reason is representation mismatch. PDF text extraction must infer reading
order, whitespace, and layout; even mature extractors document ambiguous text
ordering and coordinate errors. A source-file verdict therefore does not prove
coverage of another extractor's output. Add a small differential corpus using
the actual downstream extractor and a real viewer. Record differences instead
of assuming the gate must reproduce an entire renderer. [pypdf extraction
documentation](https://pypdf.readthedocs.io/en/stable/user/extract-text.html)

## 2. Calibrate hidden-text signals against viewer modes

PR #182's hidden-text/instruction conjunction is a useful direction, but
visibility needs a declared viewer and mode. Microsoft's `w:vanish` semantics
include style inheritance and an application option to reveal hidden text.
`w:webHidden` applies to web view and explicitly does not hide text in ordinary
paginated view. Neither property alone proves what every reviewer sees.
[Microsoft Vanish](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.vanish?view=openxml-3.0.1),
[Microsoft WebHidden](https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.wordprocessing.webhidden?view=openxml-3.0.1)

Prioritize real-viewer attack/control pairs before extending visibility
heuristics: directly hidden versus style-inherited text; web versus print view;
white text on white versus dark backgrounds; benign OCR layers versus embedded
instructions. Preserve original and extracted views and their provenance. Treat
unimplemented visibility cases as coverage limits, not evidence of visibility.

## 3. Make visual-input coverage an explicit admission decision

The project correctly documents that it does not OCR images. If a consumer sends
pixels to a vision model, a text scan cannot claim coverage of what that model
reads. For that integration, declare visual coverage absent and either hold the
input for its intended use or add a separately bounded local OCR/rendering
stage. Scan that stage's exact text output, retain the original image checks,
and record the engine and language settings. OCR still misses or misreads text,
so a clean OCR result must not become a semantic-safety claim. [pypdf OCR
limitations](https://pypdf.readthedocs.io/en/stable/user/extract-text.html#ocr-vs-text-extraction)

Do this only when a real consumer needs image ingestion. It adds parser surface,
latency, and language-dependent errors; it should not silently change today's
offline text-gate contract.

## 4. Preserve action authorization outside the detector

The README already separates permission to read from permission to follow
instructions. Verify that separation in CyClaw and CG-agent-harness: source
content cannot grant tool access, select an otherwise unauthorized destination,
or persist instructions into trusted memory. Validate tool parameters and
egress against user/session authority even after a clean scan. OWASP recommends
least privilege and independent tool-call validation; a guardrail model is
itself susceptible to injection. [OWASP prompt-injection
guidance](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html#agent-specific-defenses)

A local classifier could later supply additional advisory evidence for
paraphrases, but first measure its incremental recall, benign holds, latency,
and language coverage. It must not override deterministic blocks, incomplete
results, or action permissions. Keep the initial experiment outside the core
scanner.

## 5. Evaluate adaptation and user cost, not only known strings

Keep the existing paired fixtures and gap probes. Add held-out families with
different authors/templates, paraphrases, split instructions, formatting changes,
and supported languages. Separate extraction coverage, rule matches, policy
holds, and actual downstream attack outcomes. Include harmless documents about
attacks and ordinary operational instructions; report benign hold rates by
document/channel and policy, alongside incomplete rates and latency.

Adaptive evaluation is justified by research that defeated eight studied
defenses after tailoring attacks to them. That result is about those defenses,
not a measured bypass rate for yara-gate. Use a bounded, recorded attempt budget
against synthetic consumer tasks and keep tuning examples separate from the
held-out evaluation set. [Zhan et al., NAACL 2025](https://aclanthology.org/2025.findings-naacl.395/)

## 6. Strengthen execution and update boundaries

The current shared deadline is cooperative and does not preempt every parser.
For unattended hostile intake, evaluate a killable worker with a wall-clock
deadline, memory/CPU limits, bounded output, no credentials/network, and a
private disposable working area. Worker death, timeout, or malformed output
must hold the input. An operating-system resource boundary complements format
budgets; a timer thread does not provide the same guarantee. Parser exploits
and decompression bombs are recognized file-upload threats. [OWASP file-upload
guidance](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html#malicious-files)

Keep the existing locked environment, ruleset digest, staged vendor installation,
and visible skips. For engine/parser/vendor updates, compare compiled-rule and
skip inventories plus verdict/coverage/performance changes against the prior
version before promotion. YARA-X intentionally differs from YARA in regex and
other rule semantics; compilation success alone is not behavioral equivalence.
[YARA-X compatibility documentation](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/)

No code, dependency, policy, or vendor-pack changes were made for this research.
Native viewers, OCR engines, consumer integrations, and attack outcomes were not
exercised; the priorities require validation against the actual deployment.
