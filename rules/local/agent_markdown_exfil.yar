rule agent_markdown_exfil {
    meta:
        id = "agent_markdown_exfil"
        author = "yara-gate"
        description = "Markdown image, link, or reference definition whose URL contains a template"
        intent = "Advisory when a markdown URL carries a template parameter"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"
    strings:
        $link = /\[[^\]]{0,120}\]\(https?:\/\/[^)\s]{0,240}(\{\{|\$\{)/ nocase ascii
        $image = /!\[[^\]]{0,120}\]\(https?:\/\/[^)\s]{0,240}(\{\{|\$\{)/ nocase ascii
        // A reference-style definition, [label]: https://host/?q={{...}}, which a link or image
        // elsewhere in the text names by label (the EchoLeak shape, CVE-2025-32711).
        $reference = /(^|\n)[ \t]{0,3}\[[^\]\r\n]{1,120}\]:[ \t]*<?https?:\/\/[^\s<>]{0,240}(\{\{|\$\{)/ nocase ascii
    condition:
        $link or $image or $reference
}
