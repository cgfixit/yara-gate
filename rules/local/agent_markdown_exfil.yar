rule agent_markdown_exfil {
    meta:
        id = "agent_markdown_exfil"
        author = "yara-gate"
        description = "Markdown image or link whose query contains a template"
        intent = "Advisory when a markdown URL carries a template parameter"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/"
    strings:
        $link = /\[[^\]]{0,120}\]\(https?:\/\/[^)\s]{0,240}(\{\{|\$\{)/ nocase ascii
        $image = /!\[[^\]]{0,120}\]\(https?:\/\/[^)\s]{0,240}(\{\{|\$\{)/ nocase ascii
    condition:
        $link or $image
}
