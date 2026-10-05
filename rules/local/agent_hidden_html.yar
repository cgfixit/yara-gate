rule agent_hidden_html {
    meta:
        author = "yara-gate"
        description = "Hidden HTML that also contains an instruction-like phrase"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $css1 = "display:none" nocase
        $css2 = "display: none" nocase
        $fs1 = "font-size:0" nocase
        $fs2 = "font-size: 0" nocase
        $p1 = "ignore previous instructions" nocase
        $p2 = "ignore all previous instructions" nocase
        $p3 = "disregard the above" nocase
        $p4 = "you are now" nocase
        $p5 = "system prompt:" nocase
        $p6 = "exfiltrate" nocase
        $p7 = "do not tell the user" nocase
    condition:
        (any of ($css*) or any of ($fs*)) and any of ($p*)
}
