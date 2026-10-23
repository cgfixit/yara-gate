rule agent_hidden_html {
    meta:
        author = "yara-gate"
        description = "Hidden HTML with an instruction-like phrase within 256 bytes"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $hidden = /(display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|<!--)[\s\S]{0,256}(ignore previous instructions|ignore all previous instructions|disregard the above|you are now\b[\s\S]{0,96}\b(ignore|override|bypass|reveal|execute|unrestricted|unfiltered)\b|system prompt:|exfiltrate|do not tell the user)/ nocase ascii wide
    condition:
        $hidden
}
