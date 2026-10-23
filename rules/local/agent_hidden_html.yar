rule agent_hidden_html {
    meta:
        author = "yara-gate"
        description = "Hidden HTML with an instruction-like phrase within 256 bytes"
        intent = "Advisory when an instruction is hidden in HTML"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $hidden = /(display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|<!--)[\s\S]{0,256}(ignore previous instructions|ignore all previous instructions|disregard the above|you are now\b[\s\S]{0,96}\b(ignore|override|bypass|reveal|execute|unrestricted|unfiltered|uncensored|jailbr(oken|eak(ing|s)?)|developer mode|do anything now|(without|no)( any)? (restrictions|rules|limits|limitations|filters|guardrails))\b|system prompt:|exfiltrate|do not tell the user)/ nocase ascii wide
        // Same DAN carve-out as agent_prompt_injection_phrases: case-sensitive, so "Dan" stays clean.
        $hidden_dan = /(?i:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|<!--)[\s\S]{0,256}(?i:you are now)\b[\s\S]{0,96}\bDAN\b/ ascii wide
    condition:
        any of them
}
