rule agent_role_spoof_action {
    meta:
        author = "yara-gate"
        description = "Claimed system authority followed by an override or disclosure request"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $role = /(\[im_start\]|<\|im_start\|>)[ \t]*(system|developer)[\s\S]{0,256}(reveal|ignore|override|execute|credentials)/ nocase ascii wide
        $claim = /(system message|developer message|highest priority|system prompt:)[\s\S]{0,256}(reveal|ignore|override|execute|credentials)/ nocase ascii wide
    condition:
        any of them
}
