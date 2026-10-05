rule agent_prompt_injection_phrases {
    meta:
        author = "yara-gate"
        description = "Phrases that try to override an agent prompt"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "ignore all previous instructions" nocase
        $c = "disregard the above" nocase
        $d = "you are now" nocase
        $e = "system prompt:" nocase
        $f = "exfiltrate" nocase
        $g = "do not tell the user" nocase
    condition:
        any of them
}
