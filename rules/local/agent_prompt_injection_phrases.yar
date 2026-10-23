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
        $d = /\byou are now\b[\s\S]{0,96}\b(ignore|override|bypass|reveal|execute|unrestricted|unfiltered|uncensored|jailbr(oken|eak(ing|s)?)|developer mode|do anything now|(without|no)( any)? (restrictions|rules|limits|limitations|filters|guardrails))\b/ nocase ascii wide
        // DAN is case-sensitive so the name "Dan" stays clean; only the phrase is nocase.
        $d_dan = /\b(?i:you are now)\b[\s\S]{0,96}\bDAN\b/ ascii wide
        $e = "system prompt:" nocase
        $f = "exfiltrate" nocase
        $g = "do not tell the user" nocase
    condition:
        any of them
}
