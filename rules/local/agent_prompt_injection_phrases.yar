rule agent_prompt_injection_phrases {
    meta:
        author = "yara-gate"
        description = "Phrases that try to override an agent prompt"
        intent = "Advisory on an instruction to the model, not on a paper that quotes one"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "ignore all previous instructions" nocase
        $c = "disregard the above" nocase
        // A writeup that names the phrase is not itself an instruction.
        $doc_phrase = /the phrase[\s\S]{0,64}(ignore previous instructions|ignore all previous instructions|disregard the above)/ nocase
        $d = /\byou are now\b[\s\S]{0,96}\b(ignore|override|bypass|reveal|execute|unrestricted|unfiltered|uncensored|jailbr(oken|eak(ing|s)?)|developer mode|do anything now|(without|no)( any)? (restrictions|rules|limits|limitations|filters|guardrails))\b/ nocase ascii wide
        // DAN is case-sensitive so the name "Dan" stays clean; only the phrase is nocase.
        $d_dan = /\b(?i:you are now)\b[\s\S]{0,96}\bDAN\b/ ascii wide
        $e = /system prompt:[\s\S]{0,80}\b(reveal|ignore|override|credentials)\b/ nocase
        $f = /\b(please |to )exfiltrate\b|\bexfiltrate (the |this |secrets|data|files|credentials)\b/ nocase
        $g = /do not tell the user[\s\S]{0,160}\b(tool_call|run_command|execute_command|function call)\b/ nocase
        $g_rev = /\b(tool_call|run_command|execute_command|function call)\b[\s\S]{0,160}do not tell the user/ nocase
    condition:
        $d or $d_dan or $e or $f or $g or $g_rev or (($a or $b or $c) and not $doc_phrase)
}
