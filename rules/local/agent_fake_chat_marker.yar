rule agent_fake_chat_marker {
    meta:
        id = "agent_fake_chat_marker"
        author = "yara-gate"
        description = "Fake chat marker or a tool-result close with no matching open"
        intent = "Advisory when a chat marker carries an instruction, or a closing tool marker has no open"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $im = /<\|im_start\|>[ \t]*(system|assistant)[\s\S]{0,200}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $close = /<\/tool_result>[\s\S]{0,80}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $open = /<tool_result[\s>]/ nocase ascii wide
    condition:
        $im or ($close and not $open)
}
