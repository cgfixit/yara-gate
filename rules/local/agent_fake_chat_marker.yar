rule agent_fake_chat_marker {
    meta:
        id = "agent_fake_chat_marker"
        author = "yara-gate"
        description = "Fake chat turn or context closer followed by an order, or a tool-result close with no matching open"
        intent = "Advisory when a spoofed turn carries an instruction: a ChatML, Llama, Gemma, Harmony, Zephyr/Phi, or Mistral token, a role tag that opens prose, a BEGIN/END USER banner, or a closing email, context, document, tool, function-results, or search-results tag the text never opened, followed within 200 bytes by an override or disclosure verb or by a send, forward, or reply aimed at an address or URL. A marker with no order is agent_turn_marker (note)"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
        reference_attack = "https://attack.mitre.org/techniques/T1698/"
    strings:
        $im = /<\|im_start\|>[ \t]*(system|assistant)[\s\S]{0,200}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $close = /<\/tool_result>[\s\S]{0,80}\b(ignore|reveal|execute|run_command|do not tell the user)\b/ nocase ascii wide
        $open = /<tool_result[\s>]/ nocase ascii wide
        // Another family's token, then an override or disclosure verb, or a send aimed at an
        // address or URL, within 200 bytes.
        $turn = /(\[INST\]|<<SYS>>|<\|(im_start|start_header_id|eot_id|start|message|channel|system|user|assistant|endoftext)\|>|<\|\|[ \t]*(user|assistant|system)[ \t]*\|\|>|<start_of_turn>|\[(SYSTEM_PROMPT|TOOL_RESULTS)\])[\s\S]{0,200}(\b(ignore|disregard|override|reveal|execute|run_command|do not tell the user)\b|(\b(send|forward|reply|respond|upload)\b|\b(e-?mail|post)[ \t])[^\r\n]{0,80}(@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,}|https?:\/\/))/ nocase ascii wide
        // A role tag that opens prose (XML records continue with another tag), then an order.
        $role = /<\/?(system|assistant|human|user)(_(message|query|input|turn|prompt))?>[ \t]*(\r?\n)?[ \t]*([A-Za-z][\s\S]{0,200})?(\b(ignore|disregard|override|reveal|execute|run_command|do not tell the user)\b|(\b(send|forward|reply|respond|upload)\b|\b(e-?mail|post)[ \t])[^\r\n]{0,80}(@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,}|https?:\/\/))/ nocase ascii wide
        // Upper-case banners closed by their delimiter: "## Start the system" and
        // "[END USER LICENSE AGREEMENT]" stay clean.
        $banner = /(<!?-{2,}|\[|#{2,}|={2,}|-{3,})[ \t]*(BEGIN|END|START)[ \t_-]+(OF[ \t_-]+)?(THE[ \t_-]+)?(USER|ASSISTANT|SYSTEM)([ \t_-]+(MESSAGE|TURN|PROMPT|INPUT|INSTRUCTIONS?|QUERY))?[ \t]*(-{2,}>?|\]|#{2,}|={2,}|-{3,}|:|\r?\n)[\s\S]{0,200}((?i:\b(ignore|disregard|override|reveal|execute|run_command|do not tell the user)\b)|(?i:\b(send|forward|reply|respond|upload)\b|\b(e-?mail|post)[ \t])[^\r\n]{0,80}(@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,}|https?:\/\/))/ ascii wide
        // A closer the text never opened ends the caller's data block early. The order is a
        // separate string checked by offset in the condition: a 200-byte regex gap after every
        // closer cost 0.4 s on a 1 MB XML export full of </email> and </context>.
        $closer = /<\/(emails?|context|documents?|tool[_-]?(output|response)s?|function[_-]?results?|search[_-]?results?|(untrusted|retrieved|external)[_-]?(data|content|context|input|text)?)>/ nocase ascii wide
        $order = /\b(ignore|disregard|override|reveal|execute|run_command|do not tell the user)\b|(\b(send|forward|reply|respond|upload)\b|\b(e-?mail|post)[ \t])[^\r\n]{0,80}(@[A-Za-z0-9-]{1,63}\.[A-Za-z]{2,}|https?:\/\/)/ nocase ascii wide
        $opener = /<(emails?|context|documents?|tool[_-]?(output|response)s?|function[_-]?results?|search[_-]?results?|(untrusted|retrieved|external)[_-]?(data|content|context|input|text)?)[\s>]/ nocase ascii wide
    condition:
        $im or ($close and not $open) or $turn or $role or $banner
        or ($closer and not $opener and for any i in (1..#closer) : ($order in (@closer[i]..@closer[i] + 260)))
}
