rule agent_turn_marker {
    meta:
        author = "yara-gate"
        description = "Chat-template token or role delimiter that opens a turn of prose, or a context closer with no opener"
        intent = "Note a spoofed conversation turn in text an agent reads: a model's special token (Llama 2 [INST] or <<SYS>>, Llama 3 headers, ChatML, Gemma, Harmony, Zephyr/Phi, Mistral, piped <||user||>) followed by words, a BEGIN/END USER banner closed by its delimiter, or a closing tag for an email, context, document, tool output, function results, or search results block that the text never opened. Model cards and prompt-format docs show these on purpose, so a lone marker is recorded, not held under agent-document; agent_fake_chat_marker is advisory when the marker carries an order. Template code (a marker followed by a quote, brace, or plus) and source-code suffixes stay clean"
        severity = "note"
        verdict_on_match = "note"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
        reference_attack = "https://attack.mitre.org/techniques/T1698/"
    strings:
        // A special token, then (after up to two line breaks) two words of prose.
        $token = /(\[INST\]|<<SYS>>|<\|(im_start|start_header_id|end_header_id|eot_id|begin_of_text|start|message|channel|system|user|assistant|endoftext)\|>|<\|\|[ \t]*(user|assistant|system)[ \t]*\|\|>|<(start|end)_of_turn>|\[(SYSTEM_PROMPT|TOOL_RESULTS|AVAILABLE_TOOLS)\])[ \t]*(\r?\n){0,2}[ \t]*[A-Za-z][A-Za-z']{0,24}([ \t,]+|[ \t]*\r?\n[ \t]*)[A-Za-z][A-Za-z']{1,24}/ nocase ascii wide
        // <-- BEGIN USER -->, [END SYSTEM], ### START ASSISTANT ###; "[END USER LICENSE ...]" stays clean.
        $banner = /(<!?-{2,}|\[|#{2,}|={2,}|-{3,})[ \t]*(BEGIN|END|START)[ \t_-]+(OF[ \t_-]+)?(THE[ \t_-]+)?(USER|ASSISTANT|SYSTEM)([ \t_-]+(MESSAGE|TURN|PROMPT|INPUT|INSTRUCTIONS?|QUERY))?[ \t]*(-{2,}>?|\]|#{2,}|={2,}|-{3,}|:|\r?\n)/ ascii wide
        $close_email = /<\/emails?>/ nocase ascii wide
        $open_email = /<emails?[\s>]/ nocase ascii wide
        $close_context = /<\/(context|documents?)>/ nocase ascii wide
        $open_context = /<(context|documents?)[\s>]/ nocase ascii wide
        $close_tool = /<\/(tool[_-]?(output|response)s?|function[_-]?results?|search[_-]?results?)>/ nocase ascii wide
        $open_tool = /<(tool[_-]?(output|response)s?|function[_-]?results?|search[_-]?results?)[\s>]/ nocase ascii wide
        $close_untrusted = /<\/(untrusted|retrieved|external)[_-]?(data|content|context|input|text)?>/ nocase ascii wide
        $open_untrusted = /<(untrusted|retrieved|external)[_-]?(data|content|context|input|text)?[\s>]/ nocase ascii wide
    condition:
        yara_gate_text
        and not yara_gate_ext matches /^(py|pyi|pyw|ipynb|js|mjs|cjs|jsx|ts|mts|cts|tsx|java|kt|kts|scala|go|rs|c|h|cc|cpp|hpp|cs|rb|php|swift|lua|jinja|jinja2|j2|tmpl|gotmpl)$/
        and (
            $token or $banner
            or ($close_email and not $open_email)
            or ($close_context and not $open_context)
            or ($close_tool and not $open_tool)
            or ($close_untrusted and not $open_untrusted)
        )
}
