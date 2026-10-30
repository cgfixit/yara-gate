rule agent_prompt_injection_phrases {
    meta:
        author = "yara-gate"
        description = "Phrases that try to override an agent prompt"
        intent = "Note on an instruction to the model, not on a paper that quotes one"
        severity = "note"
        verdict_on_match = "note"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        // Verb, optional quantifier and determiner, adjective, noun: "ignore all of your prior directions".
        // Words may be split by one line break (hard-wrapped Markdown, an SMS body); a blank line still splits them.
        $a = /\b(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)(all([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?(the([ \t]+|[ \t]*\r?\n[ \t]*)|your([ \t]+|[ \t]*\r?\n[ \t]*)|any([ \t]+|[ \t]*\r?\n[ \t]*)|my([ \t]+|[ \t]*\r?\n[ \t]*))?(previous|prior|preceding|earlier|initial|original)([ \t]+|[ \t]*\r?\n[ \t]*)(instructions?|directions|prompts?|rules)\b/ nocase ascii wide
        $b = /\b(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)(all([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?the([ \t]+|[ \t]*\r?\n[ \t]*)above\b/ nocase ascii wide
        $c = /\b(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)(everything|all)([ \t]+|[ \t]*\r?\n[ \t]*)(you([ \t]+|[ \t]*\r?\n[ \t]*)(were|have([ \t]+|[ \t]*\r?\n[ \t]*)been)([ \t]+|[ \t]*\r?\n[ \t]*)told|(said|stated|written)([ \t]+|[ \t]*\r?\n[ \t]*)(above|before|earlier))\b/ nocase ascii wide
        // Name the first phrase after the prefix, not a later separate directive.
        // YARA-X forbids mixing greedy and non-greedy quantifiers, so every quantifier here is lazy.
        // The match still ends at the word boundary after the noun, where $a, $b, and $c end.
        $doc_phrase = /the phrase[\s\S]{0,64}?\b(ignore|disregard|forget)([ \t]+?|[ \t]*?\r??\n[ \t]*?)((all([ \t]+?|[ \t]*?\r??\n[ \t]*?)(of([ \t]+?|[ \t]*?\r??\n[ \t]*?))??)??((the([ \t]+?|[ \t]*?\r??\n[ \t]*?)|your([ \t]+?|[ \t]*?\r??\n[ \t]*?)|any([ \t]+?|[ \t]*?\r??\n[ \t]*?)|my([ \t]+?|[ \t]*?\r??\n[ \t]*?))??(previous|prior|preceding|earlier|initial|original)([ \t]+?|[ \t]*?\r??\n[ \t]*?)(instructions??|directions|prompts??|rules)|the([ \t]+?|[ \t]*?\r??\n[ \t]*?)above)|(everything|all)([ \t]+?|[ \t]*?\r??\n[ \t]*?)(you([ \t]+?|[ \t]*?\r??\n[ \t]*?)(were|have([ \t]+?|[ \t]*?\r??\n[ \t]*?)been)([ \t]+?|[ \t]*?\r??\n[ \t]*?)told|(said|stated|written)([ \t]+?|[ \t]*?\r??\n[ \t]*?)(above|before|earlier)))\b/ nocase ascii wide
        $d = /\byou are now\b[\s\S]{0,96}\b(ignore|override|bypass|reveal|execute|unrestricted|unfiltered|uncensored|jailbr(oken|eak(ing|s)?)|developer mode|do anything now|(without|no)( any)? (restrictions|rules|limits|limitations|filters|guardrails))\b/ nocase ascii wide
        // DAN is case-sensitive so the name "Dan" stays clean; only the phrase is nocase.
        $d_dan = /\b(?i:you are now)\b[\s\S]{0,96}\bDAN\b/ ascii wide
        $e = /system prompt:[\s\S]{0,80}\b(reveal|ignore|override|credentials)\b/ nocase
        // "Repeat your system prompt verbatim": a disclosure demand, not a mention of the prompt.
        $e_verbatim = /\b(reveal|leak|repeat|print|output|dump)[ \t]+(me[ \t]+)?(your|the)[ \t]+(system[ \t]+prompt|(initial|hidden|original)[ \t]+instructions)\b[^\r\n]{0,40}\b(verbatim|word[ \t]+for[ \t]+word|in[ \t]+full|exactly)\b/ nocase ascii wide
        // "Reveal your system prompt" without a qualifier: second person only, so "the debug view can show
        // the system prompt" stays clean.
        $e_disclose = /\b(reveal|show|print|output|display|disclose|tell[ \t]+me)[ \t]+(me[ \t]+)?your[ \t]+(system[ \t]+prompt|(hidden|initial|original)[ \t]+instructions)\b/ nocase ascii wide
        // "New instructions:" followed by standing-order language on the same line.
        $new_instr = /\bnew[ \t]+instructions?[ \t]*:[^\r\n]{0,80}\b(from[ \t]+now[ \t]+on|respond[ \t]+only|you[ \t]+are[ \t]+now|ignore)\b/ nocase ascii wide
        $f = /\b(please |to )exfiltrate\b|\bexfiltrate (the |this |secrets|data|files|credentials)\b/ nocase
        $g = /do not tell the user[\s\S]{0,160}\b(tool_call|run_command|execute_command|function call)\b/ nocase
        $g_rev = /\b(tool_call|run_command|execute_command|function call)\b[\s\S]{0,160}do not tell the user/ nocase
    condition:
        $d or $d_dan or $e or $e_verbatim or $e_disclose or $new_instr or $f or $g or $g_rev or
        for any of ($a, $b, $c) : (
            for any i in (1..#) : (
                // Exempt only the occurrence ending at the nearest documentary match.
                with quote_index = #doc_phrase in (0..@[i]) : (
                    not defined @doc_phrase[quote_index] or
                    @doc_phrase[quote_index] + !doc_phrase[quote_index] != @[i] + ![i]
                )
            )
        )
}
