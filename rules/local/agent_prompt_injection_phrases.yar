rule agent_prompt_injection_phrases {
    meta:
        author = "yara-gate"
        description = "Phrases that try to override an agent prompt"
        intent = "Note on an instruction to the model, not on a paper that quotes one. Orders aimed at the agent's tools (exfiltrate, a concealed tool call) are agent_tool_hijack_directive and stay advisory"
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
        // The same order with the words in another place, or without an adjective. None of these has
        // the documentary exemption: it is written for the $a, $b, and $c grammar only.
        // "Ignore all instructions above", "disregard the rules above", "ignore above instructions".
        $a_post = /\b(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)(all([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?((the|your|any|my)([ \t]+|[ \t]*\r?\n[ \t]*))?(instructions?|directions|prompts?|rules)([ \t]+|[ \t]*\r?\n[ \t]*)above\b/ nocase ascii wide
        $a_above = /\b(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)(all([ \t]+|[ \t]*\r?\n[ \t]*))?above([ \t]+|[ \t]*\r?\n[ \t]*)(instructions?|directions|prompts?|rules)\b/ nocase ascii wide
        // Second person, no adjective: "ignore your instructions", "forget your system prompt".
        // "The model may ignore the system prompt" names no owner and stays clean, and so does
        // "don't forget your instructions": forget counts only before the prompt or programming.
        $a_your = /\b((ignore|disregard)([ \t]+|[ \t]*\r?\n[ \t]*)(all([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?your([ \t]+|[ \t]*\r?\n[ \t]*)(instructions|directions)|(ignore|disregard|forget)([ \t]+|[ \t]*\r?\n[ \t]*)(all([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?your([ \t]+|[ \t]*\r?\n[ \t]*)(programming|(system|developer)([ \t]+|[ \t]*\r?\n[ \t]*)(prompt|message|instructions)))\b/ nocase ascii wide
        // A negated verb: "do not follow the previous instructions", "stop following your earlier rules".
        $a_follow = /\b((do([ \t]+|[ \t]*\r?\n[ \t]*)not|don't|never)([ \t]+|[ \t]*\r?\n[ \t]*)(follow|obey)|stop([ \t]+|[ \t]*\r?\n[ \t]*)(following|obeying)|no([ \t]+|[ \t]*\r?\n[ \t]*)longer([ \t]+|[ \t]*\r?\n[ \t]*)(follow|obey))([ \t]+|[ \t]*\r?\n[ \t]*)((all|any)([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?((the|your|my)([ \t]+|[ \t]*\r?\n[ \t]*))?(previous|prior|preceding|earlier|above|initial|original)([ \t]+|[ \t]*\r?\n[ \t]*)(instructions?|directions|prompts?|rules)\b/ nocase ascii wide
        // "Override previous instructions". Rules are left out: later rules override earlier
        // rules in every stylesheet and firewall manual.
        $a_replace = /\b(override|overrule|bypass)([ \t]+|[ \t]*\r?\n[ \t]*)((all|any)([ \t]+|[ \t]*\r?\n[ \t]*)(of([ \t]+|[ \t]*\r?\n[ \t]*))?)?((the|your|my)([ \t]+|[ \t]*\r?\n[ \t]*))?(previous|prior|preceding|earlier|above|initial|original)([ \t]+|[ \t]*\r?\n[ \t]*)(instructions?|directions|prompts?)\b/ nocase ascii wide
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
    condition:
        $d or $d_dan or $e or $e_verbatim or $e_disclose or $new_instr or
        $a_post or $a_above or $a_your or $a_follow or $a_replace or
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
