rule agent_hidden_html {
    meta:
        author = "yara-gate"
        description = "Hidden HTML or a Markdown comment with an instruction-like phrase within 256 bytes"
        intent = "Advisory when an instruction follows a hiding cue: display none, visibility hidden, a font size of 0 or 1 px, an offset of -1000 px or more that moves the text off screen, a screen-reader-only class, the hidden attribute, an HTML comment, or a Markdown reference-style comment. The cue alone is ordinary markup and is not reported; white or transparent text and zero opacity are not cues, because dark themes and fade-in animations use them on text a reader sees"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        // CSS is not computed: each cue is a spelling that hides text in most pages, read lexically.
        $hidden = /(display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|<!--|font-size\s*:\s*1p[xt]|(left|top|text-indent|margin-left|margin-top)\s*:\s*-([0-9]{4,6}(px|pt)?|[0-9]{3,6}r?em)|class\s*=\s*["'][^"'<>]{0,80}\b(sr-only|visually-hidden|screen-reader-text)\b|<[a-z][a-z0-9]{0,15}\s([^<>]{0,200}\s)?hidden[\s>\/=]|\[(\/\/|comment)\]:[ \t]*[#<])[\s\S]{0,256}(ignore previous instructions|ignore all previous instructions|disregard the above|you are now\b[\s\S]{0,96}\b(ignore|override|bypass|reveal|execute|unrestricted|unfiltered|uncensored|jailbr(oken|eak(ing|s)?)|developer mode|do anything now|(without|no)( any)? (restrictions|rules|limits|limitations|filters|guardrails))\b|system prompt:|exfiltrate|do not tell the user)/ nocase ascii wide
        // Same DAN carve-out as agent_prompt_injection_phrases: case-sensitive, so "Dan" stays clean.
        $hidden_dan = /(?i:display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden|<!--|font-size\s*:\s*1p[xt]|(left|top|text-indent|margin-left|margin-top)\s*:\s*-([0-9]{4,6}(px|pt)?|[0-9]{3,6}r?em)|class\s*=\s*["'][^"'<>]{0,80}\b(sr-only|visually-hidden|screen-reader-text)\b|<[a-z][a-z0-9]{0,15}\s([^<>]{0,200}\s)?hidden[\s>\/=]|\[(\/\/|comment)\]:[ \t]*[#<])[\s\S]{0,256}(?i:you are now)\b[\s\S]{0,96}\bDAN\b/ ascii wide
    condition:
        any of them
}
