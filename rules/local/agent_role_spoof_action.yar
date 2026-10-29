rule agent_role_spoof_action {
    meta:
        author = "yara-gate"
        description = "Claimed system authority, an all-caps authority header line, or a developer claim followed by an override, disclosure, or mode-switch request"
        intent = "Advisory when a fake system role asks for an override"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
    strings:
        $role = /(\[im_start\]|<\|im_start\|>)[ \t]*(system|developer)[\s\S]{0,256}(reveal|ignore|override|execute|credentials)/ nocase ascii wide
        $claim = /(system message|developer message|highest priority|system prompt:)[\s\S]{0,256}(reveal|ignore|override|execute|credentials)/ nocase ascii wide
        $header = /(<\|start_header_id\|>(system|developer)<\|end_header_id\|>|\[start\](system|developer)\[message\]|<(system|developer)>)[\s\S]{0,256}\b(reveal|ignore|override|execute|credentials)\b/ nocase ascii wide
        // A one-line message: an all-caps authority header (SYSTEM:, [ADMIN], ADMIN OVERRIDE CODE 7731:) or an
        // "I am your developer" claim, then a disclosure, override, or mode-switch request on the same line.
        // The header is case-sensitive so "Operating system: Windows" and "System: reboot at 02:00" stay clean.
        $header_line = /(^|[\r\n])[ \t]*[\[(]?(SYSTEM|ADMIN|ADMINISTRATOR|DEVELOPER|OPERATOR)([ \t]+(OVERRIDE|MESSAGE|NOTICE|ALERT|UPDATE|CODE))?[^\r\n]{0,16}[:\]][^\r\n]{0,120}(?i:\b(reveal|disclose|print|output|show)[ \t]+(me[ \t]+)?(your|all|the)[ \t]+[^\r\n]{0,24}(configuration|system prompt|hidden instructions|instructions|credentials|password|api key)\b|\b(disregard|ignore|override|disable|bypass)[ \t]+(all[ \t]+|your[ \t]+|the[ \t]+)?[^\r\n]{0,24}(safety|content filters?|filters|rules|restrictions|guardrails|instructions|policy|policies|checks)\b|\b(enter|enable|switch to|activate)[ \t]+(maintenance|developer|debug|unrestricted|god)[ \t]+mode\b)/ ascii wide
        $claim_line = /\bI am your (developer|administrator|operator|creator)\b[^\r\n]{0,120}\b((reveal|disclose|print|output|show)[ \t]+(me[ \t]+)?(your|all|the)[ \t]+[^\r\n]{0,24}(configuration|system prompt|hidden instructions|instructions|credentials|password|api key)|(disregard|ignore|override|disable|bypass)[ \t]+(all[ \t]+|your[ \t]+|the[ \t]+)?[^\r\n]{0,24}(safety|content filters?|filters|rules|restrictions|guardrails|instructions|policy|policies|checks)|(enter|enable|switch to|activate)[ \t]+(maintenance|developer|debug|unrestricted|god)[ \t]+mode)\b/ nocase ascii wide
    condition:
        any of them
}
