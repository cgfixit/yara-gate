rule agent_persistent_instruction {
    meta:
        author = "yara-gate"
        description = "Request to persist approval or safety bypass instructions in agent guidance or future sessions"
        intent = "Advisory on a request to persist a safety bypass"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html"
    strings:
        $file = /\b(append|write|save|store)\b[\s\S]{0,96}\b(AGENTS\.md|CLAUDE\.md|MEMORY\.md|memory)\b[\s\S]{0,160}\b(bypass|skip|disable)[ \t]+(user[ \t]+)?(approval|confirmation|safety checks|audit logging)\b/ nocase ascii wide
        // "Remember for future sessions" or "for all future sessions", then the bypass. The bypass
        // opens a clause or follows "to", "must", "always", and the like, so a standing rule that
        // keeps the check ("never skip approval", "do not bypass confirmation") stays clean. The
        // word before the verb is read in the pattern, not by pairing matches, so the cost stays
        // linear on a file of repeated lines.
        $future = /\bremember\b[\s\S]{0,48}\b(for|in)[ \t]+(all[ \t]+)?future[ \t]+(sessions|tasks|conversations|chats)\b([\s\S]{0,96}([:,;.!\r\n-]|\b(to|must|should|always|please|and|then|also|can|may|will|just|you|we|I)))?[ \t]+(bypass|skip|disable)[ \t]+(user[ \t]+)?(approval|confirmation|safety checks|audit logging)\b/ nocase ascii wide
    condition:
        any of them
}
