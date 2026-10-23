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
        $future = /\bremember\b[\s\S]{0,48}\bfor future (sessions|tasks)\b[\s\S]{0,96}\b(bypass|skip|disable)[ \t]+(user[ \t]+)?(approval|confirmation|safety checks|audit logging)\b/ nocase ascii wide
    condition:
        any of them
}
