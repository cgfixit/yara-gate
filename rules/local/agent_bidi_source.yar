rule agent_bidi_source {
    meta:
        author = "yara-gate"
        description = "Bidirectional override, embedding, or isolate in a source-code file (Trojan Source)"
        intent = "Block any explicit bidirectional control in a file whose extension names a programming or shell language. CVE-2021-42574 reorders what a reviewer sees in a comment or string literal against what the compiler or interpreter reads; compilers such as rustc reject these characters in literals and comments by default, so source code has no ordinary use for them. The suffix comes from the submitted or member name"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://trojansource.codes/"
        reference_cve = "https://nvd.nist.gov/vuln/detail/CVE-2021-42574"
    strings:
        $override = { E2 80 ( AD | AE ) }
        $embedding = { E2 80 ( AA | AB | AC ) }
        $isolate = { E2 81 ( A6 | A7 | A8 | A9 ) }
    condition:
        yara_gate_text
        and yara_gate_ext matches /^(c|h|cc|cpp|cxx|hh|hpp|hxx|cs|java|kt|kts|scala|groovy|go|rs|swift|m|mm|py|pyw|pyi|js|mjs|cjs|jsx|ts|mts|cts|tsx|rb|php|pl|pm|lua|dart|zig|sh|bash|zsh|ps1|psm1|psd1|bat|cmd|vbs|sql)$/
        and any of them
}
