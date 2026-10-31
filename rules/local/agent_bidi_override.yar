rule agent_bidi_override {
    meta:
        author = "yara-gate"
        description = "Explicit left-to-right or right-to-left override in text"
        intent = "Note an explicit bidirectional override in a text unit. In prose it is as often a copied right-to-left name as a spoof, so one hit is recorded, not held under agent-document; a second lexical note in the same member makes heuristic_unicode_control_conjunction (advisory). In a source-code file agent_bidi_source blocks it (Trojan Source). Binary units are skipped"
        severity = "note"
        verdict_on_match = "note"
        reference = "https://www.unicode.org/reports/tr9/"
    strings:
        $d = { E2 80 AD }
        $e = { E2 80 AE }
    condition:
        yara_gate_text and any of them
}
