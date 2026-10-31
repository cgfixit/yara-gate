rule agent_bidi_formatting {
    meta:
        author = "yara-gate"
        description = "Directional embeddings and isolates in text"
        intent = "Note a directional embedding or isolate in a text unit. Isolates wrap right-to-left names in ordinary text, so one hit is recorded, not held under agent-document; a second lexical note in the same member makes heuristic_unicode_control_conjunction (advisory). In a source-code file agent_bidi_source blocks it (Trojan Source). Binary units are skipped"
        severity = "note"
        verdict_on_match = "note"
        reference = "https://www.unicode.org/reports/tr9/"
    strings:
        $embedding = { E2 80 ( AA | AB | AC ) }
        $isolate = { E2 81 ( A6 | A7 | A8 | A9 ) }
    condition:
        yara_gate_text and any of them
}
