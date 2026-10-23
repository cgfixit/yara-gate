rule agent_bidi_formatting {
    meta:
        author = "yara-gate"
        description = "Directional embeddings and isolates"
        intent = "Block directional embeddings and isolates"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://www.unicode.org/reports/tr9/"
    strings:
        $embedding = { E2 80 ( AA | AB | AC ) }
        $isolate = { E2 81 ( A6 | A7 | A8 | A9 ) }
    condition:
        any of them
}
