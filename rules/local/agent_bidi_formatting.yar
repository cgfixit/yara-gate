rule agent_bidi_formatting {
    meta:
        author = "yara-gate"
        description = "Directional embeddings and isolates can be legitimate multilingual formatting"
        verdict_on_match = "advisory"
        reference = "https://www.unicode.org/reports/tr9/"
    strings:
        $embedding = { E2 80 ( AA | AB | AC ) }
        $isolate = { E2 81 ( A6 | A7 | A8 | A9 ) }
    condition:
        any of them
}
