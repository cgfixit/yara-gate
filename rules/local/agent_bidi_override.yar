rule agent_bidi_override {
    meta:
        author = "yara-gate"
        description = "Explicit left-to-right or right-to-left overrides"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://www.unicode.org/reports/tr9/"
    strings:
        $d = { E2 80 AD }
        $e = { E2 80 AE }
    condition:
        any of them
}
