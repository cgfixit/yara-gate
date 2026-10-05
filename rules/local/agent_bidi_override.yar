rule agent_bidi_override {
    meta:
        author = "yara-gate"
        description = "Bidirectional override and isolate characters"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://www.unicode.org/reports/tr9/"
    strings:
        $a = { E2 80 AA }
        $b = { E2 80 AB }
        $c = { E2 80 AC }
        $d = { E2 80 AD }
        $e = { E2 80 AE }
        $f = { E2 81 A6 }
        $g = { E2 81 A7 }
        $h = { E2 81 A8 }
        $i = { E2 81 A9 }
    condition:
        any of them
}
