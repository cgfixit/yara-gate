rule agent_invisible_unicode {
    meta:
        author = "yara-gate"
        description = "Zero-width characters and Unicode tags"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://www.unicode.org/reports/tr36/"
    strings:
        $zw0 = { E2 80 8B }
        $zw1 = { E2 80 8C }
        $zw2 = { E2 80 8D }
        $zw3 = { E2 80 8E }
        $zw4 = { E2 80 8F }
        $wj0 = { E2 81 A0 }
        $wj1 = { E2 81 A1 }
        $wj2 = { E2 81 A2 }
        $wj3 = { E2 81 A3 }
        $wj4 = { E2 81 A4 }
        $bom = { EF BB BF }
        $tag0 = { F3 A0 80 ?? }
        $tag1 = { F3 A0 81 ?? }
    condition:
        any of ($zw*) or any of ($wj*) or any of ($tag*) or ($bom and not $bom at 0)
}
