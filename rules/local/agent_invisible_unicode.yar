rule agent_invisible_unicode {
    meta:
        author = "yara-gate"
        description = "Zero-width space, internal BOM or Unicode tags; ordinary joiners are allowed"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.unicode.org/reports/tr36/"
    strings:
        $zw0 = { E2 80 8B }
        $bom = { EF BB BF }
        $tag0 = { F3 A0 80 ?? }
        $tag1 = { F3 A0 81 ?? }
    condition:
        $zw0 or any of ($tag*) or ($bom and not $bom at 0)
}
