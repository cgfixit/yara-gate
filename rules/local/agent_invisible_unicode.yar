rule agent_invisible_unicode {
    meta:
        author = "yara-gate"
        description = "Zero-width space, marks, word joiners, internal BOM, or Unicode tags"
        intent = "Block invisible Unicode and an internal BOM"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://www.unicode.org/reports/tr36/"
    strings:
        $zwsp = { E2 80 8B }
        $lrm = { E2 80 8E }
        $rlm = { E2 80 8F }
        $wj = { E2 81 ( A0 | A1 | A2 | A3 | A4 ) }
        $bom = { EF BB BF }
        $tag0 = { F3 A0 80 ?? }
        $tag1 = { F3 A0 81 ?? }
    condition:
        $zwsp or $lrm or $rlm or $wj or any of ($tag*) or ($bom and not $bom at 0)
}
