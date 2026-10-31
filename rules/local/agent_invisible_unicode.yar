rule agent_invisible_unicode {
    meta:
        author = "yara-gate"
        description = "Zero-width space, directional marks, word joiners, or an internal BOM in text"
        intent = "Note invisible formatting in a text unit. One hit is a paste artifact as often as an attack (a ZWSP copied from a web page, an RLM in a Hebrew or Arabic name), so it is recorded and not held under agent-document; the scanner reports heuristic_unicode_control_conjunction (advisory) when the same member also carries a lexical note, which is the split-phrase case. Unicode tag characters are heuristic_unicode_tag. Binary units are skipped: these byte sequences occur by chance in compressed data"
        severity = "note"
        verdict_on_match = "note"
        reference = "https://www.unicode.org/reports/tr36/"
    strings:
        $zwsp = { E2 80 8B }
        $lrm = { E2 80 8E }
        $rlm = { E2 80 8F }
        $wj = { E2 81 ( A0 | A1 | A2 | A3 | A4 ) }
        $bom = { EF BB BF }
    condition:
        yara_gate_text and ($zwsp or $lrm or $rlm or $wj or ($bom and not $bom at 0))
}
