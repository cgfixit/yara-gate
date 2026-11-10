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

rule agent_invisible_run {
    meta:
        author = "yara-gate"
        description = "A run of 16 or more zero-width or invisible formatting characters in text"
        intent = "Advisory on 16 or more consecutive characters from U+200B to U+200D, U+2060 to U+2064, U+FEFF, U+180E, and U+034F in a text unit. The run renders as nothing and carries one bit or more per character, the zero-width encoding that hides bytes in ordinary text. A single joiner in Persian or Indic text, a ZWJ between emoji, a stray ZWSP, and an internal BOM do not form a run and stay notes (agent_invisible_unicode, heuristic_invisible_joiner). As for those notes, binary units are skipped and, in a decoded PDF stream, a match must have UTF-8 text beside it"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.unicode.org/reports/tr36/"
        reference_attack = "https://atlas.mitre.org/techniques/AML.T0068"
        technique = "T1027"
    strings:
        $run = /(\xe2\x80[\x8b-\x8d]|\xe2\x81[\xa0-\xa4]|\xef\xbb\xbf|\xe1\xa0\x8e|\xcd\x8f){16}/
    condition:
        yara_gate_text and $run
}
