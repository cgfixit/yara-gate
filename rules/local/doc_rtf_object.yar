rule doc_rtf_object {
    meta:
        id = "doc_rtf_object"
        author = "yara-gate"
        description = "RTF object data or an object update"
        intent = "Block an RTF file that carries objdata or objupdate"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://attack.mitre.org/techniques/T1204/"
    strings:
        $objdata = /\\objdata\b/ nocase ascii
        $objupdate = /\\objupdate\b/ nocase ascii
    condition:
        uint32(0) == 0x74725c7b and ($objdata or $objupdate)
}
