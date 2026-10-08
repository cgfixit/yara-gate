rule doc_external_template {
    meta:
        author = "yara-gate"
        description = "OOXML relationship with an external attached-template target, or RTF remote template"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1221/"
    strings:
        // All three attributes must occur in the same bounded Relationship element.
        $rel = /<Relationship\b[^>]{0,2048}>/ nocase
        $type = /\bType\s*=\s*["'][^"']{0,256}\/attachedTemplate["']/ nocase
        $mode = /\bTargetMode\s*=\s*["']External["']/ nocase
        $target = /\bTarget\s*=\s*["'](https?:\/\/|\\\\)/ nocase
        $rtf = /\\template\b[\s\S]{0,256}(https?:\/\/|\\\\)/ nocase
    condition:
        (uint32(0) == 0x74725c7b and $rtf) or
        for any i in (1..#rel) : (
            $type in (@rel[i]..@rel[i]+!rel[i]-1) and
            $mode in (@rel[i]..@rel[i]+!rel[i]-1) and
            $target in (@rel[i]..@rel[i]+!rel[i]-1)
        )
}
