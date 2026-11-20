rule doc_external_template {
    meta:
        author = "yara-gate"
        description = "OOXML relationship with an external attached-template target, or RTF remote template"
        intent = "Advisory on an external attached template"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1221/"
    strings:
        // All three attributes must occur in the same bounded Relationship element.
        $rel = /<Relationship\b[^>]{0,2048}>/ nocase
        $type = /\bType\s*=\s*["'][^"']{0,256}\/attachedTemplate["']/ nocase
        $mode = /\bTargetMode\s*=\s*["']External["']/ nocase
        $target = /\bTarget\s*=\s*["'](https?:\/\/|\\\\)/ nocase
        // The RTF control word and the remote opener that starts within 256 bytes after it. They
        // are separate strings paired in the condition. One pattern with [\s\S]{0,256} between
        // them is split by YARA-X at a gap over 200 bytes and paired match by match, which
        // reached the scan deadline on a file of them
        // (docs/verification/2026-11-20-any-byte-gap-timing.md).
        $template = /\\template\b/ nocase
        $link = /https?:\/\// nocase
        // Two backslashes that start a run. The byte before the window is the control word's
        // last letter, so every run in the window starts in it, and the window holds two
        // backslashes exactly when it holds this match one byte earlier. Matching every pair
        // would fill the list on a megabyte of backslashes in any file.
        $unc = /[^\\]\\\\/
    condition:
        (uint32(0) == 0x74725c7b and (
            for any i in (1..#template) : (
                $link in (@template[i] + !template[i]..@template[i] + !template[i] + 256)
                or $unc in (@template[i] + !template[i] - 1..@template[i] + !template[i] + 255)
            )
            // A full list of any of the three counts as the pair (see the note below).
            or (
                (#template >= 1000000 or #link >= 1000000 or #unc >= 1000000)
                and $template and ($link or $unc)
            )
        )) or
        for any i in (1..#rel) : (
            $type in (@rel[i]..@rel[i]+!rel[i]-1) and
            $mode in (@rel[i]..@rel[i]+!rel[i]-1) and
            $target in (@rel[i]..@rel[i]+!rel[i]-1)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of any string this condition places counts as every one of them
        // being near the others, so a flood ahead of a match cannot hide it
        // (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (#rel >= 1000000 or #type >= 1000000 or #mode >= 1000000 or #target >= 1000000)
            and $rel and $type and $mode and $target
        )
}
