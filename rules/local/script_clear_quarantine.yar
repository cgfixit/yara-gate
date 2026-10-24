rule script_clear_quarantine {
    meta:
        id = "script_clear_quarantine"
        author = "yara-gate"
        description = "Command that deletes the macOS quarantine attribute or clears every attribute"
        intent = "Advisory when xattr -d com.apple.quarantine or xattr -c is the command, not a mention"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1553/001/"
    strings:
        // A mid-sentence mention is not a command. The cue is a line or shell separator.
        // -d, -rd, -dr and -r -d delete the attribute. -c, -cr and -rc clear all of them.
        $cmd = /(^|[\n;&|])[ \t]*(sudo[ \t]+)?xattr[ \t]+(-[rsv]+[ \t]+)?-[rsv]*(d[rsv]*[ \t]+com\.apple\.quarantine\b|c[rsv]*[ \t])/ nocase ascii wide
    condition:
        $cmd
}
