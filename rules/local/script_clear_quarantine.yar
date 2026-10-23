rule script_clear_quarantine {
    meta:
        id = "script_clear_quarantine"
        author = "yara-gate"
        description = "Command that clears the macOS quarantine attribute"
        intent = "Advisory when xattr -d com.apple.quarantine is the command, not a mention"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1553/001/"
    strings:
        // A mid-sentence mention is not a command. The cue is a line or shell separator.
        $cmd = /(^|[\n;&|])[ \t]*xattr[ \t]+-d[ \t]+com\.apple\.quarantine\b/ nocase ascii wide
    condition:
        $cmd
}
