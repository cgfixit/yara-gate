rule script_mshta_remote {
    meta:
        author = "yara-gate"
        description = "Mshta command directly loading an HTTP(S) resource or an inline vbscript: or javascript: URL"
        intent = "Advisory when mshta loads an HTTP resource or runs an inline script protocol"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
        technique = "T1218.005"
    strings:
        $remote = /\bmshta(\.exe)?["']?[ \t]+["']?https?:\/\/[^\s"'<>]{4,256}/ nocase ascii wide
        // mshta vbscript:Execute(...) and mshta javascript:... need no file and no network.
        $inline = /\bmshta(\.exe)?["']?[ \t]+["']?(vbscript|javascript):/ nocase ascii wide
    condition:
        $remote or $inline
}
