rule win_lolbin_download {
    meta:
        author = "yara-gate"
        description = "certutil, bitsadmin, or msiexec command that fetches an HTTP(S) URL"
        intent = "Advisory on a Windows built-in used as a downloader or remote installer, not on a mention of the tool"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1105/"
        technique = "T1105"
    strings:
        $certutil = /\bcertutil(\.exe)?["']?[ \t]+[^\r\n;&|]{0,64}-(urlcache|verifyctl)\b[^\r\n;&|]{0,128}\bhttps?:\/\// nocase ascii wide
        $bitsadmin = /\bbitsadmin(\.exe)?["']?[ \t]+[^\r\n;&|]{0,128}\/(transfer|addfile)\b[^\r\n;&|]{0,256}\bhttps?:\/\// nocase ascii wide
        $msiexec = /\bmsiexec(\.exe)?["']?[ \t]+[^\r\n;&|]{0,64}\/(i|package|a)[ \t]+["']?https?:\/\// nocase ascii wide
    condition:
        any of them
}
