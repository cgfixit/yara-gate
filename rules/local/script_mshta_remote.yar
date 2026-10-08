rule script_mshta_remote {
    meta:
        author = "yara-gate"
        description = "Mshta command directly loading an HTTP(S) resource"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
        technique = "T1218.005"
    strings:
        $remote = /\bmshta(\.exe)?["']?[ \t]+["']?https?:\/\/[^\s"'<>]{4,256}/ nocase ascii wide
    condition:
        $remote
}
