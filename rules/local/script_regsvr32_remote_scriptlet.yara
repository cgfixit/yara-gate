rule script_regsvr32_remote_scriptlet {
    meta:
        author = "yara-gate"
        description = "Regsvr32 with a remote /i target and scrobj.dll in one bounded command"
        intent = "Advisory when regsvr32 loads a remote scriptlet"
        verdict_on_match = "advisory"
        severity = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/010/"
        technique = "T1218.010"
    strings:
        $command = /\bregsvr32(\.exe)?["']?[ \t]+[^\r\n;|&]{1,2048}/ nocase ascii wide
        // regsvr32 reads /i: and -i: the same way.
        $remote = /[ \t][\/-]i:["']?https?:\/\/[^\s"'<>]{4,256}/ nocase ascii wide
        $scriptlet = /\bscrobj\.dll(["' \t\r\n]|$)/ nocase ascii wide
    condition:
        for any i in (1..#command) : (
            $remote in (@command[i]..@command[i] + !command[i] - 1) and
            $scriptlet in (@command[i]..@command[i] + !command[i] - 1)
        )
}
