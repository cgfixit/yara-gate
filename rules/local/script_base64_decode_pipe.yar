rule script_base64_decode_pipe {
    meta:
        id = "script_base64_decode_pipe"
        author = "yara-gate"
        description = "base64 decode piped into a shell"
        intent = "Advisory when base64 -d is piped into sh or bash"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $pipe = /\bbase64[ \t]+(-d|--decode)\b[^\r\n|]{0,80}\|[ \t]*(sh|bash)\b/ nocase ascii wide
    condition:
        $pipe
}
