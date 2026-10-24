rule script_base64_decode_pipe {
    meta:
        id = "script_base64_decode_pipe"
        author = "yara-gate"
        description = "base64 decode piped into sh, bash, or zsh"
        intent = "Advisory when base64 -d is piped into sh, bash, or zsh"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        $pipe = /\bbase64[ \t]+(-d|--decode)\b[^\r\n|]{0,80}\|[ \t]*(sh|bash|zsh)\b/ nocase ascii wide
    condition:
        $pipe
}
