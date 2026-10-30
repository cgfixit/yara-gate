rule script_base64_decode_pipe {
    meta:
        id = "script_base64_decode_pipe"
        author = "yara-gate"
        description = "base64 decode piped into sh, bash, or zsh, or into python or perl as the program"
        intent = "Advisory when base64 -d is piped into sh, bash, or zsh, or into python or perl with no program argument"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
    strings:
        // python or perl runs the decoded bytes only when given no program; base64 -d | python3 -m
        // json.tool decodes a token and stays clean.
        $pipe = /\bbase64[ \t]+(-d|--decode)\b[^\r\n|]{0,80}\|[ \t]*((sh|bash|zsh)\b|(python[23]?|perl)([ \t]+-)?[ \t]*([\r\n;&|)#]|$))/ nocase ascii wide
    condition:
        $pipe
}
