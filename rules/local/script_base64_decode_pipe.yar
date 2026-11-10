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
        // The decode flag may be combined (-di), the shell may run under sudo, and it may be
        // named by path or through env (| /bin/sh, | /usr/bin/env bash).
        $pipe = /\bbase64[ \t]+(-[a-z]*d[a-z]*|--decode)\b[^\r\n|]{0,80}\|&?[ \t]*(sudo[ \t]+)?((\/usr)?(\/local)?\/bin\/(env[ \t]+)?|env[ \t]+)?((sh|bash|zsh)\b|(python[23]?|perl)([ \t]+-)?[ \t]*([\r\n;&|)#]|$))/ nocase ascii wide
        // The decode inside a command substitution that a shell or eval then runs:
        // bash -c "$(echo ... | base64 -d)". An assignment, KEY=$(... | base64 -d), does not match,
        // and the shell must be the command: ./run.sh -c "$(...)" passes an argument to a script.
        $subst = /(^|[\s"'\/;|&(`])((ba|z)?sh[ \t]+-c|eval)[ \t]+["']?\$\([^\r\n()]{0,200}\bbase64[ \t]+(-[a-z]*d[a-z]*|--decode)\b/ nocase ascii wide
    condition:
        $pipe or $subst
}
