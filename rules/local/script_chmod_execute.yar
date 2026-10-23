rule script_chmod_execute {
    meta:
        id = "script_chmod_execute"
        author = "yara-gate"
        description = "chmod +x followed by execution in the same short region"
        intent = "Advisory when a file is marked executable and then run nearby"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1222/002/"
    strings:
        $chain = /\bchmod[ \t]+\+x\b[^\n]{0,120}\n[ \t]*(\.\/|bash[ \t]|sh[ \t]|zsh[ \t])/ nocase ascii wide
    condition:
        $chain
}
