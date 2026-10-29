rule script_chmod_execute {
    meta:
        id = "script_chmod_execute"
        author = "yara-gate"
        description = "chmod +x, u+x, or an octal mode followed by execution (./, a shell, /tmp, or ~/) on the next line or after && or ;"
        intent = "Advisory when a file is marked executable and then run nearby"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1222/002/"
    strings:
        // The launch may follow on the next line or on the same line after && or ;. A path under
        // a temp directory or the home directory counts as a launch; /usr/bin does not.
        $chain = /\bchmod[ \t]+(\+x|[ugoa]{1,3}\+[rw]{0,2}x|[0-7]{3,4})\b[^\n]{0,120}(\n|&&|;)[ \t]*(\.\/|bash[ \t]|sh[ \t]|zsh[ \t]|\/(private\/)?(var\/)?tmp\/|~\/)/ nocase ascii wide
    condition:
        $chain
}
