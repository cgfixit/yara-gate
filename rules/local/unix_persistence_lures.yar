rule macos_password_prompt {
    meta:
        author = "yara-gate"
        description = "AppleScript dialog that asks for a password with a hidden answer"
        intent = "Advisory on a display dialog that collects a password, the stealer prompt that imitates a system request"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1056/002/"
        technique = "T1056.002"
    strings:
        // The dialog text names a password and the answer field is hidden: the stealer shape.
        $prompt = /\bdisplay[ \t]+dialog\b[^\r\n]{0,256}\b(password|passcode|passphrase|credentials)\b[^\r\n]{0,256}\bwith[ \t]+hidden[ \t]+answer\b/ nocase ascii wide
        $prompt_reverse = /\bdisplay[ \t]+dialog\b[^\r\n]{0,256}\bwith[ \t]+hidden[ \t]+answer\b[^\r\n]{0,128}\b(password|passcode|passphrase|credentials)\b/ nocase ascii wide
    condition:
        any of them
}

rule macos_keychain_dump {
    meta:
        author = "yara-gate"
        description = "security command that prints keychain secrets or dumps a keychain"
        intent = "Advisory on security find-generic-password or find-internet-password with -g or -w, or dump-keychain -d"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1555/001/"
        technique = "T1555.001"
    strings:
        // Without -g or -w the command prints metadata only; with them it prints the secret.
        $find = /\bsecurity[ \t]+find-(generic|internet)-password\b[^\r\n;|&]{0,200}[ \t]-[a-zA-Z]*[gw][a-zA-Z]*\b/ nocase ascii wide
        $dump = /\bsecurity[ \t]+dump-keychain[ \t]+(-[a-z]*d)\b/ nocase ascii wide
    condition:
        any of them
}

rule unix_privilege_persistence {
    meta:
        author = "yara-gate"
        description = "Shell text that grants passwordless sudo, preloads a library, plants a downloaded SSH key, edits the TCC database, or wipes shell history"
        intent = "Advisory on a persistence or anti-forensics edit to sudoers, ld.so.preload, authorized_keys, TCC.db, or the shell history"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1548/003/"
        technique = "T1548.003"
    strings:
        $sudoers = /\bNOPASSWD:[ \t]*ALL\b[^\r\n]{0,120}>>?[ \t]*\/etc\/sudoers/ nocase ascii wide
        $preload = />>?[ \t]*\/etc\/ld\.so\.preload\b/ nocase ascii wide
        // A key that arrives by download; a local public key appended by hand does not match.
        $sshkey = /\b(curl|wget)\b[^\r\n]{0,200}>>?[ \t]*[^\r\n]{0,80}\.ssh\/authorized_keys\b/ nocase ascii wide
        $tcc = /\bTCC\.db\b[^\r\n]{0,160}\b(insert|replace)[ \t]+(or[ \t]+replace[ \t]+)?into[ \t]+access\b/ nocase ascii wide
        $history = /\b(unset[ \t]+HISTFILE|export[ \t]+HISTFILE=\/dev\/null|history[ \t]+-c)\b[^\r\n]{0,120}\b(unset[ \t]+HISTFILE|history[ \t]+-c|rm[ \t]+-r?f[ \t]+[^\r\n]{0,60}_history)\b/ nocase ascii wide
    condition:
        any of them
}
