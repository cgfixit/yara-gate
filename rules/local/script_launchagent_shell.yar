rule script_launchagent_shell {
    meta:
        id = "script_launchagent_shell"
        author = "yara-gate"
        description = "LaunchAgent program arguments that run a shell or scripting interpreter with a downloader"
        intent = "Advisory on a plist whose ProgramArguments run a shell, python, perl, ruby, osascript, curl, or env with curl, wget, osascript, base64, or urlopen"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1543/001/"
    strings:
        $plist = "<plist" nocase ascii wide
        // The ProgramArguments key and an interpreter string that starts within 500 bytes after
        // it, paired in the condition. One pattern with [\s\S]{0,500} between them is split by
        // YARA-X at a gap over 200 bytes and paired match by match, which cost the square of the
        // number of keys (docs/verification/2026-11-20-any-byte-gap-timing.md). The ascii and wide
        // copies are separate strings so a UTF-16 key is paired only with a UTF-16 string; the
        // window is 500 bytes for both, as [\s\S] matches one byte in a wide pattern too.
        $key = /<key>ProgramArguments<\/key>/ nocase ascii
        $key_wide = /<key>ProgramArguments<\/key>/ nocase wide
        $shell = /<string>(\/bin\/(bash|sh|zsh)|\/usr\/bin\/(python3?|perl|ruby|osascript|curl|env))<\/string>/ nocase ascii
        $shell_wide = /<string>(\/bin\/(bash|sh|zsh)|\/usr\/bin\/(python3?|perl|ruby|osascript|curl|env))<\/string>/ nocase wide
        $net = /\b(curl|wget|osascript|base64|urlopen)\b/ nocase ascii wide
    condition:
        $plist and $net and (
            for any i in (1..#key) : ( $shell in (@key[i] + !key[i]..@key[i] + !key[i] + 500) )
            or for any i in (1..#key_wide) : (
                $shell_wide in (@key_wide[i] + !key_wide[i]..@key_wide[i] + !key_wide[i] + 500)
            )
            // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
            // notice. A full list of a key or an interpreter string counts as a key with its
            // interpreter, so a flood ahead of a pair cannot hide it
            // (docs/verification/2026-11-17-match-cap-rules.md).
            or (
                (#key >= 1000000 or #key_wide >= 1000000 or #shell >= 1000000 or #shell_wide >= 1000000)
                and ($key or $key_wide) and ($shell or $shell_wide)
            )
        )
}
