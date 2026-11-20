rule linux_desktop_exec_fetch {
    meta:
        author = "yara-gate"
        description = "Desktop entry whose Exec line runs a downloader or a decoder"
        intent = "Advisory on a .desktop launcher that fetches or decodes a payload when opened"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.bleepingcomputer.com/news/security/apt36-hackers-abuse-linux-desktop-files-to-install-malware/"
        technique = "T1204.002"
    strings:
        // The tool must be in command position on the Exec line: first, after a shell -c, or
        // after a separator. A browser URL such as https://curl.se/ is an argument, not a command.
        // The section header and an Exec line that starts within 4,096 bytes after it are two
        // strings paired in the condition. One pattern with [\s\S]{0,4096} between them is split
        // by YARA-X at a gap over 200 bytes and paired match by match, which reached the scan
        // deadline on a file of them (docs/verification/2026-11-20-any-byte-gap-timing.md).
        // The ascii and wide copies are separate so a UTF-16 header is paired only with a UTF-16
        // line; the window is 4,096 bytes for both, as [\s\S] matches one byte in a wide pattern.
        $entry = /\[Desktop Entry\]/ nocase ascii
        $entry_wide = /\[Desktop Entry\]/ nocase wide
        $exec = /[\r\n][ \t]*Exec[ \t]*=([^\r\n]{0,1024}([;&|`(]|[ \t]-c[ \t]+["']?))?[ \t]*["']?((\/usr)?(\/local)?\/s?bin\/)?(curl|wget|base64[ \t]+(-d|--decode)|xxd[ \t]+-r|openssl[ \t]+enc)\b/ nocase ascii
        $exec_wide = /[\r\n][ \t]*Exec[ \t]*=([^\r\n]{0,1024}([;&|`(]|[ \t]-c[ \t]+["']?))?[ \t]*["']?((\/usr)?(\/local)?\/s?bin\/)?(curl|wget|base64[ \t]+(-d|--decode)|xxd[ \t]+-r|openssl[ \t]+enc)\b/ nocase wide
    condition:
        for any i in (1..#entry) : ( $exec in (@entry[i] + !entry[i]..@entry[i] + !entry[i] + 4096) )
        or for any i in (1..#entry_wide) : (
            $exec_wide in (@entry_wide[i] + !entry_wide[i]..@entry_wide[i] + !entry_wide[i] + 4096)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of a header or an Exec line counts as a header with its line, so
        // a flood ahead of a pair cannot hide it
        // (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (#entry >= 1000000 or #entry_wide >= 1000000 or #exec >= 1000000 or #exec_wide >= 1000000)
            and ($entry or $entry_wide) and ($exec or $exec_wide)
        )
}

rule script_fetch_chmod_run {
    meta:
        author = "yara-gate"
        description = "One command line that downloads a file, marks it executable, and runs it by path"
        intent = "Advisory on curl or wget, then chmod, then a path launch chained on one line"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.sophos.com/blog/why-amos-matters-the-macos-malware-stealing-data-at-scale"
        technique = "T1105"
    strings:
        // A chain that ends in mv or an install step does not match; only a path launch does.
        $chain = /\b(curl|wget)\b[^\r\n]{0,512}(&&|;)[ \t]*(sudo[ \t]+)?chmod[ \t]+(\+x|[ugoa]{1,3}\+[rw]{0,2}x|[0-7]{3,4})[ \t]+[^\r\n]{1,256}(&&|;)[ \t]*(sudo[ \t]+)?["']?(\.{0,2}\/|~\/|\$[A-Za-z_{])/ nocase ascii wide
    condition:
        $chain
}

rule web_applescript_url_lure {
    meta:
        author = "yara-gate"
        description = "applescript URL that opens Script Editor with a prefilled shell or download script"
        intent = "Advisory on a Script Editor link whose script runs a shell command or curl"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.bleepingcomputer.com/news/security/new-macos-stealer-campaign-uses-script-editor-in-clickfix-attack/"
        technique = "T1059.002"
    strings:
        $url = /applescript:\/\/com\.apple\.scripteditor\?[^"'<>\s]{0,128}action=new[^"'<>\s]{0,128}script=[^"'<>\s]{0,4096}(do(%20|\+)shell(%20|\+)script|curl|osascript)/ nocase ascii wide
    condition:
        $url
}
