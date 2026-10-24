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
        // The tool must be on the Exec line itself, after the [Desktop Entry] header.
        $exec = /\[Desktop Entry\][\s\S]{0,4096}[\r\n][ \t]*Exec[ \t]*=[^\r\n]{0,1024}\b(curl|wget|base64[ \t]+(-d|--decode)|xxd[ \t]+-r|openssl[ \t]+enc)\b/ nocase ascii wide
    condition:
        $exec
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
