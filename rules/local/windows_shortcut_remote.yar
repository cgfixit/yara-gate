rule win_internet_shortcut_launch {
    meta:
        author = "yara-gate"
        description = "Internet shortcut that targets a file, UNC, or search URL, a local program, or a remote working directory"
        intent = "Advisory on a .url shortcut that launches a file or program, or runs from a remote working directory"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://blog.checkpoint.com/research/inside-stealth-falcons-espionage-campaign-using-a-microsoft-zero-day/"
        technique = "T1204.002"
    strings:
        // Each value must sit in a line that starts within 4,096 bytes after the
        // [InternetShortcut] header. Header and lines are separate strings paired in the
        // condition. One pattern with [\s\S]{0,4096} between them is split by YARA-X at a gap
        // over 200 bytes and paired match by match, which reached the scan deadline on a file of
        // them (docs/verification/2026-11-20-any-byte-gap-timing.md). The ascii and wide copies
        // are separate so a UTF-16 header is paired only with a UTF-16 line; the window is 4,096
        // bytes for both, as [\s\S] matches one byte in a wide pattern too.
        $section = /\[InternetShortcut\]/ nocase ascii
        $section_wide = /\[InternetShortcut\]/ nocase wide
        $remote = /[\r\n][ \t]*URL[ \t]*=[ \t]*["']?(file:|search-ms:|search:|\\\\)/ nocase ascii
        $remote_wide = /[\r\n][ \t]*URL[ \t]*=[ \t]*["']?(file:|search-ms:|search:|\\\\)/ nocase wide
        $program = /[\r\n][ \t]*URL[ \t]*=[ \t]*["']?[A-Za-z]:\\[^\r\n]{0,260}\.(exe|com|bat|cmd|scr|cpl|pif|hta|js|jse|vbs|vbe|wsf|ps1|msi)\b/ nocase ascii
        $program_wide = /[\r\n][ \t]*URL[ \t]*=[ \t]*["']?[A-Za-z]:\\[^\r\n]{0,260}\.(exe|com|bat|cmd|scr|cpl|pif|hta|js|jse|vbs|vbe|wsf|ps1|msi)\b/ nocase wide
        $workdir = /[\r\n][ \t]*WorkingDirectory[ \t]*=[ \t]*["']?(\\\\|file:|https?:)/ nocase ascii
        $workdir_wide = /[\r\n][ \t]*WorkingDirectory[ \t]*=[ \t]*["']?(\\\\|file:|https?:)/ nocase wide
    condition:
        for any i in (1..#section) : (
            $remote in (@section[i] + !section[i]..@section[i] + !section[i] + 4096)
            or $program in (@section[i] + !section[i]..@section[i] + !section[i] + 4096)
            or $workdir in (@section[i] + !section[i]..@section[i] + !section[i] + 4096)
        )
        or for any i in (1..#section_wide) : (
            $remote_wide in (@section_wide[i] + !section_wide[i]..@section_wide[i] + !section_wide[i] + 4096)
            or $program_wide in (@section_wide[i] + !section_wide[i]..@section_wide[i] + !section_wide[i] + 4096)
            or $workdir_wide in (@section_wide[i] + !section_wide[i]..@section_wide[i] + !section_wide[i] + 4096)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of a header or a line counts as a header with its line, so a
        // flood ahead of a pair cannot hide it
        // (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (
                #section >= 1000000 or #section_wide >= 1000000 or #remote >= 1000000 or #remote_wide >= 1000000
                or #program >= 1000000 or #program_wide >= 1000000 or #workdir >= 1000000 or #workdir_wide >= 1000000
            )
            and ($section or $section_wide)
            and ($remote or $remote_wide or $program or $program_wide or $workdir or $workdir_wide)
        )
}

rule win_shortcut_remote_icon {
    meta:
        author = "yara-gate"
        description = "Internet shortcut, Explorer command, or folder settings file whose icon loads from a UNC path or file URL"
        intent = "Advisory on an icon path that makes Explorer contact a remote host when the folder is shown"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1187/"
        technique = "T1187"
    strings:
        // A section header and an icon line that starts within 4,096 bytes after it, paired in
        // the condition for the reason given in win_internet_shortcut_launch.
        $section = /\[(InternetShortcut|Shell|\.ShellClassInfo)\]/ nocase ascii
        $section_wide = /\[(InternetShortcut|Shell|\.ShellClassInfo)\]/ nocase wide
        $icon = /[\r\n][ \t]*(IconFile|IconResource)[ \t]*=[ \t]*["']?(\\\\|file:)/ nocase ascii
        $icon_wide = /[\r\n][ \t]*(IconFile|IconResource)[ \t]*=[ \t]*["']?(\\\\|file:)/ nocase wide
    condition:
        for any i in (1..#section) : (
            $icon in (@section[i] + !section[i]..@section[i] + !section[i] + 4096)
        )
        or for any i in (1..#section_wide) : (
            $icon_wide in (@section_wide[i] + !section_wide[i]..@section_wide[i] + !section_wide[i] + 4096)
        )
        // A full list of a header or an icon line counts as a header with its line
        // (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (#section >= 1000000 or #section_wide >= 1000000 or #icon >= 1000000 or #icon_wide >= 1000000)
            and ($section or $section_wide) and ($icon or $icon_wide)
        )
}

rule win_library_unc_location {
    meta:
        author = "yara-gate"
        description = "Library or search connector file whose location URL is a UNC path or a file URL with a host"
        intent = "Block a .library-ms or .searchConnector-ms file that makes Explorer contact an SMB host when it lists the folder or extracts the archive"
        severity = "block"
        verdict_on_match = "block"
        reference = "https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/"
        technique = "T1187"
    strings:
        // The description must open the file, after an optional XML declaration, so a
        // write-up that quotes one stays advisory. Entity-encoded slashes reach this rule
        // through the html-unescaped view.
        // The root element and a url element that starts within 8,192 bytes after it are two
        // strings paired in the condition, for the reason given in win_internet_shortcut_launch.
        // The root must start in the first four bytes, as the one pattern had to.
        $root = /[ \t\r\n]{0,64}(<\?xml[^>]{0,256}>[ \t\r\n]{0,64})?<(libraryDescription|searchConnectorDescription)\b/ nocase ascii
        $root_wide = /[ \t\r\n]{0,64}(<\?xml[^>]{0,256}>[ \t\r\n]{0,64})?<(libraryDescription|searchConnectorDescription)\b/ nocase wide
        $unc = /<url[ \t\r\n]*>[ \t\r\n]*(<!\[CDATA\[[ \t\r\n]*)?(file:)?[\\\/]{2}([^\\\/<]|[\\\/]{2})/ nocase ascii
        $unc_wide = /<url[ \t\r\n]*>[ \t\r\n]*(<!\[CDATA\[[ \t\r\n]*)?(file:)?[\\\/]{2}([^\\\/<]|[\\\/]{2})/ nocase wide
    condition:
        for any i in (1..#root) : (
            @root[i] <= 3 and $unc in (@root[i] + !root[i]..@root[i] + !root[i] + 8192)
        )
        or for any i in (1..#root_wide) : (
            @root_wide[i] <= 3 and $unc_wide in (@root_wide[i] + !root_wide[i]..@root_wide[i] + !root_wide[i] + 8192)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of a root or a url, with a root in the first four bytes, counts
        // as that root with its url (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (#root >= 1000000 or #root_wide >= 1000000 or #unc >= 1000000 or #unc_wide >= 1000000)
            and ($root in (0..3) or $root_wide in (0..3)) and ($unc or $unc_wide)
        )
}

rule win_library_remote_location {
    meta:
        author = "yara-gate"
        description = "Library or search connector description whose location URL is a web address or file URL, or a UNC path that win_library_unc_location does not block"
        intent = "Advisory on a .library-ms or .searchConnector-ms location that points Explorer at a remote site, or on quoted library XML"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/"
        technique = "T1187"
    strings:
        // \b keeps <searchConnectorDescriptionList> from counting as a connector root.
        // The root element and a url element that starts within 8,192 bytes after it, paired in
        // the condition for the reason given in win_internet_shortcut_launch.
        $root = /<(libraryDescription|searchConnectorDescription)\b/ nocase ascii
        $root_wide = /<(libraryDescription|searchConnectorDescription)\b/ nocase wide
        $location = /<url>[ \t\r\n]*(\\\\|file:|https?:\/\/)/ nocase ascii
        $location_wide = /<url>[ \t\r\n]*(\\\\|file:|https?:\/\/)/ nocase wide
    condition:
        (
            for any i in (1..#root) : (
                $location in (@root[i] + !root[i]..@root[i] + !root[i] + 8192)
            )
            or for any i in (1..#root_wide) : (
                $location_wide in (@root_wide[i] + !root_wide[i]..@root_wide[i] + !root_wide[i] + 8192)
            )
            // A full list of a root or a url counts as a root with its url
            // (docs/verification/2026-11-17-match-cap-rules.md).
            or (
                (#root >= 1000000 or #root_wide >= 1000000 or #location >= 1000000 or #location_wide >= 1000000)
                and ($root or $root_wide) and ($location or $location_wide)
            )
        )
        and not win_library_unc_location
}

rule web_search_ms_remote {
    meta:
        author = "yara-gate"
        description = "search-ms or search URI whose crumb location is a UNC path, encoded UNC path, or web address"
        intent = "Advisory on a Windows Search link that opens a remote share as if it were a local folder"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.trellix.com/blogs/research/beyond-file-search-a-novel-method/"
        technique = "T1204.001"
    strings:
        $uri = /\bsearch(-ms)?:[^\s"'<>]{0,512}crumb=location:[ \t]*(\\\\|%5c%5c|https?:|file:)/ nocase ascii wide
    condition:
        $uri
}
