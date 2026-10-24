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
        // Each value must sit in a line after the [InternetShortcut] header.
        $remote = /\[InternetShortcut\][\s\S]{0,4096}[\r\n][ \t]*URL[ \t]*=[ \t]*["']?(file:|search-ms:|search:|\\\\)/ nocase ascii wide
        $program = /\[InternetShortcut\][\s\S]{0,4096}[\r\n][ \t]*URL[ \t]*=[ \t]*["']?[A-Za-z]:\\[^\r\n]{0,260}\.(exe|com|bat|cmd|scr|cpl|pif|hta|js|jse|vbs|vbe|wsf|ps1|msi)\b/ nocase ascii wide
        $workdir = /\[InternetShortcut\][\s\S]{0,4096}[\r\n][ \t]*WorkingDirectory[ \t]*=[ \t]*["']?(\\\\|file:|https?:)/ nocase ascii wide
    condition:
        any of them
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
        $icon = /\[(InternetShortcut|Shell|\.ShellClassInfo)\][\s\S]{0,4096}[\r\n][ \t]*(IconFile|IconResource)[ \t]*=[ \t]*["']?(\\\\|file:)/ nocase ascii wide
    condition:
        $icon
}

rule win_library_remote_location {
    meta:
        author = "yara-gate"
        description = "Library or search connector description whose location URL is a UNC path, file URL, or web address"
        intent = "Advisory on a .library-ms or .searchConnector-ms file that points Explorer at a remote location"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://research.checkpoint.com/2025/cve-2025-24054-ntlm-exploit-in-the-wild/"
        technique = "T1187"
    strings:
        // \b keeps <searchConnectorDescriptionList> from counting as a connector root.
        $location = /<(libraryDescription|searchConnectorDescription)\b[\s\S]{0,8192}<url>[ \t\r\n]*(\\\\|file:|https?:\/\/)/ nocase ascii wide
    condition:
        $location
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
