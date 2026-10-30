import "lnk"

rule shortcut_powershell_encoded {
    meta:
        author = "yara-gate"
        description = "Parsed PowerShell shortcut with encoded command and hidden or bypass arguments"
        intent = "Advisory on a PowerShell shortcut that hides an encoded command"
        verdict_on_match = "advisory"
        severity = "advisory"
        reference = "https://virustotal.github.io/yara-x/docs/modules/lnk/"
        technique = "T1059.001"
    condition:
        lnk.is_lnk and
        (lnk.relative_path matches /(^|[\\\/])(powershell|pwsh)\.exe$/i or
         lnk.local_base_path matches /(^|[\\\/])(powershell|pwsh)\.exe$/i or
         lnk.common_path_suffix matches /(^|[\\\/])(powershell|pwsh)\.exe$/i) and
        lnk.cmd_line_args matches /(^|[ \t])-(e|ec|enc|encodedcommand)[ \t]+["']?[A-Za-z0-9+\/]{40,512}={0,2}(["' \t\r\n]|$)/i and
        (lnk.cmd_line_args matches /(^|[ \t])-w(indowstyle)?[ \t]+(hidden|h)\b/i or
         lnk.cmd_line_args matches /(^|[ \t])-(ep|executionpolicy)[ \t]+bypass\b/i)
}

rule shortcut_mshta_remote {
    meta:
        author = "yara-gate"
        description = "Parsed MSHTA shortcut with an HTTP(S) argument"
        intent = "Advisory on an MSHTA shortcut that opens an HTTP argument"
        verdict_on_match = "advisory"
        severity = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
        technique = "T1218.005"
    condition:
        lnk.is_lnk and
        (lnk.relative_path matches /(^|[\\\/])mshta\.exe$/i or
         lnk.local_base_path matches /(^|[\\\/])mshta\.exe$/i or
         lnk.common_path_suffix matches /(^|[\\\/])mshta\.exe$/i) and
        lnk.cmd_line_args matches /^[ \t]*["']?https?:\/\/[^\s"'<>]{4,256}(["' \t\r\n]|$)/i
}

rule shortcut_padded_arguments {
    meta:
        author = "yara-gate"
        description = "Parsed shortcut whose command-line arguments open with a run of whitespace"
        intent = "Advisory on an .lnk whose arguments start with a line break, vertical tab, or form feed, or with 32 or more spaces or tabs, so the Properties dialog shows an empty Target"
        verdict_on_match = "advisory"
        severity = "advisory"
        reference = "https://www.trendaisecurity.com/en-us/resources-insights/trendai-security-blog/windows-shortcut-zero-day-exploit"
        technique = "T1204.002"
    condition:
        // ZDI-CAN-25373: space, tab, LF, VT, FF, and CR padding inside COMMAND_LINE_ARGUMENTS.
        // No shortcut writer puts a line break first; a few typed spaces stay clean.
        lnk.is_lnk and lnk.cmd_line_args matches /^([ \t]*[\r\n\x0b\x0c]|[ \t]{32,})/
}

rule shortcut_interpreter_remote {
    meta:
        author = "yara-gate"
        description = "Parsed shortcut that runs a command interpreter, script host, or installer tool with a URL or UNC path in its arguments"
        intent = "Advisory on an .lnk whose target is cmd, PowerShell, wscript, cscript, conhost, forfiles, rundll32, regsvr32, msiexec, certutil, or bitsadmin and whose arguments name an http(s) URL or a UNC path"
        verdict_on_match = "advisory"
        severity = "advisory"
        reference = "https://attack.mitre.org/techniques/T1204/002/"
        technique = "T1204.002"
    condition:
        // explorer.exe and browsers are left out: a share or web shortcut is ordinary.
        lnk.is_lnk and
        (lnk.relative_path matches /(^|[\\\/])(cmd|powershell|pwsh|wscript|cscript|conhost|forfiles|rundll32|regsvr32|msiexec|certutil|bitsadmin)\.exe$/i or
         lnk.local_base_path matches /(^|[\\\/])(cmd|powershell|pwsh|wscript|cscript|conhost|forfiles|rundll32|regsvr32|msiexec|certutil|bitsadmin)\.exe$/i or
         lnk.common_path_suffix matches /(^|[\\\/])(cmd|powershell|pwsh|wscript|cscript|conhost|forfiles|rundll32|regsvr32|msiexec|certutil|bitsadmin)\.exe$/i) and
        lnk.cmd_line_args matches /(https?:\/\/|\\\\[A-Za-z0-9._-]+\\)/i
}
