import "lnk"

rule shortcut_powershell_encoded {
    meta:
        author = "yara-gate"
        description = "Parsed PowerShell shortcut with encoded command and hidden or bypass arguments"
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
