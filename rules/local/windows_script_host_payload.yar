rule win_script_host_fetch_run {
    meta:
        author = "yara-gate"
        description = "VBScript or JScript that creates a download or file-write object and a shell object, then runs something"
        intent = "Advisory on a .vbs, .js, .jse, .wsf, or .hta body that fetches or writes a file and reaches WScript.Shell or Shell.Application to run it"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
        technique = "T1059.005"
    strings:
        // Object creation in either script language, including GetObject moniker forms.
        $create = /\b(CreateObject|ActiveXObject|GetObject)[ \t]*\(/ nocase ascii wide
        // Download or write-to-disk COM classes.
        $fetch = /\b(MSXML2\.(Server)?XMLHTTP|Microsoft\.XMLHTTP|WinHttp\.WinHttpRequest|ADODB\.Stream)\b/ nocase ascii wide
        // A shell object followed by a run or execute call that starts within 512 bytes after
        // it. They are two strings paired in the condition. One pattern with [\s\S]{0,512}
        // between them is split by YARA-X at a gap over 200 bytes and paired match by match,
        // which reached the scan deadline on a file of them
        // (docs/verification/2026-11-20-any-byte-gap-timing.md). The ascii and wide copies are
        // separate so a UTF-16 object is paired only with a UTF-16 call; the window is 512 bytes
        // for both, as [\s\S] matches one byte in a wide pattern too.
        $shell = /\b(WScript\.Shell|Shell\.Application)\b/ nocase ascii
        $shell_wide = /\b(WScript\.Shell|Shell\.Application)\b/ nocase wide
        $run = /\.(Run|Exec|ShellExecute)[ \t]*\(?[ \t]*["']?/ nocase ascii
        $run_wide = /\.(Run|Exec|ShellExecute)[ \t]*\(?[ \t]*["']?/ nocase wide
        // A writeup that quotes the lure, as in the delivery rules.
        $doc = /(the following|common lure|for example)[\s\S]{0,160}\b(WScript\.Shell|XMLHTTP|ADODB\.Stream)\b/ nocase ascii wide
    condition:
        $create and $fetch and not $doc and (
            for any i in (1..#shell) : ( $run in (@shell[i] + !shell[i]..@shell[i] + !shell[i] + 512) )
            or for any i in (1..#shell_wide) : (
                $run_wide in (@shell_wide[i] + !shell_wide[i]..@shell_wide[i] + !shell_wide[i] + 512)
            )
            // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
            // notice. A full list of a shell object or a call counts as an object with its call,
            // so a flood ahead of a pair cannot hide it
            // (docs/verification/2026-11-17-match-cap-rules.md).
            or (
                (#shell >= 1000000 or #shell_wide >= 1000000 or #run >= 1000000 or #run_wide >= 1000000)
                and ($shell or $shell_wide) and ($run or $run_wide)
            )
        )
}

rule win_cmd_fetch_start {
    meta:
        author = "yara-gate"
        description = "A downloader that saves a runnable file, then a start, call, or interpreter launch of a runnable file on the same or the next line"
        intent = "Advisory on a batch or PowerShell line that downloads an executable, script, or installer and then launches one"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1105/"
        technique = "T1105"
    strings:
        // Downloader, a saved runnable suffix, then a launch verb and a runnable suffix within one line break.
        $chain = /\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl(\.exe)?|wget(\.exe)?|certutil(\.exe)?[ \t]+-urlcache|bitsadmin(\.exe)?[ \t]+\/transfer)\b[^\r\n]{0,256}\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|msi|scr|com)\b[^\r\n]{0,200}(\r?\n|;|&&?|\|)[ \t]*(start|call|cmd(\.exe)?[ \t]+\/[ck]|rundll32|regsvr32|wscript|cscript|mshta|msiexec|powershell|pwsh|\.\\|\.\/)[^\r\n]{0,160}\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|hta|msi|scr|com)\b/ nocase ascii wide
        $doc = /(the following command|common lure|for example)[\s\S]{0,160}\b(iwr|irm|Invoke-WebRequest|curl|wget|certutil|bitsadmin)\b/ nocase ascii wide
    condition:
        $chain and not $doc
}
