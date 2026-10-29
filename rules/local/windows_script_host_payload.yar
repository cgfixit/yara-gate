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
        // A shell object followed by a run or execute call on it.
        $run = /\b(WScript\.Shell|Shell\.Application)\b[\s\S]{0,512}\.(Run|Exec|ShellExecute)[ \t]*\(?[ \t]*["']?/ nocase ascii wide
        // A writeup that quotes the lure, as in the delivery rules.
        $doc = /(the following|common lure|for example)[\s\S]{0,160}\b(WScript\.Shell|XMLHTTP|ADODB\.Stream)\b/ nocase ascii wide
    condition:
        $create and $fetch and $run and not $doc
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
