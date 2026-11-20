rule win_defender_tamper {
    meta:
        author = "yara-gate"
        description = "Command or registry export that turns off Microsoft Defender protection, stops its service, or excludes a drive root, a user-writable folder, a script interpreter, or a runnable suffix"
        intent = "Advisory on the Defender tampering that loaders run before the payload, not on Get-MpPreference or a scoped build-folder exclusion"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/powershell/module/defender/set-mppreference"
        reference_attack = "https://attack.mitre.org/techniques/T1562/001/"
        technique = "T1562.001"
    strings:
        // Set-MpPreference switches take $true, 1, or no value at all; $false turns protection back on.
        $setmp = /\bSet-MpPreference\b[^\r\n;|]{0,200}[ \t]-Disable(RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|BlockAtFirstSeen|IntrusionPreventionSystem|ArchiveScanning)\b([ \t:]+(\$true|1)\b|[ \t]*(\r|\n|;|\||$|[ \t]-))/ nocase ascii wide
        // Excluding a whole drive, a temp or profile folder, an interpreter, or a runnable suffix.
        // Add appends to the exclusion list and Set replaces it; both leave the target unscanned.
        $exclude = /\b(Add|Set)-MpPreference\b[^\r\n;|]{0,120}[ \t]-Exclusion(Path|Process|Extension)[ \t:]+["']?(C:\\?["']?([ \t\r\n;|]|$)|\$env:(TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE|PUBLIC|ProgramData)\b|%(TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE|PUBLIC|ProgramData)%|C:\\(Users\\Public|ProgramData|Windows\\Temp)\b|(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b|\.?(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)["']?([ \t\r\n;|,]|$))/ nocase ascii wide
        // A policy value that switches Defender off: reg add, Set-ItemProperty, or a .reg line.
        $regcmd = /\b(reg(\.exe)?[ \t]+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,240}\bDisable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|OnAccessProtection|ScanOnRealtimeEnable)\b[^\r\n]{0,80}([\/-]d[ \t]+["']?0*1\b|-Value[ \t]+["']?0*1\b)/ nocase ascii wide
        $regfile = /(^|[\r\n])[ \t]*"Disable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|OnAccessProtection)"[ \t]*=[ \t]*dword:0{0,7}1\b/ nocase ascii wide
        // config counts only when it disables the service; "start= auto" repairs protection.
        $service = /\b(sc(\.exe)?[ \t]+(stop|delete)[ \t]+WinDefend\b|sc(\.exe)?[ \t]+config[ \t]+WinDefend\b[^\r\n;|&]{0,80}\bstart=[ \t]*disabled\b|Stop-Service\b[^\r\n;|]{0,40}\bWinDefend\b)/ nocase ascii wide
    condition:
        any of them
}

rule win_amsi_bypass {
    meta:
        author = "yara-gate"
        description = "Script that disables AMSI through AmsiUtils fields or patches AmsiScanBuffer or EtwEventWrite in memory"
        intent = "Advisory on the in-process AMSI and ETW bypasses that precede a PowerShell or .NET payload, not on a mention of AMSI"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal"
        reference_attack = "https://attack.mitre.org/techniques/T1562/001/"
        technique = "T1562.001"
    strings:
        // The reflection bypass: the AmsiUtils class plus its amsiInitFailed, amsiContext, or
        // amsiSession field, in either order within one script region.
        // The class and the field are separate strings and the condition looks for one starting
        // within 400 bytes after the other ends. One pattern with [\s\S]{0,400} between them is
        // split by YARA-X at a gap over 200 bytes and paired match by match, which reached the
        // scan deadline on a file of them (docs/verification/2026-11-20-any-byte-gap-timing.md).
        // The ascii and wide copies are separate so UTF-16 text is paired only with UTF-16 text;
        // a window is the same number of bytes for both, as [\s\S] matches one byte in a wide
        // pattern too. The field after the class needs no word boundary before it; the field
        // before the class does, so it has a string of its own.
        $utils = /AmsiUtils/ nocase ascii
        $utils_wide = /AmsiUtils/ nocase wide
        $field = /amsi(InitFailed|Context|Session)\b/ nocase ascii
        $field_wide = /amsi(InitFailed|Context|Session)\b/ nocase wide
        $field_first = /\bamsi(InitFailed|Context|Session)\b/ nocase ascii
        $field_first_wide = /\bamsi(InitFailed|Context|Session)\b/ nocase wide
        // The memory patch: resolve the export, then make its page writable, in either order
        // within 2,048 bytes.
        $export = /\b(AmsiScanBuffer|AmsiOpenSession|EtwEventWrite)\b/ nocase ascii
        $export_wide = /\b(AmsiScanBuffer|AmsiOpenSession|EtwEventWrite)\b/ nocase wide
        $protect = /\bVirtualProtect\b/ nocase ascii
        $protect_wide = /\bVirtualProtect\b/ nocase wide
    condition:
        for any i in (1..#utils) : ( $field in (@utils[i] + !utils[i]..@utils[i] + !utils[i] + 400) )
        or for any i in (1..#utils_wide) : (
            $field_wide in (@utils_wide[i] + !utils_wide[i]..@utils_wide[i] + !utils_wide[i] + 400)
        )
        or for any i in (1..#field_first) : (
            $utils in (@field_first[i] + !field_first[i]..@field_first[i] + !field_first[i] + 400)
        )
        or for any i in (1..#field_first_wide) : (
            $utils_wide in (@field_first_wide[i] + !field_first_wide[i]..@field_first_wide[i] + !field_first_wide[i] + 400)
        )
        or for any i in (1..#export) : (
            $protect in (@export[i] + !export[i]..@export[i] + !export[i] + 2048)
        )
        or for any i in (1..#export_wide) : (
            $protect_wide in (@export_wide[i] + !export_wide[i]..@export_wide[i] + !export_wide[i] + 2048)
        )
        or for any i in (1..#protect) : (
            $export in (@protect[i] + !protect[i]..@protect[i] + !protect[i] + 2048)
        )
        or for any i in (1..#protect_wide) : (
            $export_wide in (@protect_wide[i] + !protect_wide[i]..@protect_wide[i] + !protect_wide[i] + 2048)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of any string placed above counts as the pair lying in reach, so
        // a flood ahead of a pair cannot hide it
        // (docs/verification/2026-11-17-match-cap-rules.md). $field_first matches are
        // $field matches.
        or (
            (#utils >= 1000000 or #utils_wide >= 1000000 or #field >= 1000000 or #field_wide >= 1000000)
            and ($utils or $utils_wide) and ($field or $field_wide)
        )
        or (
            (#export >= 1000000 or #export_wide >= 1000000 or #protect >= 1000000 or #protect_wide >= 1000000)
            and ($export or $export_wide) and ($protect or $protect_wide)
        )
}

rule win_recovery_inhibit {
    meta:
        author = "yara-gate"
        description = "Command that deletes volume shadow copies or backups, or turns off Windows recovery"
        intent = "Advisory on the ransomware preparation step that removes restore points, not on listing or creating them"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1490/"
        technique = "T1490"
    strings:
        $vssadmin = /\bvssadmin(\.exe)?["']?[ \t]+delete[ \t]+shadows\b/ nocase ascii wide
        $wmic = /\bwmic(\.exe)?["']?[ \t]+([^\r\n;|]{0,64}[ \t])?shadowcopy[ \t]+([^\r\n;|]{0,64}[ \t])?delete\b/ nocase ascii wide
        // Get-WmiObject or Get-CimInstance on Win32_ShadowCopy piped into a delete.
        $ps = /\bWin32_ShadowCopy\b[^\r\n]{0,160}(\.Delete\(\)|Remove-(CimInstance|WmiObject)\b)/ nocase ascii wide
        $bcdedit = /\bbcdedit(\.exe)?["']?[ \t]+\/set[ \t]+[^\r\n;|]{0,40}\b(recoveryenabled[ \t]+(no|off|0)\b|bootstatuspolicy[ \t]+ignoreallfailures\b)/ nocase ascii wide
        $wbadmin = /\bwbadmin(\.exe)?["']?[ \t]+delete[ \t]+(catalog|systemstatebackup|backup)\b/ nocase ascii wide
    condition:
        any of them
}
