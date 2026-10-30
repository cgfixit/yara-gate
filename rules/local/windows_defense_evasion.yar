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
        $exclude = /\bAdd-MpPreference\b[^\r\n;|]{0,120}[ \t]-Exclusion(Path|Process|Extension)[ \t:]+["']?(C:\\?["']?([ \t\r\n;|]|$)|\$env:(TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE|PUBLIC|ProgramData)\b|%(TEMP|TMP|APPDATA|LOCALAPPDATA|USERPROFILE|PUBLIC|ProgramData)%|C:\\(Users\\Public|ProgramData|Windows\\Temp)\b|(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b|\.?(exe|dll|ps1|bat|cmd|vbs|js|hta|scr)["']?([ \t\r\n;|,]|$))/ nocase ascii wide
        // A policy value that switches Defender off: reg add, Set-ItemProperty, or a .reg line.
        $regcmd = /\b(reg(\.exe)?[ \t]+add|Set-ItemProperty|New-ItemProperty)\b[^\r\n]{0,240}\bDisable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|OnAccessProtection|ScanOnRealtimeEnable)\b[^\r\n]{0,80}([\/-]d[ \t]+["']?0*1\b|-Value[ \t]+["']?0*1\b)/ nocase ascii wide
        $regfile = /(^|[\r\n])[ \t]*"Disable(AntiSpyware|AntiVirus|RealtimeMonitoring|BehaviorMonitoring|OnAccessProtection)"[ \t]*=[ \t]*dword:0{0,7}1\b/ nocase ascii wide
        $service = /\b(sc(\.exe)?[ \t]+(stop|delete|config)[ \t]+WinDefend\b|Stop-Service\b[^\r\n;|]{0,40}\bWinDefend\b)/ nocase ascii wide
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
        $utils_field = /AmsiUtils[\s\S]{0,400}amsi(InitFailed|Context|Session)\b/ nocase ascii wide
        $field_utils = /\bamsi(InitFailed|Context|Session)\b[\s\S]{0,400}AmsiUtils/ nocase ascii wide
        // The memory patch: resolve the export, then make its page writable.
        $patch = /\b(AmsiScanBuffer|AmsiOpenSession|EtwEventWrite)\b[\s\S]{0,2048}\bVirtualProtect\b/ nocase ascii wide
        $patch_reverse = /\bVirtualProtect\b[\s\S]{0,2048}\b(AmsiScanBuffer|AmsiOpenSession|EtwEventWrite)\b/ nocase ascii wide
    condition:
        any of them
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
