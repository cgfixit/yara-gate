rule win_hta_shell_object {
    meta:
        author = "yara-gate"
        description = "HTML Application that creates a shell, download, or file-write COM object"
        intent = "Advisory on an .hta whose script reaches WScript.Shell, Shell.Application, ADODB.Stream, or XMLHTTP"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/005/"
        technique = "T1218.005"
    strings:
        // The hta:application element is what makes mshta treat the page as an application.
        $hta = /<hta:application\b/ nocase ascii wide
        $object = /\b(WScript\.Shell|Shell\.Application|ADODB\.Stream|MSXML2\.(Server)?XMLHTTP|Microsoft\.XMLHTTP)\b/ nocase ascii wide
    condition:
        $hta and $object
}

rule win_wsf_remote_script {
    meta:
        author = "yara-gate"
        description = "Windows Script File whose script element loads its source from a URL or a UNC path"
        intent = "Advisory on a .wsf job that pulls its script body from a remote location"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/005/"
        technique = "T1059.005"
    strings:
        $job = /<(job|package)\b/ nocase ascii wide
        $src = /<script\b[^>]{0,256}\bsrc[ \t]*=[ \t]*["']?(https?:\/\/|\\\\)/ nocase ascii wide
    condition:
        $job and $src
}

rule win_msc_console_remote {
    meta:
        author = "yara-gate"
        description = "Management Console file whose StringTable holds a URL, script protocol, or UNC path, or that names apds.dll"
        intent = "Advisory on an .msc console that renders remote or scripted content when opened"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.elastic.co/security-labs/grimresource"
        technique = "T1218.014"
    strings:
        $console = /<MMC_ConsoleFile\b/ nocase ascii wide
        $string = /<String\b[^>]{0,120}>[^<]{0,64}(https?:\/\/|javascript:|vbscript:|\\\\)/ nocase ascii wide
        $apds = /\bapds\.dll\b/ nocase ascii wide
    condition:
        $console and ($string or $apds)
}

rule win_reg_run_interpreter {
    meta:
        author = "yara-gate"
        description = "Registry export that sets a Run, RunOnce, Winlogon, or IFEO Debugger value to a script host or installer"
        intent = "Advisory on a .reg file that would start powershell, mshta, wscript, rundll32, regsvr32, cmd, certutil, bitsadmin, or msiexec at logon"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1547/001/"
        technique = "T1547.001"
    strings:
        $header5 = "Windows Registry Editor Version 5.00" nocase ascii wide
        $header4 = "REGEDIT4" ascii wide
        // The value must follow a persistence key and name one of the interpreters or installers:
        // it starts within 1,024 bytes after the key's closing bracket, and a Debugger value
        // within 512 bytes after an Image File Execution Options key. Key and value are separate
        // strings paired in the condition. One pattern with [\s\S]{0,1024} between them is split
        // by YARA-X at a gap over 200 bytes and paired match by match, which reached the scan
        // deadline on a file of them (docs/verification/2026-11-20-any-byte-gap-timing.md).
        // The ascii and wide copies are separate so a UTF-16 key is paired only with a UTF-16
        // value; a window is the same number of bytes for both, as [\s\S] matches one byte in a
        // wide pattern too.
        $run_key = /\\CurrentVersion\\(Run|RunOnce|RunServices|Winlogon)[^\]\r\n]{0,64}\]/ nocase ascii
        $run_key_wide = /\\CurrentVersion\\(Run|RunOnce|RunServices|Winlogon)[^\]\r\n]{0,64}\]/ nocase wide
        $run_value = /"[^"\r\n]{0,64}"[ \t]*=[ \t]*"[^"\r\n]{0,96}\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|cmd(\.exe)?["']?[ \t]+\/[ck])\b/ nocase ascii
        $run_value_wide = /"[^"\r\n]{0,64}"[ \t]*=[ \t]*"[^"\r\n]{0,96}\b(powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec|cmd(\.exe)?["']?[ \t]+\/[ck])\b/ nocase wide
        $ifeo_key = /Image File Execution Options\\[^\]\r\n]{1,80}\]/ nocase ascii
        $ifeo_key_wide = /Image File Execution Options\\[^\]\r\n]{1,80}\]/ nocase wide
        $debugger = /"Debugger"[ \t]*=/ nocase ascii
        $debugger_wide = /"Debugger"[ \t]*=/ nocase wide
    condition:
        ($header5 or $header4) and (
            for any i in (1..#run_key) : (
                $run_value in (@run_key[i] + !run_key[i]..@run_key[i] + !run_key[i] + 1024)
            )
            or for any i in (1..#run_key_wide) : (
                $run_value_wide in (@run_key_wide[i] + !run_key_wide[i]..@run_key_wide[i] + !run_key_wide[i] + 1024)
            )
            or for any i in (1..#ifeo_key) : (
                $debugger in (@ifeo_key[i] + !ifeo_key[i]..@ifeo_key[i] + !ifeo_key[i] + 512)
            )
            or for any i in (1..#ifeo_key_wide) : (
                $debugger_wide in (@ifeo_key_wide[i] + !ifeo_key_wide[i]..@ifeo_key_wide[i] + !ifeo_key_wide[i] + 512)
            )
            // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
            // notice. A full list of a key or a value counts as a key with its value, so a flood
            // ahead of a pair cannot hide it
            // (docs/verification/2026-11-17-match-cap-rules.md).
            or (
                (#run_key >= 1000000 or #run_key_wide >= 1000000 or #run_value >= 1000000 or #run_value_wide >= 1000000)
                and ($run_key or $run_key_wide) and ($run_value or $run_value_wide)
            )
            or (
                (#ifeo_key >= 1000000 or #ifeo_key_wide >= 1000000 or #debugger >= 1000000 or #debugger_wide >= 1000000)
                and ($ifeo_key or $ifeo_key_wide) and ($debugger or $debugger_wide)
            )
        )
}

rule win_script_encoded_body {
    meta:
        author = "yara-gate"
        description = "Windows Script Encoder body: the #@~^ opening marker with its length field and the ==^#~@ closing marker"
        intent = "Advisory on a .vbe or .jse body, or an encoded script block in a page, that the script engines decode at run time so a reader cannot see it"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/scripting-articles/d14c8zsc(v=vs.84)"
        technique = "T1027.010"
    strings:
        // screnc writes the marker, a six-character base64 length, then ==; the body ends with ==^#~@.
        $open = /#@~\^[A-Za-z0-9+\/]{6}==/ ascii wide
        $close = "==^#~@" ascii wide
    condition:
        $open and $close
}
