rule doc_spreadsheet_formula_exec {
    meta:
        author = "yara-gate"
        description = "CSV, SYLK, or IQY cell that launches a program through DDE, calls a system DLL, or pulls remote data"
        intent = "Advisory on a spreadsheet text file whose cell runs cmd, powershell, or another host, or fetches a URL when opened"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://owasp.org/www-community/attacks/CSV_Injection"
        technique = "T1559.002"
    strings:
        // A cell starts at the file, a line, or a delimiter. =cmd|' /C calc'!A0 is the DDE shape.
        $dde = /(^|[\r\n,;\t"'])[ \t]*[=+\-@][ \t]*(cmd|powershell|pwsh|mshta|rundll32|regsvr32|msiexec|wscript|cscript|certutil)\b[^\r\n|]{0,64}\|/ nocase ascii wide
        $fetch = /(^|[\r\n,;\t"'])[ \t]*[=+\-@][^\r\n]{0,32}\b(DDE|WEBSERVICE|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED)\(/ nocase ascii wide
        // Excel 4.0 macro sheets in SYLK call Win32 exports by name; the E field marker precedes CALL.
        $xlm = /(CALL|REGISTER)\([ \t]*"(Shell32|urlmon|kernel32|user32)/ nocase ascii wide
        $exec = /\bEXEC\([ \t]*"[^"\r\n]{0,16}(cmd|powershell|mshta|rundll32|regsvr32)/ nocase ascii wide
        // An Internet Query file: WEB, a version line, then the URL Excel fetches.
        $iqy = /^WEB[\r\n]+[0-9]{0,4}[\r\n]+["']?https?:\/\// nocase ascii wide
    condition:
        any of them
}
