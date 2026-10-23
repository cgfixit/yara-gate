rule script_download_execute {
    meta:
        author = "yara-gate"
        description = "Download and interpreter execution in the same bounded command region"
        intent = "Advisory on a download piped into a shell, not on a writeup that quotes that lure"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        $shell = /\b(curl|wget)\b[^\r\n|]{0,256}\|[ \t]*(sh|bash|zsh|python[23]?|perl)\b/ nocase ascii wide
        $powershell = /\b(Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b[^\r\n]{0,256}(Invoke-Expression|\bIEX\b)/ nocase ascii wide
        $powershell_reverse = /\b(Invoke-Expression|IEX)\b[^\r\n]{0,256}(Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b/ nocase ascii wide
        $doc = /(the following command|common lure|for example)[\s\S]{0,160}\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString)\b/ nocase
    condition:
        ($shell or $powershell or $powershell_reverse) and not $doc
}
