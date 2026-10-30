rule script_download_execute {
    meta:
        author = "yara-gate"
        description = "Download and interpreter execution in the same bounded command region"
        intent = "Advisory on a download piped or substituted into a shell, not on a writeup that quotes that lure"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        // sudo, with or without flags such as -E, can sit between the pipe and the interpreter.
        $shell = /\b(curl|wget)\b[^\r\n|]{0,256}\|[ \t]*(sudo[ \t]+(-[A-Za-z]+[ \t]+)*)?(sh|bash|zsh|python[23]?|perl)\b/ nocase ascii wide
        // bash <(curl ...) and sh -c "$(curl ...)" run the download without a pipe.
        $subst = /\b(sh|bash|zsh)[ \t]+(-c[ \t]+["']?)?[<$]\([ \t]*(curl|wget)\b/ nocase ascii wide
        // iwr and irm are the built-in aliases that ClickFix command lines use.
        $powershell = /\b(Invoke-WebRequest|Invoke-RestMethod|DownloadString|iwr|irm)\b[^\r\n]{0,256}(Invoke-Expression|\bIEX\b)/ nocase ascii wide
        $powershell_reverse = /\b(Invoke-Expression|IEX)\b[^\r\n]{0,256}\b(Invoke-WebRequest|Invoke-RestMethod|DownloadString|iwr|irm)\b/ nocase ascii wide
        // A python -c one-liner whose quoted program fetches a URL and runs the result, in either
        // order. A Python file that does both is a program, not a one-liner, and is left alone.
        $py = /\bpython[23]?(\.exe)?[ \t]+(-[A-Za-z]+[ \t]+)*-c[ \t]+["'][^\r\n]{0,512}/ nocase ascii wide
        $py_fetch = /\b(urlopen|urlretrieve|requests\.(get|post)|http\.client|HTTPSConnection)\b/ ascii wide
        $py_exec = /\b(exec|eval|os\.system|os\.popen|subprocess\.(run|call|Popen|check_output))[ \t]*\(/ ascii wide
        $doc = /(the following command|common lure|for example)[\s\S]{0,160}\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|iwr|irm|python[23]?)\b/ nocase
    condition:
        ($shell or $subst or $powershell or $powershell_reverse or
         for any i in (1..#py) : (
             $py_fetch in (@py[i]..@py[i] + !py[i] - 1) and
             $py_exec in (@py[i]..@py[i] + !py[i] - 1)
         )) and not $doc
}
