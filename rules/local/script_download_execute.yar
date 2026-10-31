rule script_download_execute {
    meta:
        author = "yara-gate"
        description = "Download and interpreter execution in the same bounded command region"
        intent = "Advisory on a download piped or substituted into a shell or interpreter that runs it, not on a writeup that quotes that lure, prose that only names the idiom, or a download piped to Python as data (json.tool, or a one-line -c program that names no code-running call, dunder, os, open, or code-executing loader). The writeup exemption covers only a command on the same line as the documentary phrase or the line below it, so a payload placed under 'For example:' is not flagged; that is the accepted cost of a text-level exemption"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
    strings:
        // sudo, with or without flags such as -E, can sit between the pipe and the interpreter.
        // The download needs a target: a word that is not a flag or a backslash (or curl's attached -Kfile / --config= / --url=), so prose that
        // names the idiom ("no `curl | bash`", a table cell "curl \| sh") is not a command.
        $shell = /\b(curl|wget)\b[^\r\n|]{0,256}[ \t](["']?[A-Za-z0-9$\/~.(@{]|-[A-Za-z]*(?-i:K)[^ \t\r\n|]|--(config|url)=)[^\r\n|]{0,256}\|[ \t]*(sudo[ \t]+(-[A-Za-z]+[ \t]+)*)?(sh|bash|zsh|python[23]?|perl)\b/ nocase ascii wide
        // Python reading the download as data: json.tool, or a one-line -c program closed on the
        // same line and followed by a boundary (end of line, space, ; & | ) < > . , or a closing backtick), so adjacent quoted segments ('a;''exec(...)') end no exemption. It exempts the $shell match at the same offset only when the program holds
        // no code-execution call ($py_danger), so `| python3 -c "exec(sys.stdin.read())"` still
        // matches, and a -c program that runs onto the next line is never exempt.
        $shell_data = /\b(curl|wget)\b[^\r\n|]{0,512}\|[ \t]*python[23]?(\.exe)?[ \t]+(-m[ \t]+json\.tool\b|-c[ \t]+("[^"$`\r\n]{1,512}"|'[^'\r\n]{1,512}')[ \t]*(\r|\n|[;&|)<>.,`]|$))/ nocase ascii wide
        // A denylist: names that run, load, or write code, any dunder (getattr(__builtins__, ...)
        // tricks), and loaders that execute what they parse. Any hit keeps the $shell match.
        $py_danger = /\b(exec|execfile|eval|compile|getattr|setattr|globals|locals|vars|open|os|subprocess|ctypes|importlib|runpy|code|builtins|yaml|pickle|jsonpickle|dill|shelve|marshal|joblib)\b|__[A-Za-z]+__|sys\.modules/ ascii wide
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
        $doc = /(the following command|common lure|for example)[^\r\n]{0,160}(\r?\n[ \t]*)?\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|iwr|irm|python[23]?)\b/ nocase
    condition:
        // A documentary phrase exempts only the match whose first byte its own span covers:
        // the phrase on the same line as the command or on the line above it.
        for any i in (1..#shell) : (
            not for any j in (1..#doc) : (@doc[j] <= @shell[i] and @shell[i] < @doc[j] + !doc[j])
            and not for any k in (1..#shell_data) : (
                @shell_data[k] == @shell[i]
                and not $py_danger in (@shell_data[k]..@shell_data[k] + !shell_data[k] - 1)
            )
        ) or
        for any of ($subst, $powershell, $powershell_reverse) : (
            for any i in (1..#) : (
                not for any j in (1..#doc) : (@doc[j] <= @[i] and @[i] < @doc[j] + !doc[j])
            )
        ) or
        for any i in (1..#py) : (
            $py_fetch in (@py[i]..@py[i] + !py[i] - 1) and
            $py_exec in (@py[i]..@py[i] + !py[i] - 1) and
            not for any j in (1..#doc) : (@doc[j] <= @py[i] and @py[i] < @doc[j] + !doc[j])
        )
}
