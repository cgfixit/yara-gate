rule web_clickfix_lure {
    meta:
        author = "yara-gate"
        description = "Verification lure with clipboard write, shell- or Explorer-opening and paste instructions nearby"
        intent = "Advisory on a clipboard lure that tells the reader to run a command"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        // clipboard.write() takes a ClipboardItem; writeText() takes a string. Both plant the command.
        $clipboard = /\b(navigator\s*\.\s*clipboard\s*\.\s*write(Text)?\s*\(|document\s*\.\s*execCommand\s*\([ \t]*["']copy["'])/ ascii wide
        $lure = /\b(verify[ \t]+(that[ \t]+)?you[ \t]+are[ \t]+(a[ \t]+)?human|captcha|verification[ \t]+required)\b/ nocase ascii wide
        // Win+R opens Run, Win+X opens the PowerShell menu, and FileFix pastes into the Explorer address bar.
        $run = /\b(win(dows)?[ \t]*(key[ \t]*)?\+[ \t]*[rx]|windows[ \t]+(run|terminal)|open[ \t]+(the[ \t]+)?(terminal|powershell|command[ \t]+prompt|run[ \t]+dialog)|file[ \t]+explorer|address[ \t]+bar)\b/ nocase ascii wide
        $paste = /\b((ctrl|control)[ \t]*\+[ \t]*v|paste[ \t]+(the[ \t]+)?(command|code))\b/ nocase ascii wide
    condition:
        for any i in (1..#clipboard) : (
            $lure in (@clipboard[i] - 4096..@clipboard[i] + 4096) and
            $run in (@clipboard[i] - 4096..@clipboard[i] + 4096) and
            $paste in (@clipboard[i] - 4096..@clipboard[i] + 4096)
        )
}
