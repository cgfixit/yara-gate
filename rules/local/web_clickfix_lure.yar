rule web_clickfix_lure {
    meta:
        author = "yara-gate"
        description = "Verification lure with clipboard write, shell-opening and paste instructions nearby"
        verdict_on_match = "advisory"
        reference = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
    strings:
        $clipboard = /\b(navigator\s*\.\s*clipboard\s*\.\s*writeText\s*\(|document\s*\.\s*execCommand\s*\([ \t]*["']copy["'])/ ascii wide
        $lure = /\b(verify[ \t]+(that[ \t]+)?you[ \t]+are[ \t]+(a[ \t]+)?human|captcha|verification[ \t]+required)\b/ nocase ascii wide
        $run = /\b(win(dows)?[ \t]*(key[ \t]*)?\+[ \t]*r|windows[ \t]+(run|terminal)|open[ \t]+(the[ \t]+)?(terminal|powershell))\b/ nocase ascii wide
        $paste = /\b((ctrl|control)[ \t]*\+[ \t]*v|paste[ \t]+(the[ \t]+)?(command|code))\b/ nocase ascii wide
    condition:
        for any i in (1..#clipboard) : (
            $lure in (@clipboard[i] - 4096..@clipboard[i] + 4096) and
            $run in (@clipboard[i] - 4096..@clipboard[i] + 4096) and
            $paste in (@clipboard[i] - 4096..@clipboard[i] + 4096)
        )
}
