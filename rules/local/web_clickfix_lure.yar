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
        // "Verify you are human", its contraction (straight or curly apostrophe, or an HTML
        // entity), "prove you are human", "I'm not a robot", "human verification", and the
        // "Verification ID" the pasted command pretends to carry.
        $lure = /\b(verify[ \t]+(that[ \t]+)?you([ \t]+a|'|\xe2\x80\x99|&#39;|&rsquo;)re[ \t]+(a[ \t]+)?human|prove[ \t]+(that[ \t]+)?you[ \t]+are[ \t]+(a[ \t]+)?human|i([ \t]+a|'|\xe2\x80\x99|&#39;|&rsquo;)m[ \t]+not[ \t]+a[ \t]+robot|human[ \t]+verification|captcha|verification[ \t]+(required|id))\b/ nocase ascii wide
        // Win+R opens Run, Win+X opens the PowerShell menu, and FileFix pastes into the Explorer address bar.
        // The macOS lure opens Spotlight with Command+Space and asks for Terminal. A key may sit
        // in its own short inline tag, as in <kbd>Win</kbd> + <kbd>R</kbd>.
        $run = /\b(win(dows)?[ \t]*(key)?([ \t]|<\/?[a-z]{1,6}>){0,6}\+([ \t]|<\/?[a-z]{1,6}>){0,6}[rx]|(cmd|command)([ \t]|<\/?[a-z]{1,6}>){0,6}\+([ \t]|<\/?[a-z]{1,6}>){0,6}space|windows[ \t]+(run|terminal)|open[ \t]+(the[ \t]+)?(terminal|powershell|command[ \t]+prompt|run[ \t]+dialog)|type[ \t]+["']?terminal|file[ \t]+explorer|address[ \t]+bar)\b/ nocase ascii wide
        $paste = /\b((ctrl|control|cmd|command)([ \t]|<\/?[a-z]{1,6}>){0,6}\+([ \t]|<\/?[a-z]{1,6}>){0,6}v|paste[ \t]+(the[ \t]+)?(command|code))\b/ nocase ascii wide
        // The Command key written as its symbol, U+2318. No word boundary can precede it.
        $paste_symbol = /\xe2\x8c\x98([ \t]|<\/?[a-z]{1,6}>){0,6}\+?([ \t]|<\/?[a-z]{1,6}>){0,6}v\b/ nocase ascii
    condition:
        for any i in (1..#clipboard) : (
            $lure in (@clipboard[i] - 4096..@clipboard[i] + 4096) and
            $run in (@clipboard[i] - 4096..@clipboard[i] + 4096) and
            ($paste in (@clipboard[i] - 4096..@clipboard[i] + 4096) or
             $paste_symbol in (@clipboard[i] - 4096..@clipboard[i] + 4096))
        )
}
