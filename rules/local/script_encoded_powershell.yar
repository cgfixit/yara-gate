rule script_encoded_powershell {
    meta:
        author = "yara-gate"
        description = "Encoded PowerShell launch with hidden-window or execution-policy bypass or unrestricted flags on the same command line"
        intent = "Advisory on encoded PowerShell with a hidden window or a bypass"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe"
        reference_campaign = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/"
        technique = "T1059.001"
    strings:
        $command = /\b(powershell|pwsh)(\.exe)?["']?[ \t]+[^\r\n;|&]{1,1024}/ nocase ascii wide
        // powershell.exe and pwsh take any prefix of a parameter name that is long enough to be
        // unambiguous (-e, -en, -enco; -w, -win; -ex, -exec), with - or / in front. The window
        // style may be any prefix of Hidden (h, hid) or its number, 1. The encoded value is read
        // from its first 40 characters, so a command of any length counts.
        $encoded = /[ \t][-\/](ec|e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?)[ \t]+["']?[A-Za-z0-9+\/]{40}/ nocase ascii wide
        $hidden = /[ \t][-\/]w(i(n(d(o(w(s(t(y(l(e)?)?)?)?)?)?)?)?)?)?[ \t]+["']?(h(i(d(d(e(n)?)?)?)?)?|1)\b/ nocase ascii wide
        $bypass = /[ \t][-\/](ep|ex(e(c(u(t(i(o(n(p(o(l(i(c(y)?)?)?)?)?)?)?)?)?)?)?)?)?)[ \t]+["']?(bypass|unrestricted)\b/ nocase ascii wide
        // The parser also accepts a doubled dash, an en dash, an em dash, or a horizontal bar.
        // These are separate strings so the common spellings above keep a three-byte literal
        // to search for; one pattern for every prefix left the engine with the letter e alone.
        $encoded_dash = /[ \t](--|\xe2\x80[\x93-\x95])(ec|e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?)[ \t]+["']?[A-Za-z0-9+\/]{40}/ nocase ascii wide
        $hidden_dash = /[ \t](--|\xe2\x80[\x93-\x95])w(i(n(d(o(w(s(t(y(l(e)?)?)?)?)?)?)?)?)?)?[ \t]+["']?(h(i(d(d(e(n)?)?)?)?)?|1)\b/ nocase ascii wide
        $bypass_dash = /[ \t](--|\xe2\x80[\x93-\x95])(ep|ex(e(c(u(t(i(o(n(p(o(l(i(c(y)?)?)?)?)?)?)?)?)?)?)?)?)?)[ \t]+["']?(bypass|unrestricted)\b/ nocase ascii wide
    condition:
        for any i in (1..#command) : (
            any of ($encoded*) in (@command[i]..@command[i] + !command[i] - 1) and
            any of ($hidden*, $bypass*) in (@command[i]..@command[i] + !command[i] - 1)
        )
}
