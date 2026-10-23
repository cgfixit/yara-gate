rule script_rundll32_mshtml {
    meta:
        author = "yara-gate"
        description = "Rundll32 JavaScript protocol invoking the MSHTML RunHTMLApplication entrypoint"
        intent = "Advisory on rundll32 launching MSHTML"
        verdict_on_match = "advisory"
        severity = "advisory"
        reference = "https://attack.mitre.org/techniques/T1218/011/"
        technique = "T1218.011"
    strings:
        $chain = /\brundll32(\.exe)?["']?[ \t]+javascript:[^\r\n;|&]{0,256}\bmshtml[ \t]*,[ \t]*RunHTMLApplication\b/ nocase ascii wide
    condition:
        $chain
}
