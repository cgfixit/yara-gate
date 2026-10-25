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
        $encoded = /[ \t]-(e|ec|enc|encodedcommand)[ \t]+["']?[A-Za-z0-9+\/]{40,512}={0,2}(["' \t\r\n]|$)/ nocase ascii wide
        $hidden = /[ \t]-w(indowstyle)?[ \t]+(hidden|h)\b/ nocase ascii wide
        $bypass = /[ \t]-(ep|executionpolicy)[ \t]+(bypass|unrestricted)\b/ nocase ascii wide
    condition:
        for any i in (1..#command) : (
            $encoded in (@command[i]..@command[i] + !command[i] - 1) and
            ($hidden in (@command[i]..@command[i] + !command[i] - 1) or
             $bypass in (@command[i]..@command[i] + !command[i] - 1))
        )
}
