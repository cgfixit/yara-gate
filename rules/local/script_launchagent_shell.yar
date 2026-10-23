rule script_launchagent_shell {
    meta:
        id = "script_launchagent_shell"
        author = "yara-gate"
        description = "LaunchAgent program arguments that run a shell downloader"
        intent = "Advisory on a plist whose ProgramArguments run a shell with curl, wget, or osascript"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1543/001/"
    strings:
        $plist = "<plist" nocase ascii wide
        $args = /<key>ProgramArguments<\/key>[\s\S]{0,500}<string>\/bin\/(bash|sh|zsh)<\/string>/ nocase ascii wide
        $net = /\b(curl|wget|osascript|base64)\b/ nocase ascii wide
    condition:
        $plist and $args and $net
}
