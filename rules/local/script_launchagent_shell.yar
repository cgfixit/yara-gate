rule script_launchagent_shell {
    meta:
        id = "script_launchagent_shell"
        author = "yara-gate"
        description = "LaunchAgent program arguments that run a shell or scripting interpreter with a downloader"
        intent = "Advisory on a plist whose ProgramArguments run a shell, python, perl, ruby, osascript, curl, or env with curl, wget, osascript, base64, or urlopen"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1543/001/"
    strings:
        $plist = "<plist" nocase ascii wide
        $args = /<key>ProgramArguments<\/key>[\s\S]{0,500}<string>(\/bin\/(bash|sh|zsh)|\/usr\/bin\/(python3?|perl|ruby|osascript|curl|env))<\/string>/ nocase ascii wide
        $net = /\b(curl|wget|osascript|base64|urlopen)\b/ nocase ascii wide
    condition:
        $plist and $args and $net
}
