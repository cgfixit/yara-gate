rule script_osascript_shell {
    meta:
        id = "script_osascript_shell"
        author = "yara-gate"
        description = "osascript -e running do shell script"
        intent = "Advisory when osascript is asked to run a shell command"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/002/"
    strings:
        $run = /\bosascript\b[^\r\n]{0,80}-e\b[\s\S]{0,200}do shell script/ nocase ascii wide
    condition:
        $run
}
