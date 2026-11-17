rule dev_vscode_autorun_task {
    meta:
        author = "yara-gate"
        description = "VS Code task that runs when the folder opens and fetches or decodes a payload, or hides its terminal"
        intent = "Advisory on a tasks.json folderOpen task with a downloader, an inline interpreter, a decoder, or reveal never, the repository lure that runs when a cloned or synced project is opened"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://code.visualstudio.com/docs/editor/tasks#_run-behavior"
        reference_attack = "https://attack.mitre.org/techniques/T1204/002/"
        technique = "T1204.002"
    strings:
        $open = /"runOn"[ \t\r\n]*:[ \t\r\n]*"folderOpen"/ ascii wide
        // The inline-program flag may sit in the task's args array instead of its command line.
        $fetch = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|iwr|irm)\b|\bnode[ \t]+-e\b|\bpython3?[ \t]+-c\b|"(node|python3?)"[^\]}]{0,160}"-[ec]"|\bbase64[ \t]+(-d|--decode)\b|\bpowershell(\.exe)?[^"\r\n]{0,40}[ \t]-e(nc|ncodedcommand)?\b/ nocase ascii wide
        $hidden = /"reveal"[ \t\r\n]*:[ \t\r\n]*"never"/ ascii wide
    condition:
        for any i in (1..#open) : (
            $fetch in (@open[i] - 2048..@open[i] + 2048) or
            $hidden in (@open[i] - 1024..@open[i] + 1024)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of any string this condition places counts as every one of them
        // being near the others, so a flood ahead of a match cannot hide it
        // (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (#open >= 1000000 or #fetch >= 1000000 or #hidden >= 1000000)
            and $open and ($fetch or $hidden)
        )
}
