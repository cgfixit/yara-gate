rule dev_git_config_exec {
    meta:
        author = "yara-gate"
        description = "Git config whose command-valued key fetches, decodes, or starts an inline interpreter, or whose hooksPath points at a temp, shared, or network folder"
        intent = "Advisory on a .git/config inside a zipped or synced repository that runs a command the next time an agent or IDE runs git status, diff, log, or fetch: core.fsmonitor, core.sshCommand, core.pager, core.editor, core.askPass, a pager.<command> entry, a filter driver's clean, smudge, or process, or a diff driver's textconv. Git LFS and git-crypt filters, the Watchman fsmonitor hook, ssh -i, delta and less pagers, and a repository-relative hooksPath such as Husky's stay clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://git-scm.com/docs/git-config#Documentation/git-config.txt-corefsmonitor"
        reference_hooks = "https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath"
        reference_attack = "https://attack.mitre.org/techniques/T1546/"
        technique = "T1546"
    strings:
        // Each key counts only inside the section that gives it meaning: no line between the
        // header and the key may open another section, so an [alias] after [core] is not read.
        $core = /(^|\n)[ \t]*\[[ \t]*core[ \t]*\][^\r\n]*(\r?\n([ \t]*[^ \t\[\r\n][^\r\n]*)?){0,400}\r?\n[ \t]*(fsmonitor|sshCommand|pager|editor|askPass)[ \t]*=[^\r\n]{0,240}(\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|nc|ncat)\b|\b(sh|bash|zsh|dash)[ \t]+-c\b|\bcmd(\.exe)?[ \t]+\/c\b|\b(powershell|pwsh)(\.exe)?\b[^\r\n]{0,80}[ \t]-(e|enc|EncodedCommand|c|Command)\b|\bpython3?[ \t]+-c\b|\bnode[ \t]+-e\b|\bperl[ \t]+-e\b|\bbase64[ \t]+(-d|--decode)\b|\/dev\/tcp\/|\bmshta\b|\bosascript\b)/ nocase ascii wide
        $pager = /(^|\n)[ \t]*\[[ \t]*pager[ \t]*\][^\r\n]*(\r?\n([ \t]*[^ \t\[\r\n][^\r\n]*)?){0,400}\r?\n[ \t]*[A-Za-z0-9-]{1,64}[ \t]*=[^\r\n]{0,240}(\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|nc|ncat)\b|\b(sh|bash|zsh|dash)[ \t]+-c\b|\bcmd(\.exe)?[ \t]+\/c\b|\b(powershell|pwsh)(\.exe)?\b[^\r\n]{0,80}[ \t]-(e|enc|EncodedCommand|c|Command)\b|\bpython3?[ \t]+-c\b|\bnode[ \t]+-e\b|\bperl[ \t]+-e\b|\bbase64[ \t]+(-d|--decode)\b|\/dev\/tcp\/|\bmshta\b|\bosascript\b)/ nocase ascii wide
        $filter = /(^|\n)[ \t]*\[[ \t]*filter[ \t]+"[^"\r\n]{1,64}"[ \t]*\][^\r\n]*(\r?\n([ \t]*[^ \t\[\r\n][^\r\n]*)?){0,400}\r?\n[ \t]*(clean|smudge|process)[ \t]*=[^\r\n]{0,240}(\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|nc|ncat)\b|\b(sh|bash|zsh|dash)[ \t]+-c\b|\bcmd(\.exe)?[ \t]+\/c\b|\b(powershell|pwsh)(\.exe)?\b[^\r\n]{0,80}[ \t]-(e|enc|EncodedCommand|c|Command)\b|\bpython3?[ \t]+-c\b|\bnode[ \t]+-e\b|\bperl[ \t]+-e\b|\bbase64[ \t]+(-d|--decode)\b|\/dev\/tcp\/|\bmshta\b|\bosascript\b)/ nocase ascii wide
        $diff = /(^|\n)[ \t]*\[[ \t]*diff[ \t]+"[^"\r\n]{1,64}"[ \t]*\][^\r\n]*(\r?\n([ \t]*[^ \t\[\r\n][^\r\n]*)?){0,400}\r?\n[ \t]*textconv[ \t]*=[^\r\n]{0,240}(\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|nc|ncat)\b|\b(sh|bash|zsh|dash)[ \t]+-c\b|\bcmd(\.exe)?[ \t]+\/c\b|\b(powershell|pwsh)(\.exe)?\b[^\r\n]{0,80}[ \t]-(e|enc|EncodedCommand|c|Command)\b|\bpython3?[ \t]+-c\b|\bnode[ \t]+-e\b|\bperl[ \t]+-e\b|\bbase64[ \t]+(-d|--decode)\b|\/dev\/tcp\/|\bmshta\b|\bosascript\b)/ nocase ascii wide
        // Hooks kept outside the repository, where another process can write them. Git escapes
        // a backslash in a value, so a UNC path is stored with each one doubled.
        $hooks = /(^|\n)[ \t]*\[[ \t]*core[ \t]*\][^\r\n]*(\r?\n([ \t]*[^ \t\[\r\n][^\r\n]*)?){0,400}\r?\n[ \t]*hooksPath[ \t]*=[ \t]*["']?(\/tmp\/|\/var\/tmp\/|\/dev\/shm\/|\/Users\/Shared\/|~\/Downloads\/|\$TMPDIR\b|%(TEMP|TMP)%|\$env:(TEMP|TMP)\b|[A-Za-z]:[\\\/](Windows[\\\/]Temp|Users[\\\/]Public)\b|(\\\\){1,2}[^\\\r\n]+\\|\/\/[^\/\r\n]+\/)/ nocase ascii wide
    condition:
        yara_gate_text and any of them
}

rule dev_devcontainer_lifecycle {
    meta:
        author = "yara-gate"
        description = "Dev container lifecycle command that runs a downloader or inline interpreter on the host, or decodes or reverse-connects inside the container"
        intent = "Advisory on a devcontainer.json in a cloned or synced repository. initializeCommand runs on the host before the container exists, so a downloader, decoder, inline interpreter, or reverse shell there is flagged. onCreateCommand, updateContentCommand, postCreateCommand, postStartCommand, and postAttachCommand run in the container, where installers are ordinary, so only decoders, encoded PowerShell, /dev/tcp, and inline Python or Node that reach the network or exec are flagged. npm ci, pip install, a repository setup script, and a curl installer piped to sh inside the container stay clean here (script_download_execute still reports the pipe)"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://containers.dev/implementors/json_reference/#lifecycle-scripts"
        reference_attack = "https://attack.mitre.org/techniques/T1204/"
        technique = "T1204"
    strings:
        // An indicator counts only inside a JSON string of the key's own value (a string, or one
        // inside its array or object, which may span lines; escaped quotes stay inside), so a later
        // property is not read.
        $host_line = /"initializeCommand"[ \t\r\n]*:[ \t\r\n]*("([^"\\\r\n]|\\.){0,400}|[\[{][^\]}]{0,1200}"([^"\\\r\n]|\\.){0,400})(\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|DownloadString|nc|ncat|certutil|bitsadmin)\b|\b(sh|bash|zsh)[ \t]+-c\b|\bcmd(\.exe)?[ \t]+\/c\b|\b(powershell|pwsh)(\.exe)?\b|\bpython3?[ \t]+-c\b|\bnode[ \t]+-e\b|\bbase64[ \t]+(-d|--decode)\b|\/dev\/tcp\/|\bmshta\b|\bosascript\b)/ nocase ascii wide
        $host_list = /"initializeCommand"[ \t\r\n]*:[ \t\r\n]*[\[{][^\]}]{0,600}"(curl|wget|nc|ncat|certutil|bitsadmin|powershell|pwsh|powershell\.exe|mshta|osascript|python3?|node)"/ nocase ascii wide
        $box = /"(onCreateCommand|updateContentCommand|postCreateCommand|postStartCommand|postAttachCommand)"[ \t\r\n]*:[ \t\r\n]*("([^"\\\r\n]|\\.){0,400}|[\[{][^\]}]{0,1200}"([^"\\\r\n]|\\.){0,400})(\bbase64[ \t]+(-d|--decode)\b|\/dev\/tcp\/|\b(powershell|pwsh)(\.exe)?\b([^"\\\r\n]|\\.){0,80}[ \t]-(e|enc|EncodedCommand)\b|\bpython3?[ \t]+-c\b([^"\\\r\n]|\\.){0,160}\b(urllib|socket|b64decode|exec\(|subprocess)|\bnode[ \t]+-e\b([^"\\\r\n]|\\.){0,160}\b(child_process|https?\.get|eval\())/ nocase ascii wide
    condition:
        (yara_gate_name == "devcontainer.json" or yara_gate_name == ".devcontainer.json") and any of them
}

rule dev_envrc_exec {
    meta:
        author = "yara-gate"
        description = "direnv .envrc that downloads, decodes, or opens a network shell"
        intent = "Advisory on an .envrc in a cloned or synced project: direnv runs it as a shell script on entering the folder once allowed, and some setups allow it automatically. A downloader, a base64 or openssl decode, /dev/tcp, or inline Python that reaches the network or execs is flagged. use flake, layout, dotenv, PATH_add, source_url with its pinned hash, and eval of pyenv or lorri output stay clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://direnv.net/man/direnv-stdlib.1.html"
        reference_attack = "https://attack.mitre.org/techniques/T1546/004/"
        technique = "T1546.004"
    strings:
        $fetch = /(^|[\r\n;&|(`$ \t])(curl|wget|nc|ncat|Invoke-WebRequest|Invoke-RestMethod)[ \t]/ ascii wide
        $decode = /\bbase64[ \t]+(-d|-D|--decode)\b|\bopenssl[ \t]+(enc|base64)\b[^\r\n]{0,80}[ \t]-d\b/ ascii wide
        $tcp = "/dev/tcp/" ascii wide
        $inline = /\bpython3?[ \t]+-c\b[^\r\n]{0,160}\b(urllib|socket|b64decode|exec\(|subprocess)|\bosascript[ \t]+-e\b/ ascii wide
    condition:
        yara_gate_name == ".envrc" and any of them
}
