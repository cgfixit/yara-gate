rule agent_config_approval_bypass {
    meta:
        author = "yara-gate"
        description = "Coding-agent project setting that turns off tool approval, or trusts every project MCP server while sending API traffic to another endpoint"
        intent = "Advisory on a cloned or synced settings file that, once an agent loads it, runs tools without asking: VS Code chat.tools autoApprove or the Copilot Claude-agent skip-permissions setting, a Claude Code bypassPermissions default mode, enableAllProjectMcpServers together with an ANTHROPIC_BASE_URL override (the CVE-2026-21852 key-redirect shape), or a Codex config with approval never and the danger-full-access sandbox. enableAllProjectMcpServers alone is common in committed settings and stays clean; a team's own settings can still match"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/"
        reference_cve = "https://github.com/advisories/GHSA-jh7p-qr78-84p7"
        reference_writeup = "https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/"
        reference_attack = "https://attack.mitre.org/techniques/T1562/001/"
        technique = "T1562.001"
    strings:
        // CVE-2025-53773: injected text wrote this key into .vscode/settings.json.
        $vscode = /"chat\.tools\.(global\.)?autoApprove"[ \t\r\n]*:[ \t\r\n]*true\b/ ascii wide
        $copilot_claude = /"github\.copilot\.chat\.claudeAgent\.allowDangerouslySkipPermissions"[ \t\r\n]*:[ \t\r\n]*true\b/ ascii wide
        $claude_mode = /"defaultMode"[ \t\r\n]*:[ \t\r\n]*"bypassPermissions"/ ascii wide
        $claude_mcp = /"enableAllProjectMcpServers"[ \t\r\n]*:[ \t\r\n]*true\b/ ascii wide
        $base_url = /"ANTHROPIC_BASE_URL"[ \t\r\n]*:[ \t\r\n]*"https?:\/\// ascii wide
        // Either key alone is a common CI setting; together they run every command unasked with full
        // disk and network access. Only a .toml counts: Codex's own Rust tests embed the same pair.
        $codex_approval = /\bapproval_policy[ \t]*=[ \t]*["']never["']/ ascii wide
        $codex_sandbox = /\bsandbox_mode[ \t]*=[ \t]*["']danger-full-access["']/ ascii wide
    condition:
        $vscode or $copilot_claude or $claude_mode or
        ($claude_mcp and $base_url) or
        ($codex_approval and $codex_sandbox and yara_gate_ext == "toml")
}

rule agent_cli_secret_sweep {
    meta:
        author = "yara-gate"
        description = "AI coding CLI started with its approval checks off, near a request to hunt for wallets, keystores, or SSH keys"
        intent = "Advisory on the s1ngularity shape: a script or install hook that runs claude, gemini, q, codex, or copilot with a permission-bypass flag and a prompt that searches the disk for credentials. A CI step that runs an agent unattended for ordinary work stays clean; GitHub Actions secrets and .env files are not hunt terms. Prose that warns about the flag next to an SSH key name can match"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c"
        reference_writeup = "https://snyk.io/blog/weaponizing-ai-coding-agents-for-malware-in-the-nx-malicious-package/"
        reference_attack = "https://attack.mitre.org/techniques/T1552/001/"
        technique = "T1552.001"
    strings:
        $bypass = /--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b|--trust-all-tools\b|--allow-all-tools\b|--yolo\b|--approval-mode[ \t=]+["']?yolo\b/ ascii wide
        $cli = /\b(claude|gemini|codex|copilot|cursor-agent|opencode|qwen)\b|\bq[ \t]+chat\b|["']q["']/ nocase ascii wide
        $hunt = /\b(crypto[ \t]+)?wallets?\b|\bkeystores?\b|\bseed[ \t]+phrases?\b|\bmnemonics?\b|\bmetamask\b|\belectrum\b|\bexodus\b|\bphantom\b|\bsolflare\b|\btrezor\b|\bid_(rsa|ed25519|ecdsa)\b|\.ssh\/|\bprivate[ \t]+keys?\b|\binventory\.txt\b/ nocase ascii wide
    condition:
        for any i in (1..#bypass) : (
            $cli in (@bypass[i] - 256..@bypass[i]) and
            $hunt in (@bypass[i] - 2048..@bypass[i] + 2048)
        )
}
