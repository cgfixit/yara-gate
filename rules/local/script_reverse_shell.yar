rule script_reverse_shell {
    meta:
        author = "yara-gate"
        description = "Shell, netcat, socat, Python, or PowerShell one-liner that connects out and hands the connection a shell"
        intent = "Advisory on the reverse-shell shapes in a dropped script, pasted command, or synced note, not on a mention of /dev/tcp or a socket"
        severity = "advisory"
        verdict_on_match = "advisory"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        technique = "T1059.004"
    strings:
        // bash -i >& /dev/tcp/host/port 0>&1, and exec N<>/dev/tcp/host/port.
        $devtcp = /\b(ba|z)?sh[ \t]+-i\b[^\r\n]{0,40}[<>]&?[ \t]*\/dev\/(tcp|udp)\/[A-Za-z0-9.:\[\]-]{1,253}\/[0-9]{1,5}\b/ nocase ascii wide
        $devtcp_exec = /\bexec[ \t]+[0-9]{1,2}[ \t]*<>[ \t]*\/dev\/(tcp|udp)\/[A-Za-z0-9.:\[\]-]{1,253}\/[0-9]{1,5}\b/ nocase ascii wide
        // nc -e /bin/sh host port, ncat --exec, and the mkfifo relay.
        $nc_exec = /\b(nc|ncat|netcat)(\.exe)?[ \t]+[^\r\n;|]{0,80}(-e|-c|--exec|--sh-exec)[ \t]+["']?(\/bin\/|\/usr\/bin\/)?((ba|z|da)?sh|cmd(\.exe)?|powershell(\.exe)?)\b/ nocase ascii wide
        $fifo = /\bmkfifo\b[^\r\n]{0,160}\b(ba|z)?sh[ \t]+-i\b[^\r\n]{0,160}\b(nc|ncat|netcat|telnet|openssl[ \t]+s_client)\b/ nocase ascii wide
        $socat = /\bsocat\b[^\r\n]{0,160}\bexec:["']?(\/bin\/)?(ba|z)?sh\b[^\r\n]{0,160}\btcp[46]?(-connect)?:/ nocase ascii wide
        $socat_reverse = /\bsocat\b[^\r\n]{0,160}\btcp[46]?(-connect)?:[^\r\n]{0,160}\bexec:["']?(\/bin\/)?(ba|z)?sh\b/ nocase ascii wide
        // Python: a connected socket whose descriptor is duplicated onto stdin or used for a pty.
        $py = /\bsocket\.socket\([\s\S]{0,400}\b(os\.dup2\([^)]{0,40}fileno\(\)|pty\.spawn\()/ ascii wide
        // PowerShell: a TCPClient stream read into Invoke-Expression.
        $ps = /\bNet\.Sockets\.TCPClient\([\s\S]{0,1024}\.GetStream\(\)[\s\S]{0,1024}\b(iex|Invoke-Expression)\b/ nocase ascii wide
    condition:
        any of them
}
