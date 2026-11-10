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
        // bash -i >& /dev/tcp/host/port 0>&1, the login-shell form bash -l > /dev/tcp/host/port,
        // and exec N<>/dev/tcp/host/port with a descriptor of up to three digits (exec 196<>).
        $devtcp = /\b(ba|z)?sh[ \t]+-[il]\b[^\r\n]{0,40}[<>]&?[ \t]*\/dev\/(tcp|udp)\/[A-Za-z0-9.:\[\]-]{1,253}\/[0-9]{1,5}\b/ nocase ascii wide
        $devtcp_exec = /\bexec[ \t]+[0-9]{1,3}[ \t]*<>[ \t]*\/dev\/(tcp|udp)\/[A-Za-z0-9.:\[\]-]{1,253}\/[0-9]{1,5}\b/ nocase ascii wide
        // A shell whose stdin, stdout, and stderr are all one numbered descriptor: the socket in
        // the PHP fsockopen and Ruby TCPSocket one-liners (sh -i <&3 >&3 2>&3, or %d from
        // sprintf) and in bash's sh <&196 >&196 2>&196. The shell must be the command, at the
        // start of a line or after a space, quote, slash, or separator: sh ./run.sh <&3 >&3 2>&3
        // and ./run.sh <&3 >&3 2>&3 are ordinary jobs with their output captured.
        $fd_shell = /(^|[\s"'\/;|&(`])(ba|z|da)?sh([ \t]+-i)?[ \t]+<&[ \t]*(%d|[0-9]{1,3})[ \t]+>&[ \t]*(%d|[0-9]{1,3})[ \t]+2>&[ \t]*(%d|[0-9]{1,3})/ ascii wide
        // Perl: the socket duplicated onto STDIN, then exec of a shell.
        $perl = /\bopen[ \t]*\([ \t]*STDIN[ \t]*,[ \t]*["']>&[ \t]*[A-Za-z_][A-Za-z0-9_]{0,31}["'][ \t]*\)[\s\S]{0,160}\bexec[ \t]*\(?[ \t]*["'][^"'\r\n]{0,24}\b(ba|z|da)?sh\b/ ascii wide
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
