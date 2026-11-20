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
        // The socket and the dup2 or pty call that starts within 400 bytes after it are two
        // strings paired in the condition, and so are the three parts of the PowerShell shape
        // below. One pattern with [\s\S]{0,400} inside it is split by YARA-X at a gap over 200
        // bytes and paired match by match, which reached the scan deadline on a file of them
        // (docs/verification/2026-11-20-any-byte-gap-timing.md). The ascii and wide copies are
        // separate strings so a UTF-16 part is paired only with UTF-16 parts; a window is the
        // same number of bytes for both, as [\s\S] matches one byte in a wide pattern too.
        $py_socket = /\bsocket\.socket\(/ ascii
        $py_socket_wide = /\bsocket\.socket\(/ wide
        $py_shell = /\b(os\.dup2\([^)]{0,40}fileno\(\)|pty\.spawn\()/ ascii
        $py_shell_wide = /\b(os\.dup2\([^)]{0,40}fileno\(\)|pty\.spawn\()/ wide
        // PowerShell: a TCPClient, GetStream() starting within 1,024 bytes after it, and iex or
        // Invoke-Expression starting within 1,024 bytes after that. The condition starts from
        // GetStream(), 12 bytes (24 wide), and looks back for the 22-byte (44 wide) client.
        $ps_client = /\bNet\.Sockets\.TCPClient\(/ nocase ascii
        $ps_client_wide = /\bNet\.Sockets\.TCPClient\(/ nocase wide
        $ps_stream = /\.GetStream\(\)/ nocase ascii
        $ps_stream_wide = /\.GetStream\(\)/ nocase wide
        $ps_iex = /\b(iex|Invoke-Expression)\b/ nocase ascii
        $ps_iex_wide = /\b(iex|Invoke-Expression)\b/ nocase wide
    condition:
        any of ($devtcp, $devtcp_exec, $fd_shell, $perl, $nc_exec, $fifo, $socat, $socat_reverse)
        or for any i in (1..#py_socket) : (
            $py_shell in (@py_socket[i] + !py_socket[i]..@py_socket[i] + !py_socket[i] + 400)
        )
        or for any i in (1..#py_socket_wide) : (
            $py_shell_wide in (@py_socket_wide[i] + !py_socket_wide[i]..@py_socket_wide[i] + !py_socket_wide[i] + 400)
        )
        or for any i in (1..#ps_stream) : (
            $ps_client in (@ps_stream[i] - 22 - 1024..@ps_stream[i] - 22)
            and $ps_iex in (@ps_stream[i] + 12..@ps_stream[i] + 12 + 1024)
        )
        or for any i in (1..#ps_stream_wide) : (
            $ps_client_wide in (@ps_stream_wide[i] - 44 - 1024..@ps_stream_wide[i] - 44)
            and $ps_iex_wide in (@ps_stream_wide[i] + 24..@ps_stream_wide[i] + 24 + 1024)
        )
        // YARA-X keeps the first 1,000,000 matches of a string and drops the rest without
        // notice. A full list of any string placed above counts as its parts lying in reach of
        // each other, so a flood ahead of a match cannot hide it
        // (docs/verification/2026-11-17-match-cap-rules.md).
        or (
            (#py_socket >= 1000000 or #py_socket_wide >= 1000000 or #py_shell >= 1000000 or #py_shell_wide >= 1000000)
            and ($py_socket or $py_socket_wide) and ($py_shell or $py_shell_wide)
        )
        or (
            (
                #ps_client >= 1000000 or #ps_client_wide >= 1000000 or #ps_stream >= 1000000
                or #ps_stream_wide >= 1000000 or #ps_iex >= 1000000 or #ps_iex_wide >= 1000000
            )
            and ($ps_client or $ps_client_wide) and ($ps_stream or $ps_stream_wide) and ($ps_iex or $ps_iex_wide)
        )
}
