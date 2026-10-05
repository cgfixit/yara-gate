# Security

The private repository is cgfixit/yara-gate. GitHub documents private vulnerability reporting for public repositories, so this private repository does not use that form.

Do not open an issue that contains a malware sample, a matched snippet, or a file from `blocked/`.

The demo listens on `127.0.0.1` only. `rules update` is the only command that uses the network, and only after `--allow-network`.
