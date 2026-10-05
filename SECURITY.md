# Security

yara-gate is a local tree. It does not have a GitHub repository yet, so GitHub private vulnerability reporting is not turned on.

When this tree is published, enable private vulnerability reporting in the repository settings. Do not open a public issue that contains a malware sample, a matched snippet, or a file from `blocked/`.

The demo listens on `127.0.0.1` only. `rules update` is the only command that uses the network, and only after `--allow-network`.
