# Security

The private repository is cgfixit/yara-gate. GitHub documents private vulnerability reporting for public repositories, so this private repository does not use that form.

Do not open an issue that contains a malware sample, a matched snippet, or a file from `blocked/`.

The demo listens on `127.0.0.1` only. `setup`, `rules install`, and `rules update` are the only commands that use the network. `setup` downloads only the URLs and sha256 values pinned in `rules.lock`, and running it is the consent; the other two require `--allow-network`. Scans, the demo, and the watcher never download. A failed install or update leaves the previous vendor tree in place.
