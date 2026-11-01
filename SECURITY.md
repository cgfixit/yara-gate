# Security

The repository is [cgfixit/yara-gate](https://github.com/cgfixit/yara-gate) and is public. Do not assume an issue, attachment, or Pages artifact is private. Use GitHub's private vulnerability reporting option if it is enabled; otherwise arrange a private reporting channel with the maintainer before sharing sensitive details.

Do not open an issue that contains a malware sample, a matched snippet, or a file from `blocked/`.

The demo listens on `127.0.0.1` only. `setup`, `rules install`, and `rules update` are the only commands that use the network. `setup` downloads only the URLs and sha256 values pinned in `rules.lock`, and running it is the consent; the other two require `--allow-network`. Scans, the demo, and the watcher never download. A failed install or update leaves the previous vendor tree in place.

The separate [Pages demo](docs/pages-demo.md) serves public static files and
curated recordings, with no scanner backend or content-entry controls. It does
not expose the loopback app. Its CSP disallows script connections and forms;
there is no analytics or application storage. GitHub still receives ordinary
hosting requests and logs visitors' IP addresses. Only the four allowlisted build
outputs may be deployed, after review, through the manual `main` workflow.
