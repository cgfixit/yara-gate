# Security

The repository is [cgfixit/yara-gate](https://github.com/cgfixit/yara-gate) and is public. Do not assume an issue, attachment, or Pages artifact is private. Use GitHub's private vulnerability reporting option if it is enabled; otherwise arrange a private reporting channel with the maintainer before sharing sensitive details.

Do not open an issue that contains a malware sample, a matched snippet, or a file from `blocked/`. Reports under `reports/` carry rule IDs, offsets, hashes, and the scan-time path, never the matched bytes; still read one before attaching it, because only the home-directory prefix is abbreviated.

The demo listens on `127.0.0.1` only. `setup`, `rules install`, and `rules update` are the only commands that use the network. `setup` downloads only the URLs and sha256 values pinned in `rules.lock`, and running it is the consent; the other two require `--allow-network`. A `GITHUB_TOKEN` or `GH_TOKEN` is sent only to `api.github.com` and is dropped on a redirect to another host. Scans, the demo, and the watcher never download, execute a target, or fetch a URL found in it. A failed install or update leaves the previous vendor tree and lock in place.

The separate [Pages demo](docs/pages-demo.md) serves public static files and
curated recordings, with no scanner backend or content-entry controls. It does
not expose the loopback app. Its CSP disallows script connections and forms;
there is no analytics or application storage. GitHub still receives ordinary
hosting requests and logs visitors' IP addresses. Only the four allowlisted build
outputs are deployed, and only from `main`: automatically after a merge once every
check on that commit is green, or by a manual run on `main` through the same gate.
Each deploy re-records the results with the real scanner and stops if any verdict or
finding differs from the reviewed recordings.

The pre-read example captures a bounded buffer and scans those exact bytes. Its
`--bytes` mode returns that buffer on success; snapshot mode rewrites the tool
input to a new private, read-only copy. Never treat its exit status as permission
to reopen the original source. The consumer must authorize the source read and
protect its snapshot home; read-only permissions do not isolate a hostile process
running under the same account. See the [handoff and storage contract](docs/integrations.md#a-pre-read-hook-that-fails-closed).
