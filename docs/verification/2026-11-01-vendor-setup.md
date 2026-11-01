# First-run vendor setup (2026-11-01)

Base revision `b663dda` (`main`). Linux container, Python 3.12.3, YARA-X 1.22.1. Disposable rules roots under a scratch directory; `~/YaraGate` was not used. The census corpus was the 320-file benign corpus from PR #142 (310 files on `main` plus 10 workflow and Keras files); those 10 files matched no vendor rule.

## First-run setup and the vendor false-positive census

`yara-gate setup` is the first-run download of the locked packs. It runs the same `install_packs` path as `rules install` (sha256 per pack, compile before swap, old tree and lock kept on failure), without the `--allow-network` flag: running it is the consent. It skips the network when the lock's `installed_vendor_files` are all present, and `--force` downloads again. A scan never downloads. When stderr is a terminal and the packs are not installed, a scan prints one `note:` line on stderr.

FACT. Against a scratch rules root copied from the checkout:

| Step | Outcome |
| --- | --- |
| `scan` on a pseudo-terminal before `setup` | the `note:` line, then the normal result, exit 0 |
| the same `scan` piped | no `note:` line |
| `setup` | three packs, sha256 matched, `compiled_rules=13631 skipped_rules=13`, exit 0, 32 s |
| `setup` again with the proxy pointed at a closed port | `already set up`, exit 0 |
| `scan` after setup with the proxy closed | normal verdict; no network |
| one recorded vendor file deleted | `scan` exits 2 `installed vendor rules missing`; `setup` reinstalls it |
| `setup --force` with a wrong sha256 in the lock | exit 2 `incomplete: ValueError`; 1,810 vendor files and the lock unchanged |

FACT. Census: the 320-file benign corpus was scanned under each policy with bundled rules only and with the locked vendor packs installed. Two vendor rules matched, both from signature-base `gen_url_persitence.yar`. Vendor rules have no `verdict_on_match`, so the scanner records every vendor match as `block`.

| Rule | Its own metadata | Files | Verdict change |
| --- | --- | --- | --- |
| `Methodology_Contains_Shortcut_OtherURIhandlers` | "Noisy rule", `score = 35` | `Mail the team.url` (`mailto:`), `Spacewar.url` (`steam://`) | clean to block under every policy |
| `Methodology_Suspicious_Shortcut_Local_URL` | `score = 50` | `Handbook.url` (a local `file:` URL, already a tagged advisory collision) | advisory to block under the default policy |

ASSESSMENT. With the packs installed, 2 of 320 ordinary files (0.6%) are newly blocked. The corpus is text, documents, and shortcuts, and it has no benign PE, ELF, or Mach-O files, where most vendor rules apply. So this census bounds the text-side risk only. AGENTS.md says metadata does not implement policy, so the scanner deliberately does not map signature-base `score` to a severity. Downgrading or skipping a vendor rule would need a reviewed, committed list; that is not built here.
