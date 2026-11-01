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

## Reviewed vendor overrides, the untracked inventory, and the sha256 message

`rules/vendor-overrides.json` is a committed list of reviewed decisions. It is packaged in the wheel as `bundled_rules/vendor-overrides.json`. A YARA match whose rule declares no `verdict_on_match` takes the action the list names (`skip`, `note`, or `advisory`), and it is `block` when the list does not name it. The list starts with the two rules from the census: `Methodology_Contains_Shortcut_OtherURIhandlers` is skipped and `Methodology_Suspicious_Shortcut_Local_URL` is advisory. `lint_rules.py` parses it and rejects a local rule name. With vendor files loaded, the list's bytes enter the ruleset digest.

FACT. Census repeated with the overrides on the locked packs: under the default, `agent-ingest`, and `agent-document` policies, all 320 files get the same verdict as with the shipped rules alone. The one remaining vendor match is the advisory `Methodology_Suspicious_Shortcut_Local_URL` on `Handbook.url`, which was already a tagged advisory.

FACT. `check_added_rules.py` adds three inert stand-in vendor rules: the skipped one gives no finding, the lowered one is advisory, and an unlisted one is block. With the list removed, the first two report `block`, so the check fails. With an invalid action in the list, every scan is incomplete with `invalid vendor-overrides.json`, and `lint_rules.py` fails.

FACT. `vendor.installed.json` beside `vendor/` now holds the installed-file inventory; `.gitignore` lists it. After `setup` on a copy of the checkout lock, the lock's sha256 was unchanged (`e0edf088…`) and the inventory held 1,809 names. Removing the whole `vendor/` still exits 2 with `installed vendor rules missing`. A legacy lock that carries `installed_vendor_files`, with one listed file deleted, still exits 2; `setup` then reinstalls, moves the list to `vendor.installed.json`, and drops it from the lock. Changing the override list changes the vendor root's ruleset digest.

FACT. A wrong sha256 in the lock now prints `incomplete: sha256 mismatch for elastic` from both `setup --force` and `rules install --allow-network`, exit 2. The exception is `RuleIntegrityError`, a `RuleDownloadError` that is also a `ValueError`, as the existing test expects.

FACT. `uv run pytest -q tests/test_rules.py tests/test_cli.py`: 65 passed, 1 skipped. Run because these changes move lock and inventory behavior those tests pin.
