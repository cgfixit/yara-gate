# Fail-closed fixes: Keras walk, vendor-override packs, setup hint, workbench host — November 2, 2026

Source: `main` at `38e100bbc559e86e570e3361256498d3a0c23420` plus the uncommitted
change on branch `claude/fail-closed-fixes`. Python 3.12.3, YARA-X 1.22.1, 82
bundled rules. All inputs were inert, scanned with disposable rules roots, gate
homes, and `XDG_DATA_HOME`/`XDG_CACHE_HOME` where an installed root mattered.
Vendor behavior used inert stand-ins, plus one census with the real pinned packs
installed into a disposable root (section 2).

## 1. Keras configs: encoding bypasses and a fail-open walk

Baseline, with a config whose layer names `os` (`module: os`), in a `.keras`
archive and as `config.json`:

| Variant (same `json.loads` result where applicable) | Baseline | After |
| --- | --- | --- |
| plain | block | block |
| `"class_name"` escaped key | clean | block |
| UTF-8 BOM prefix | clean | block |
| UTF-16LE | clean | block |
| `"pad": [0] * 200001` ahead of the layers (node cap) | clean | incomplete, `keras config exceeds walk limit` |
| layer nested 70 levels (depth cap) | clean | incomplete, same reason |
| `.h5` with reordered top-level keys | clean | block |
| `.h5` with `{ "class_name"` (space) | clean | block |
| `{"symbols":[{"class_name":"Popen","module":"subprocess"}]}` as `index.json` | block | clean |

`.json` configs are now decoded with `json.detect_encoding`, as `json.loads`
does for bytes, and parsed when they contain `"class_name"` or a `\u` escape.
Only a config with `class_name` at its top level is walked, as `load_model`
requires. `.h5` candidates open with any top-level key Keras writes, and nested
objects inside a decoded config are skipped. Reaching the node or depth cap in a
Keras config with nothing found returns an incomplete reason through the
heuristic error channel, so the file is held instead of passing.

Benign size and timing checks (one run each): a 2.4 MB annotation file with
300,000+ nodes and `class_name` keys (no top-level `class_name`), a 2.8 MB JSON
file full of `\u` escapes, and a 3,000-layer Dense config all stayed clean, with
times within 0.2 s of the baseline.

## 2. Vendor overrides ignored their `pack`

`rules/vendor-overrides.json` entries name a pack, but the scanner keyed them by
rule name alone, so an entry for signature-base also skipped or lowered a
same-named rule from any other pack, or a local rule lacking `verdict_on_match`.
Overrides are now keyed by (pack directory, rule). The scanner maps each
compiled namespace (`gate_<index>`) to its `vendor/<pack>/` directory on the
compile, cache, and memo paths; a rule outside `vendor/` has no pack and always
blocks. `yara-forge-core` installs as `vendor/yara-forge`. Enforcement can only
narrow where an override applies, so any mismatch fails toward block.

Inert stand-ins under `vendor/signature-base/` and `vendor/elastic/`, in two
processes sharing one compiled cache:

| Token | Cold compile | Cached compile |
| --- | --- | --- |
| signature-base rule with `skip` | clean | clean |
| signature-base rule with `advisory` | advisory | advisory |
| same name as the skipped rule, from `vendor/elastic/` | block | block |

On the baseline the elastic match was silenced (`got []`).

**Real pinned packs.** To check that pack scoping adds no false positives,
`yara-gate setup --rules <scratch root>` downloaded the three locked packs into a
disposable root (scratch `XDG_DATA_HOME`/`XDG_CACHE_HOME`; nothing under the
repository or `~/YaraGate`): sha256 matched, `compiled_rules=13631
skipped_rules=13`, the same counts as the November 1 census. No rule name is
defined in more than one pack (by a `rule <name>` scan: yara-forge 5,141,
signature-base 5,991, elastic 3,069), and both override names exist only in
`vendor/signature-base/`. The 320-file benign corpus from `measure_precision.py`
was then scanned under all three policies (960 scans) with `main`'s name-only
matching and with this branch: verdicts and findings were identical. The only
vendor finding was the documented advisory `Methodology_Suspicious_Shortcut_Local_URL`
on `Handbook.url`; the `mailto:` and `steam://` shortcuts stayed clean, and the
other non-clean files were the four tagged Windows collisions. No scan was
incomplete. A future pin that reuses an overridden name in another pack would
block until a reviewed entry names that pack. `lint_rules.py` now
fails when an entry names a pack that `rules.lock` does not install; with
`signature-bse` substituted it exited 1 with
`Methodology_Contains_Shortcut_OtherURIhandlers names a pack not in rules.lock`.

## 3. The setup hint was missing on a fresh installed copy

With `XDG_DATA_HOME` pointing at an empty installed root (no `rules.lock` yet),
`yara-gate scan` on a terminal (`script -qec …`) scanned clean with the bundled
overlay and printed no hint, although `setup` would download from the packaged
lock there. `_setup_hint` now reads the same lock `setup` uses
(`lock_for_install`). After the change the terminal run printed
`note: vendor packs not installed; run 'yara-gate setup' once`; the same command
piped printed only the result line.

## 4. The workbench blamed the input when opened as localhost

`yara-gate demo` accepts scans only with `Host: 127.0.0.1:<port>` (DNS-rebinding
defense). Opened as `http://localhost:<port>/`, the page loaded but every scan
showed `Scan rejected: rejected` and "Correct the input and try again". The page
now detects a non-`127.0.0.1` host, keeps the scan buttons disabled, and says to
open `http://127.0.0.1:<port>/`; the notice survives a policy or input change.
The server's checks are unchanged.

Headless Chromium 153.0.8010.12 (Playwright) against an owned
`yara-gate demo --port 0 --rules <disposable>` restarted after the code change:
at `127.0.0.1`, the five samples under all three policies, an HTML-encoded paste,
and an empty submission behaved as before (82 rules); at `localhost`, the notice
and disabled buttons appeared with no console messages. This is not Computer Use.

## Checks

New fixtures in `check_added_rules.py`: `escaped-key.json`, `bom-config.json`,
`utf16-config.json`, `reordered.h5`, `api-index.json`, and the cross-pack override.
With the `src/` change stashed, all six fail; with it, `added-rule checks passed
(90 plus 4 vendor-override cases)`.

```sh
uv run ruff check . && uv run ruff format --check . && uv run mypy --strict src
uv run python docs/verification/lint_rules.py        # 82 rules; vendor overrides (2)
uv run python docs/verification/check_rule_pairs.py  # 109 rules
uv run python docs/verification/check_scan_only.py   # 7 cases, linux
uv run python docs/verification/check_intake.py      # passed
uv run python docs/verification/measure_precision.py --fail-over   # exit 0
uv run python docs/research/probe_rule_coverage.py --verify        # passed
uv run pytest -q tests/test_heuristics.py tests/test_rules.py tests/test_scanner.py \
  tests/test_policies.py -k "not wheel"                            # 265 passed
uv run pytest -q tests/test_demo.py <six invariant-guard tests>    # 16 passed
```

Not verified here: vendor-pack accuracy beyond that benign census, Keras itself
loading the variant files (not installed; the claim rests on its use of
`json.loads`), the wheel-install test, Windows and macOS, and hosted CI.
