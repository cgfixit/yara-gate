# Inline style `all`: linear in the declarations

Date: 2026-11-25. Base: `main` at `d9a0017`. Engine: YARA-X 1.24.0, Python 3.12.3, x86_64
Linux container with 4 cores. Rules: a disposable copy of the shipped `rules/local` (89
rules), no vendor packs. Every input was synthetic and inert, built in memory and scanned
with `scan_bytes`. Every run below is a direct run on this container; nothing here is hosted
CI.

## What was wrong

`_css_declarations` in `src/yara_gate/htmlhidden.py` resolves one inline style the way a
browser does. An `all` declaration without `!important` removes every earlier declaration
except the `!important` ones. It found those by walking every key kept so far, and the
`!important` keys stay kept. So a style of N distinct `!important` declarations followed by
M `all` declarations cost N × M steps, all inside one call that the scan deadline never
looks at. The deadline does not preempt the reader, so the scan ran far past it.

The lead came from a read-only sweep for loops that grow with the input and do not reach
the deadline check. Of the eight shapes it named that were cheap to build, seven finished
inside the deadline on the base at 4 MiB (0.8 to 4.4 s). This one did not.

## Reproduced on the base

`<p style="p0000000:x!important;…;all:y;all:y;…">`, half `!important` declarations and half
`all`, under the default 30 s deadline:

| Input | Base | Changed |
| --- | --- | --- |
| 64 KiB | 0.24 s, clean | 0.09 s, clean |
| 128 KiB | 0.81 s, clean | 0.11 s, clean |
| 256 KiB | 2.90 s, clean | 0.14 s, clean |
| 1.1 MiB | 79.21 s, incomplete `timeout` | 0.43 s, clean |
| 4 MiB | killed after 120 s | 1.42 s, clean |

The base grows about four times per doubling. A profile of the 128 KiB input put 0.85 s of
0.87 s in `_css_declarations` itself.

## The change

The function now keeps `loose`, the keys in `found` that are not `!important`, as it goes.
An `all` without `!important` deletes exactly those keys. An `all` with `!important` clears
`found` as before. Each key enters `loose` once per declaration, so the cost is linear. What
the function returns is unchanged, including the order of its keys.

## Checks

- A differential fuzz of the base and changed functions: 600,000 random styles (two seeds),
  built from `all` in several spellings, the shorthands in `_CSS_SHORTHANDS` and their
  longhands, `!important` in three spellings, escapes, empty and malformed declarations.
  Every result was identical, key order included.
- Every `style` attribute in the HTML, XHTML, and SVG files under `/usr`, `/opt`, and the
  locked virtual environment (11,881 files, 217,131 attributes) gave identical results.
- `docs/research/probe_html_hidden_browser.py` against Chromium 158.0.8127.36: the 447
  directed documents and 3,000 generated ones (seed 7) gave the same counts in every category
  on the base and on the change. That run rendered with scripting off (`ORACLE_JS` unset),
  so each set showed one unsound marker, a `noscript` inside a `display:none` element. With
  scripting on, which the reader assumes, both sets have none; see the
  [`noscript` oracle record](2026-11-25-html-hidden-noscript-oracle.md).
- `check_worst_case_timing.py --case html-style-all.html`: killed at the watchdog on the
  base, 1.28 s and clean on the change. The full run passed all 106 inputs; the slowest took
  5.5 s.
- `probe_rule_coverage.py --verify` passed. `yara-gate conform`: 96 fixtures, 288 checks,
  0 changed verdicts, 0 changed findings. Ruff, format, and `mypy --strict src scripts`
  passed.

Not run: the hosted pytest and selftest suites, left to CI. Nothing here measures a
production false-positive rate.
