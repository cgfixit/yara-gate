# Locked dependency refresh — October 30, 2026

Base: `44de331`. Only the locked versions change. The application, shipped rules,
dependency bounds, and Python requirement remain as on main.

| Package | Before | After |
| --- | --- | --- |
| yara-x | 1.22.0 | 1.22.1 |
| pydantic | 2.14.1 | 2.14.2 |
| pydantic-core | 2.50.1 | 2.50.2 |
| platformdirs | 4.13.5 | 4.14.0 |
| mypy (dev) | 2.4.0 | 2.4.1 |
| pytest (dev) | 9.1.1 | 9.2.0 |
| ruff (dev) | 0.17.2 | 0.17.3 |

`uv tree --outdated --depth 1` lists no remaining newer version after the lock
change. This record does not claim a vulnerability audit or a performance change.

## Direct runtime verification

Python 3.12, Linux, frozen locked environment, disposable homes and rules:

- `uv sync --frozen --group dev` and `uv pip check` pass.
- `uv run python docs/research/probe_rule_coverage.py --verify` reports no failures.
- `uv run yara-gate selftest` prints `SELFTEST PASS` on YARA-X 1.22.1.
- `measure_precision.py --fail-over` exits 0 over the 267-file corpus.
- `check_rules_lock.py`, `check_text_controls.py`, Ruff, and `mypy --strict src` pass.
- The 253-test suite passes (1 skipped).

Ubuntu, macOS, and Windows scan-only coverage runs in hosted CI for this draft.
No vendor packs were downloaded, no targets were executed, and no operator gate
home was used.
