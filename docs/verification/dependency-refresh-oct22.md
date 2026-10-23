# Locked dependency refresh — October 22, 2026

Base: `d0c5a0f2af48288b8f13de3d757e97a338ae587a`. Only the locked versions
change; the application, shipped rules, dependency bounds and Python requirement
remain as on main.

| Package | Before | After |
| --- | --- | --- |
| yara-x | 1.21.0 | 1.22.0 |
| ruff | 0.17.1 | 0.17.2 |
| pycparser | 3.11 | 3.12 |

[YARA-X release notes](https://github.com/VirusTotal/yara-x/releases/tag/v1.22.0)
include compiler/runtime correctness and deserialized-rule validation fixes.
[Ruff release notes](https://github.com/astral-sh/ruff/releases/tag/0.17.2)
include lint correctness fixes. This record does not claim a comprehensive
vulnerability audit or production performance improvement.

## Independent runtime verification

Python 3.12.12, macOS 27.0.1 ARM64, frozen locked environment:

- `uv sync --frozen --group dev` and `uv pip check` pass (36 installed packages).
- `uv run --frozen python docs/research/probe_rule_coverage.py --verify` passes:
  20 compiled local rules, zero skips, 120 library cases, 24 actual CLI operations,
  nine benign observations and three failure paths. This checks the unchanged
  main code against YARA-X 1.22.0, using inert input and disposable homes/rules.
- A direct `pycparser.CParser().parse` probe parses a two-argument C function;
  a cryptography AES-GCM encrypt/decrypt round trip passes with synthetic bytes.
- Ruff lint and formatting checks across the repository, and strict mypy across
  `src`, pass using the updated lock.

Broad pytest, selftest and Ubuntu/macOS coverage run in hosted CI for this draft.
No live vendor packs were downloaded, no targets executed and no operator gate
home used. Platform wheels listed in the lock are not evidence of a native
Windows runtime check. The new local-rule and PDF fixes have independent drafts.
