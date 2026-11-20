# Claude Code skills for yara-gate

Three skills for working on this tree in Claude Code. Each is a slash command under its own
name, and each has a shorter command in [`../commands/`](../commands/) that reads the skill's
file and follows it. [AGENTS.md](../../AGENTS.md) holds the contracts; a skill restates none of
them and loses to it wherever the two differ.

| Skill | Short command | Starts | Use it for |
| --- | --- | --- | --- |
| [`yara-gate-optimize`](yara-gate-optimize/SKILL.md) | `/optimize [focus]` | Only when you type it | An improvement pass: prove problems on the base revision, fix the smallest whole thing, hand back draft pull requests with evidence |
| [`yara-gate-dep-sync`](yara-gate-dep-sync/SKILL.md) | `/dep-sync [scope]` | When typed, or when a request is about dependencies | The state of `uv.lock`, the engine, pinned Actions, Dependabot pull requests, and vendor pins; reports before it changes a lock |
| [`yara-gate-detection-research`](yara-gate-detection-research/SKILL.md) | `/detection-research [lead]` | When typed, or when a request is about a detection lead | One lead from primary source to a recorded result: caught, fixed, left open, or declined |

Two of them carry a script that only reads the checkout and writes nothing outside a temporary
directory:

- [`yara-gate-dep-sync/scripts/dep_state.py`](yara-gate-dep-sync/scripts/dep_state.py) prints
  the dependency state and exits 1 when two files that must agree do not.
- [`yara-gate-detection-research/scripts/probe_candidate.py`](yara-gate-detection-research/scripts/probe_candidate.py)
  scans inert candidate files beside a caught control with a disposable copy of the rules.

No skill here declares `allowed-tools`, so none widens what a session may do without asking.

The skills under [`.agents/skills/`](../../.agents/skills/) are the ones other agent runtimes
load. `yara-gate-optimize` is the Claude Code successor to `yara-gate-optimizer` there; the
runtime-verify, invariant-guard, rule-authoring, and demo-evidence skills have no copy here, and
a Claude session can read them as documents.
