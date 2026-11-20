"""Print this checkout's dependency state from its own files. No network, no writes.

    uv run python .claude/skills/yara-gate-dep-sync/scripts/dep_state.py

It reads `pyproject.toml`, `uv.lock`, `.python-version`, the workflows, `dependabot.yml`,
`rules/rules.lock`, and the engine version the living docs name. Newer releases are not its
question: `uv tree --frozen --outdated --depth 1 --group dev` asks the index for those.

Exit 1 when two files that must agree do not; each disagreement is printed under `PROBLEMS`.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

LIVING_DOCS = (
    "AGENTS.md",
    "README.md",
    "user-guide.md",
    "rules/README.md",
    "docs/rules.md",
    "docs/integrations.md",
    "docs/pages-demo.md",
    "docs/research/detection-backlog.md",
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_USES = re.compile(r"uses:\s*([^\s@]+)@(\S+)(?:\s*#\s*(\S+))?")
_SHA = re.compile(r"[0-9a-f]{40}")
_ENGINE = re.compile(r"YARA-X (\d+\.\d+\.\d+)")


def _repo() -> Path:
    for folder in Path(__file__).resolve().parents:
        if (folder / "pyproject.toml").is_file() and (folder / "uv.lock").is_file():
            return folder
    raise SystemExit("no pyproject.toml and uv.lock above this script")


def _normal(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _locked(lock: dict[str, object]) -> dict[str, tuple[str, datetime | None]]:
    """Each locked package's version and the upload time of its earliest file."""
    found: dict[str, tuple[str, datetime | None]] = {}
    packages = lock.get("package", [])
    for package in packages if isinstance(packages, list) else []:
        files = [package.get("sdist") or {}, *package.get("wheels", [])]
        times = [
            datetime.fromisoformat(str(item["upload-time"]).replace("Z", "+00:00"))
            for item in files
            if "upload-time" in item
        ]
        found[_normal(str(package["name"]))] = (
            str(package.get("version", "?")),
            min(times) if times else None,
        )
    return found


def main() -> int:
    repo = _repo()
    problems: list[str] = []
    project = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((repo / "uv.lock").read_text(encoding="utf-8"))
    workflows = sorted((repo / ".github/workflows").glob("*.yml"))
    workflow_text = {path.name: path.read_text(encoding="utf-8") for path in workflows}
    dependabot = (repo / ".github/dependabot.yml").read_text(encoding="utf-8")
    cooldown = re.search(r"default-days:\s*(\d+)", dependabot)
    cooldown_days = int(cooldown[1]) if cooldown else 0
    now = datetime.now(UTC)

    print(f"repository: {repo.name}  project: {project['project']['version']}")

    print("\n== Python ==")
    pinned = (repo / ".python-version").read_text(encoding="utf-8").strip()
    python = {
        ".python-version": pinned,
        "requires-python": str(project["project"]["requires-python"]).lstrip(">=~ "),
        "ruff target-version": str(project["tool"]["ruff"]["target-version"]),
        "mypy python_version": str(project["tool"]["mypy"]["python_version"]),
    }
    for name, text in workflow_text.items():
        for version in sorted(set(re.findall(r'python-version:\s*"?([\d.]+)"?', text))):
            python[f"{name} python-version"] = version
    for where, value in python.items():
        same = value in (pinned, "py" + pinned.replace(".", ""))
        print(f"  {where:42s} {value}{'' if same else '   <-- differs'}")
        if not same:
            problems.append(f"{where} is {value}, .python-version is {pinned}")

    print(f"\n== Direct dependencies (Dependabot cooldown: {cooldown_days} days) ==")
    locked = _locked(lock)
    groups = [("runtime", project["project"]["dependencies"])]
    groups += [(f"group {name}", items) for name, items in project["dependency-groups"].items()]
    for group, requirements in groups:
        for requirement in requirements:
            match = _NAME.match(requirement)
            name = match.group() if match else requirement
            bound = requirement[len(name) :].strip() or "(any)"
            version, uploaded = locked.get(_normal(name), ("", None))
            if not version:
                problems.append(f"{name} is in pyproject.toml and not in uv.lock")
                print(f"  {name:14s} {bound:10s} NOT LOCKED  [{group}]")
                continue
            age = "upload time not recorded"
            if uploaded is not None:
                days = (now - uploaded).days
                young = "  <-- inside the cooldown" if days < cooldown_days else ""
                age = f"uploaded {uploaded:%Y-%m-%d}, {days} days ago{young}"
            print(f"  {name:14s} {bound:10s} locked {version:9s} {age}  [{group}]")
    print(f"  ({len(locked)} packages in uv.lock, transitive ones included)")

    print("\n== Actions and build tools ==")
    actions: dict[tuple[str, str, str], int] = {}
    for text in workflow_text.values():
        for action, ref, comment in _USES.findall(text):
            actions[(action, ref, comment)] = actions.get((action, ref, comment), 0) + 1
    for (action, ref, comment), count in sorted(actions.items()):
        pinned_sha = _SHA.fullmatch(ref) is not None
        print(f"  {action:34s} {ref[:12]:12s} {comment or '(no version comment)':10s} x{count}")
        if not pinned_sha:
            problems.append(f"{action}@{ref} is not pinned to a commit")
    ci = workflow_text.get("ci.yml", "")
    built = set(re.findall(r"actionlint@([0-9a-f]{40})", ci))
    cached = set(re.findall(r"actionlint-([0-9a-f]{40})-", ci))
    print(f"  actionlint built from {sorted(built)}; cache key names {sorted(cached)}")
    if built != cached:
        problems.append("ci.yml builds actionlint at one commit and keys its cache on another")
    ecosystems = re.findall(r"package-ecosystem:\s*(\S+)", dependabot)
    print("  dependabot ecosystems:", ", ".join(ecosystems))

    print("\n== Vendor rule packs (report only; changing a pin needs the owner's say) ==")
    lock_bytes = (repo / "rules/rules.lock").read_bytes()
    for pack in json.loads(lock_bytes)["packs"]:
        print(f"  {pack['name']:18s} pin {str(pack['pin'])[:12]}")
    recorded = (repo / "docs/verification/rules.lock.sha256").read_text(encoding="utf-8").split()[0]
    digest = hashlib.sha256(lock_bytes).hexdigest()
    print(f"  rules.lock sha256 {'matches' if digest == recorded else 'DIFFERS FROM'} its pin")
    if digest != recorded:
        problems.append("rules/rules.lock does not match docs/verification/rules.lock.sha256")

    print("\n== Packaged paths ==")
    include = project["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for source, target in include.items():
        present = (repo / source).exists()
        print(f"  {source:28s} -> {target}{'' if present else '   <-- missing'}")
        if not present:
            problems.append(f"force-include source {source} does not exist")

    engine = locked.get("yara-x", ("?", None))[0]
    print(f"\n== Engine version named in living docs (locked: {engine}) ==")
    for name in LIVING_DOCS:
        path = repo / name
        if not path.is_file():
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for number, line in enumerate(lines, start=1):
            for version in _ENGINE.findall(line):
                note = "" if version == engine else "   <-- not the locked version"
                print(f"  {name}:{number}  YARA-X {version}{note}")
    print("  A line that names another version may be a dated measurement: read it before editing.")

    print("\n== PROBLEMS ==")
    for problem in problems:
        print(f"  {problem}")
    if not problems:
        print("  none")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
