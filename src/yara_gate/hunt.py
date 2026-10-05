"""Build a candidate rule only after a file in blocked/ is confirmed."""

from pathlib import Path
from typing import Any

from yara_gate.quarantine import GatePaths
from yara_gate.rules import default_rules_dir, project_root
from yara_gate.scanner import MAX_FILE_BYTES


def hunt(
    home: GatePaths,
    sha256: str,
    reason: str,
    scope: Path,
    *,
    rules_dir: Path | None = None,
    benign_dir: Path | None = None,
) -> tuple[Path, list[Path]]:
    if not reason.strip():
        raise ValueError("reason is required")
    slot = home.blocked / sha256
    if not slot.is_dir():
        raise FileNotFoundError(sha256)
    sample = _one_file(slot)
    strings = _distinctive(sample.read_bytes(), benign_dir or _default_benign())
    if not strings:
        raise RuntimeError("no distinctive strings")
    rule_text = _rule(sha256[:12], strings)
    import yara_x

    rules = yara_x.compile(rule_text)
    for benign in _files(benign_dir or _default_benign()):
        if rules.scan(benign.read_bytes()).matching_rules:
            raise RuntimeError("candidate matched the benign corpus")
    if not rules.scan(sample.read_bytes()).matching_rules:
        raise RuntimeError("candidate missed the confirmed file")
    root = rules_dir or default_rules_dir()
    local = root / "local"
    local.mkdir(parents=True, exist_ok=True)
    dest = local / f"hunt_{sha256[:12]}.yar"
    dest.write_text(rule_text, encoding="utf-8")
    hits = [path for path in _files(scope) if _hit(rules, path)]
    return dest, hits


def _one_file(slot: Path) -> Path:
    files = [item for item in slot.iterdir() if item.is_file() and not item.name.startswith(".")]
    if len(files) != 1:
        raise FileNotFoundError(slot.name)
    return files[0]


def _files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    return [
        path for path in sorted(root.rglob("*")) if path.is_file() and not path.name.startswith(".")
    ]


def _default_benign() -> Path:
    return project_root() / "tests" / "fixtures" / "benign"


def _distinctive(data: bytes, benign_dir: Path) -> list[str]:
    blobs = [path.read_bytes() for path in _files(benign_dir)]
    found: list[str] = []
    buf: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            buf.append(chr(byte))
            continue
        if len(buf) > 8:
            found.append("".join(buf))
        buf = []
    if len(buf) > 8:
        found.append("".join(buf))
    unique = sorted(set(found), key=len, reverse=True)
    kept = [item for item in unique if all(item.encode() not in blob for blob in blobs)]
    return kept[:8]


def _rule(sha12: str, strings: list[str]) -> str:
    body = [
        f"rule hunt_{sha12} {{",
        "    meta:",
        '        author = "yara-gate"',
        '        description = "Candidate built from a confirmed file"',
        '        severity = "advisory"',
        '        verdict_on_match = "advisory"',
        '        status = "candidate"',
        '        reference = "operator-confirmed"',
        "    strings:",
    ]
    for index, item in enumerate(strings):
        body.append(f'        $s{index} = "{_escape(item)}" ascii')
    body.extend(["    condition:", "        any of them", "}", ""])
    return "\n".join(body)


def _escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _hit(rules: Any, path: Path) -> bool:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return False
        scan = rules.scan
        return bool(scan(path.read_bytes()).matching_rules)
    except OSError:
        return False
