"""Load, pin, and promote YARA rules. Network runs only in ``update``."""

import hashlib
import io
import json
import re
import shutil
import tarfile
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

_STATUS = re.compile(r'(?m)^\s*status\s*=\s*"([^"]+)"')
_RULE_NAME = re.compile(r"(?m)^rule\s+([A-Za-z0-9_]+)")
_CACHE_SALT = b"yara-gate-rules-v1"
_ALLOWED_DOWNLOAD_HOSTS = frozenset({"github.com", "codeload.github.com"})


class PackPin(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    url: str
    pin: str
    sha256: str


class RulesLock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packs: list[PackPin]


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_rules_dir() -> Path:
    return project_root() / "rules"


def lock_path(rules_dir: Path | None = None) -> Path:
    return (rules_dir or default_rules_dir()) / "rules.lock"


def load_lock(rules_dir: Path | None = None) -> RulesLock:
    path = lock_path(rules_dir)
    if not path.is_file():
        return RulesLock(packs=[])
    return RulesLock.model_validate(json.loads(path.read_text(encoding="utf-8")))


def save_lock(lock: RulesLock, rules_dir: Path | None = None) -> None:
    path = lock_path(rules_dir)
    path.write_text(lock.model_dump_json(indent=2) + "\n", encoding="utf-8")


def rule_files(rules_dir: Path) -> list[Path]:
    found: list[Path] = []
    for folder in (rules_dir / "local", rules_dir / "vendor"):
        if folder.is_dir():
            found.extend(sorted(folder.rglob("*.yar")))
            found.extend(sorted(folder.rglob("*.yara")))
    if found:
        return found
    found.extend(sorted(rules_dir.glob("*.yar")))
    found.extend(sorted(rules_dir.glob("*.yara")))
    return found


def is_candidate(text: str) -> bool:
    match = _STATUS.search(text)
    return match is not None and match.group(1) == "candidate"


def compile_sources(rules_dir: Path) -> tuple[object | None, list[str], str | None, int, int]:
    """Return compiled rules, skip lines, fatal error, compiled rule count, skipped rule count."""
    try:
        import yara_x
    except ImportError:
        return None, [], "yara-x missing", 0, 0

    files = rule_files(rules_dir)
    if not files:
        return None, [], "no rules compiled", 0, 0
    digest = _source_digest(files)
    cached = _read_cache(rules_dir, digest)
    if cached is not None:
        compiled, skipped = _split_good(files, rules_dir)
        return cached, skipped, None, _count_rules(compiled), _count_skipped(skipped)

    good: list[tuple[Path, str]] = []
    skipped = []
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if is_candidate(text):
            continue
        try:
            _validate_one(yara_x, path, text)
        except yara_x.CompileError as exc:
            skipped.append(f"{path.name}: {exc.__class__.__name__}")
            continue
        good.append((path, text))
    if not good:
        _write_skipped(rules_dir, skipped)
        return None, skipped, "no rules compiled", 0, _count_skipped(skipped)

    compiler = yara_x.Compiler(relaxed_re_syntax=True)
    compiler.define_global("yara_gate_ext", "bin")
    _add_include_dirs(compiler, rules_dir)
    for index, (path, text) in enumerate(good):
        compiler.new_namespace(f"gate_{index}")
        compiler.add_source(text, origin=path.name)
    rules = compiler.build()
    _write_cache(rules_dir, digest, rules)
    _write_skipped(rules_dir, skipped)
    return rules, skipped, None, _count_rules(good), _count_skipped(skipped)


def promote(rule_id: str, rules_dir: Path | None = None) -> Path:
    root = rules_dir or default_rules_dir()
    target = _find_hunt_rule(root, rule_id)
    text = target.read_text(encoding="utf-8")
    if 'status = "candidate"' not in text and 'status = "promoted"' not in text:
        raise ValueError(f"{target.name} is not a hunt rule")
    updated = text.replace('status = "candidate"', 'status = "promoted"', 1)
    updated = re.sub(
        r'verdict_on_match\s*=\s*"(advisory|block)"',
        'verdict_on_match = "block"',
        updated,
        count=1,
    )
    import yara_x

    yara_x.compile(updated)
    target.write_text(updated, encoding="utf-8")
    _clear_cache(root)
    return target


def update_packs(rules_dir: Path | None = None) -> RulesLock:
    """Download pinned packs. Caller must have passed ``--allow-network``."""
    root = rules_dir or default_rules_dir()
    vendor = root / "vendor"
    if vendor.exists():
        for child in vendor.iterdir():
            if child.name == ".gitkeep":
                continue
            if child.is_dir():
                shutil.rmtree(child)
            else:
                child.unlink()
    vendor.mkdir(parents=True, exist_ok=True)
    packs = [
        _fetch_forge(vendor),
        _fetch_git("signature-base", "Neo23x0/signature-base", "yara", vendor),
        _fetch_git("elastic", "elastic/protections-artifacts", "yara", vendor),
    ]
    lock = RulesLock(packs=packs)
    save_lock(lock, root)
    _clear_cache(root)
    return lock


def _fetch_forge(vendor: Path) -> PackPin:
    meta = _json("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest")
    tag = str(meta["tag_name"])
    asset = next(item for item in meta["assets"] if item["name"] == "yara-forge-rules-core.zip")
    url = str(asset["browser_download_url"])
    blob = _bytes(url)
    digest = hashlib.sha256(blob).hexdigest()
    dest = vendor / "yara-forge"
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.endswith((".yar", ".yara")):
                continue
            target = dest / Path(info.filename).name
            target.write_bytes(archive.read(info))
    return PackPin(name="yara-forge-core", url=url, pin=tag, sha256=digest)


def _fetch_git(name: str, repo: str, subpath: str, vendor: Path) -> PackPin:
    description = _json(f"https://api.github.com/repos/{repo}")
    branch = str(description["default_branch"])
    commit = _json(f"https://api.github.com/repos/{repo}/commits/{branch}")
    sha = str(commit["sha"])
    url = f"https://codeload.github.com/{repo}/tar.gz/{sha}"
    blob = _bytes(url)
    digest = hashlib.sha256(blob).hexdigest()
    dest = vendor / name
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            target = _vendor_member(dest, member.name, subpath)
            if target is None:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(extracted.read())
    return PackPin(name=name, url=url, pin=sha, sha256=digest)


def _vendor_member(dest: Path, member_name: str, subpath: str) -> Path | None:
    """Return a path inside dest, or None when the tar member escapes it."""
    parts = Path(member_name).parts
    if subpath not in parts or not member_name.endswith((".yar", ".yara")):
        return None
    relative = Path(*parts[parts.index(subpath) + 1 :])
    if not relative.parts or relative.is_absolute() or ".." in relative.parts:
        return None
    root = dest.resolve()
    target = (dest / relative).resolve()
    if target != root and root not in target.parents:
        return None
    return dest / relative


def _json(url: str) -> dict[str, Any]:
    payload = _bytes(url)
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"unexpected payload from {url}")
    return parsed


def _allowed_url(url: str) -> str:
    """Allow only https URLs on the two GitHub hosts used by the lock file."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if parsed.scheme != "https" or host not in _ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError("refusing rule URL")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("refusing rule URL")
    return url


def _bytes(url: str) -> bytes:
    # Host allowlist already ran. An empty proxy map stops HTTP_PROXY from redirecting this call.
    request = urllib.request.Request(  # noqa: S310
        _allowed_url(url),
        headers={"User-Agent": "yara-gate", "Accept": "application/vnd.github+json"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=180) as response:
        body = response.read()
    if not isinstance(body, bytes):
        raise TypeError("rule download was not bytes")
    return body


def _validate_one(yara_x: Any, path: Path, text: str) -> None:
    compiler_type = yara_x.Compiler
    compiler = compiler_type(relaxed_re_syntax=True)
    compiler.define_global("yara_gate_ext", "bin")
    include = getattr(compiler, "add_include_dir", None)
    if callable(include):
        include(str(path.parent))
    compiler.add_source(text, origin=path.name)
    compiler.build()


def _add_include_dirs(compiler: object, rules_dir: Path) -> None:
    add = getattr(compiler, "add_include_dir", None)
    if not callable(add):
        return
    seen: set[Path] = set()
    for path in rule_files(rules_dir):
        if path.parent in seen:
            continue
        seen.add(path.parent)
        add(str(path.parent))


def _split_good(files: list[Path], rules_dir: Path) -> tuple[list[tuple[Path, str]], list[str]]:
    good: list[tuple[Path, str]] = []
    skipped: list[str] = []
    skipped_names: set[str] = set()
    skipped_path = rules_dir / "vendor" / "SKIPPED.md"
    if skipped_path.is_file():
        for line in skipped_path.read_text(encoding="utf-8").splitlines():
            if line and not line.startswith("#"):
                skipped.append(line)
                skipped_names.add(line.split(":", 1)[0])
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        if is_candidate(text) or path.name in skipped_names:
            continue
        good.append((path, text))
    return good, skipped


def _source_digest(files: list[Path]) -> str:
    hasher = hashlib.sha256(_CACHE_SALT)
    for path in files:
        hasher.update(path.name.encode())
        hasher.update(path.read_bytes())
    return hasher.hexdigest()


def _cache_file(rules_dir: Path, digest: str) -> Path:
    return rules_dir / ".cache" / f"{digest}.yarc"


def _read_cache(rules_dir: Path, digest: str) -> object | None:
    path = _cache_file(rules_dir, digest)
    if not path.is_file():
        return None
    import yara_x

    with path.open("rb") as handle:
        return yara_x.Rules.deserialize_from(handle)


def _write_cache(rules_dir: Path, digest: str, rules: Any) -> None:
    path = _cache_file(rules_dir, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        serialize = rules.serialize_into
        serialize(handle)


def _clear_cache(rules_dir: Path) -> None:
    cache = rules_dir / ".cache"
    if cache.exists():
        shutil.rmtree(cache)


def _write_skipped(rules_dir: Path, skipped: list[str]) -> None:
    vendor = rules_dir / "vendor"
    vendor.mkdir(parents=True, exist_ok=True)
    lines = ["# Rules skipped because yara-x could not compile them", ""]
    lines.extend(skipped)
    (vendor / "SKIPPED.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def _count_rules(good: list[tuple[Path, str]]) -> int:
    total = 0
    for _path, text in good:
        total += len(_RULE_NAME.findall(text))
    return total


def _count_skipped(skipped: list[str]) -> int:
    return len(skipped)


def _find_hunt_rule(rules_dir: Path, rule_id: str) -> Path:
    local = rules_dir / "local"
    token = rule_id.removeprefix("hunt_")
    direct = local / f"hunt_{token}.yar"
    if direct.is_file():
        return direct
    matches = sorted(local.glob(f"*{token}*.yar"))
    if len(matches) == 1:
        return matches[0]
    raise FileNotFoundError(rule_id)
