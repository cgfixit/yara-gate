"""Load, pin, and promote YARA rules. Network runs only in ``update``."""

import hashlib
import importlib.metadata
import io
import json
import os
import re
import secrets
import shutil
import tarfile
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from http.client import HTTPMessage
from pathlib import Path
from typing import IO, Any

from pydantic import BaseModel, ConfigDict

_STATUS = re.compile(r'(?m)^\s*status\s*=\s*"([^"]+)"')
_RULE_NAME = re.compile(r"(?m)^rule\s+([A-Za-z0-9_]+)")
_CACHE_SALT = b"yara-gate-rules-v2"
_ALLOWED_DOWNLOAD_HOSTS = frozenset(
    {
        "github.com",
        "codeload.github.com",
        "api.github.com",
        "release-assets.githubusercontent.com",
    }
)
_DOWNLOAD_CAP = 300 * 1024 * 1024
Transport = Callable[[str], bytes]


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
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    temporary.write_text(lock.model_dump_json(indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


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
    digest = ruleset_digest(rules_dir)
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
            skipped.append(f"{path.relative_to(rules_dir).as_posix()}: {exc.__class__.__name__}")
            continue
        good.append((path, text))
    if not good:
        _write_skipped(rules_dir, skipped)
        return None, skipped, "no rules compiled", 0, _count_skipped(skipped)

    if any(not line.startswith("vendor/") for line in skipped):
        _write_skipped(rules_dir, skipped)
        return None, skipped, "local rule compile failed", 0, _count_skipped(skipped)

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


def update_packs(rules_dir: Path | None = None, *, transport: Transport | None = None) -> RulesLock:
    """Resolve current pins, then swap vendor only after the new tree compiles."""
    root = rules_dir or default_rules_dir()
    staging = _staging_dir(root)
    try:
        packs = [
            _fetch_forge(staging, transport=transport),
            _fetch_git(
                "signature-base",
                "Neo23x0/signature-base",
                "yara",
                staging,
                transport=transport,
            ),
            _fetch_git(
                "elastic",
                "elastic/protections-artifacts",
                "yara",
                staging,
                transport=transport,
            ),
        ]
        _validate_staged(root, staging)
        lock = RulesLock(packs=packs)
        _swap_vendor(root, staging, lock)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    _clear_cache(root)
    return lock


def install_packs(
    rules_dir: Path | None = None, *, transport: Transport | None = None
) -> RulesLock:
    """Download the locked URLs and keep the old vendor tree if any check fails."""
    root = rules_dir or default_rules_dir()
    lock = load_lock(root)
    if not lock.packs:
        raise ValueError("rules.lock has no packs")
    staging = _staging_dir(root)
    try:
        for pack in lock.packs:
            blob = _bytes(pack.url, transport=transport)
            digest = hashlib.sha256(blob).hexdigest()
            if digest != pack.sha256:
                raise ValueError("sha256 mismatch")
            _extract_locked(pack, blob, staging)
        _validate_staged(root, staging)
        _swap_vendor(root, staging, lock)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    _clear_cache(root)
    return lock


def _fetch_forge(vendor: Path, *, transport: Transport | None = None) -> PackPin:
    meta = _json(
        "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest",
        transport=transport,
    )
    tag = str(meta["tag_name"])
    asset = next(item for item in meta["assets"] if item["name"] == "yara-forge-rules-core.zip")
    url = str(asset["browser_download_url"])
    blob = _bytes(url, transport=transport)
    digest = hashlib.sha256(blob).hexdigest()
    _extract_zip(blob, vendor / "yara-forge")
    return PackPin(name="yara-forge-core", url=url, pin=tag, sha256=digest)


def _fetch_git(
    name: str,
    repo: str,
    subpath: str,
    vendor: Path,
    *,
    transport: Transport | None = None,
) -> PackPin:
    description = _json(f"https://api.github.com/repos/{repo}", transport=transport)
    branch = str(description["default_branch"])
    commit = _json(f"https://api.github.com/repos/{repo}/commits/{branch}", transport=transport)
    sha = str(commit["sha"])
    url = f"https://codeload.github.com/{repo}/tar.gz/{sha}"
    blob = _bytes(url, transport=transport)
    digest = hashlib.sha256(blob).hexdigest()
    _extract_tar(blob, vendor / name, subpath)
    return PackPin(name=name, url=url, pin=sha, sha256=digest)


def _extract_locked(pack: PackPin, blob: bytes, vendor: Path) -> None:
    if pack.name == "yara-forge-core" or blob.startswith(b"PK"):
        _extract_zip(blob, vendor / "yara-forge")
        return
    _extract_tar(blob, vendor / pack.name, "yara")


def _extract_zip(blob: bytes, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        for info in archive.infolist():
            if info.is_dir() or not info.filename.endswith((".yar", ".yara")):
                continue
            target = dest / Path(info.filename).name
            target.write_bytes(archive.read(info))


def _extract_tar(blob: bytes, dest: Path, subpath: str) -> None:
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


def _json(url: str, *, transport: Transport | None = None) -> dict[str, Any]:
    payload = _bytes(url, transport=transport)
    parsed = json.loads(payload.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"unexpected payload from {url}")
    return parsed


def _allowed_url(url: str) -> str:
    """Allow only https URLs on the GitHub hosts used for metadata and pack bytes."""
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname
    if parsed.scheme != "https" or host not in _ALLOWED_DOWNLOAD_HOSTS:
        raise ValueError("refusing rule URL")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError("refusing rule URL")
    return url


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    """Re-check every redirect hop against the host allowlist."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        _allowed_url(urllib.parse.urljoin(req.full_url, newurl))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _bytes(url: str, *, transport: Transport | None = None) -> bytes:
    clean = _allowed_url(url)
    if transport is not None:
        body = transport(clean)
    else:
        # An empty proxy map stops HTTP_PROXY from sending this call elsewhere.
        request = urllib.request.Request(  # noqa: S310
            clean,
            headers={"User-Agent": "yara-gate", "Accept": "application/vnd.github+json"},
        )
        opener = urllib.request.build_opener(_PinnedRedirect, urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=180) as response:
            body = _read_capped(response)
    if not isinstance(body, bytes):
        raise TypeError("rule download was not bytes")
    if len(body) > _DOWNLOAD_CAP:
        raise ValueError("download exceeds cap")
    return body


def _read_capped(response: object) -> bytes:
    read = getattr(response, "read", None)
    if not callable(read):
        raise TypeError("rule download was not bytes")
    chunks: list[bytes] = []
    total = 0
    while total <= _DOWNLOAD_CAP:
        block = read(1024 * 1024)
        if not isinstance(block, bytes):
            raise TypeError("rule download was not bytes")
        if not block:
            return b"".join(chunks)
        total += len(block)
        if total > _DOWNLOAD_CAP:
            raise ValueError("download exceeds cap")
        chunks.append(block)
    raise ValueError("download exceeds cap")


def _staging_dir(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f".staging-{secrets.token_hex(4)}"
    staging.mkdir()
    return staging


def _validate_staged(root: Path, staging: Path) -> None:
    check = root / f".check-{secrets.token_hex(4)}"
    check.mkdir()
    try:
        local = root / "local"
        if local.is_dir():
            os.symlink(local, check / "local", target_is_directory=True)
        os.symlink(staging, check / "vendor", target_is_directory=True)
        _compiled, _skipped, error, _count, _skip = compile_sources(check)
        if error:
            raise ValueError(error)
    finally:
        if check.exists():
            # The vendor entry is a symlink. Remove it before deleting the check dir.
            vendor_link = check / "vendor"
            if vendor_link.is_symlink():
                vendor_link.unlink()
            local_link = check / "local"
            if local_link.is_symlink():
                local_link.unlink()
            shutil.rmtree(check)


def _swap_vendor(root: Path, staging: Path, lock: RulesLock) -> None:
    vendor = root / "vendor"
    old = root / f".vendor-old-{secrets.token_hex(4)}"
    moved = False
    try:
        if vendor.exists():
            os.rename(vendor, old)
            moved = True
        os.rename(staging, vendor)
        save_lock(lock, root)
        if moved and old.exists():
            shutil.rmtree(old)
    except Exception:
        if moved and old.exists():
            if vendor.exists():
                shutil.rmtree(vendor, ignore_errors=True)
            if not vendor.exists():
                os.rename(old, vendor)
        raise


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
        if is_candidate(text) or path.relative_to(rules_dir).as_posix() in skipped_names:
            continue
        good.append((path, text))
    return good, skipped


def ruleset_digest(rules_dir: Path) -> str:
    hasher = hashlib.sha256(_CACHE_SALT)
    hasher.update(importlib.metadata.version("yara-x").encode())
    for path in rule_files(rules_dir):
        hasher.update(path.relative_to(rules_dir).as_posix().encode())
        hasher.update(b"\x00")
        hasher.update(path.read_bytes())
        hasher.update(b"\x00")
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
