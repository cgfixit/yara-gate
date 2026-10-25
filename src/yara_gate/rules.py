"""Load, pin, and promote YARA rules. Network runs only in ``update``."""

import functools
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import tarfile
import time
import urllib.error
import urllib.parse
import zipfile
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import platformdirs

_STATUS = re.compile(r'(?m)^\s*status\s*=\s*"([^"]+)"')
# private and global rules compile too, so they count.
_RULE_NAME = re.compile(r"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+([A-Za-z0-9_]+)")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
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
# The last compiled set, keyed by its digest, so each file in a run skips deserializing.
_MEMO: dict[str, tuple[object, list[str], int, int]] = {}
# Content hash of one rules directory. Later files in the same run stat instead of rereading.
_DIGEST_STAMP: dict[str, tuple[object, ...]] = {}
_DIGEST_VALUE: dict[str, str] = {}
# The sorted rule-file listing of one folder, keyed by folder, valid while every directory
# under it keeps its mtime. A directory touched within the racy window is never cached, so a
# file created in the same timestamp tick as the listing cannot be missed (git's "racily clean").
_LISTING: dict[str, tuple[tuple[tuple[str, int], ...], list[Path]]] = {}
_RACY_WINDOW_NS = 2_000_000_000


class RuleDownloadError(Exception):
    """A rule download failed. The message is safe to print."""


@dataclass(kw_only=True, slots=True)
class PackPin:
    name: str
    url: str
    pin: str
    sha256: str

    @classmethod
    def model_validate(cls, data: object) -> "PackPin":
        fields = ("name", "url", "pin", "sha256")
        if not isinstance(data, dict) or set(data) != set(fields):
            raise ValueError("invalid pack pin")
        if not all(isinstance(data[key], str) for key in fields):
            raise ValueError("invalid pack pin")
        return cls(**{key: data[key] for key in fields})


@dataclass(kw_only=True, slots=True)
class RulesLock:
    packs: list[PackPin]
    installed_vendor_files: list[str] | None = None

    @classmethod
    def model_validate(cls, data: object) -> "RulesLock":
        """Parse a decoded lock. Anything unexpected raises ValueError, as the loader expects."""
        if not isinstance(data, dict) or not set(data) <= {"packs", "installed_vendor_files"}:
            raise ValueError("invalid rules.lock")
        packs = data.get("packs")
        if not isinstance(packs, list):
            raise ValueError("invalid rules.lock")
        installed = data.get("installed_vendor_files")
        if installed is not None and (
            not isinstance(installed, list) or not all(isinstance(item, str) for item in installed)
        ):
            raise ValueError("invalid rules.lock")
        return cls(
            packs=[PackPin.model_validate(item) for item in packs], installed_vendor_files=installed
        )

    def model_dump_json(self, *, indent: int | None = None, exclude_none: bool = False) -> str:
        data: dict[str, object] = {"packs": [asdict(pack) for pack in self.packs]}
        if self.installed_vendor_files is not None or not exclude_none:
            data["installed_vendor_files"] = self.installed_vendor_files
        separators = (",", ": ") if indent else (",", ":")
        return json.dumps(data, indent=indent, separators=separators, ensure_ascii=False)


def project_root() -> Path:
    return Path(__file__).resolve().parents[2]


def bundled_local_dir() -> Path | None:
    path = Path(__file__).resolve().parent / "bundled_rules" / "local"
    if path.is_dir() and any(path.glob("*.yar")):
        return path
    return None


def shipped_local_dir() -> Path:
    """Local rules shipped in the wheel, or the checkout copy in an editable install."""
    bundled = bundled_local_dir()
    if bundled is not None:
        return bundled
    return project_root() / "rules" / "local"


def shipped_benign_dir() -> Path:
    """Benign corpus shipped beside the packaged rules, else the checkout fixtures."""
    bundled = Path(__file__).resolve().parent / "bundled_rules" / "benign"
    if bundled.is_dir() and any(bundled.iterdir()):
        return bundled
    return project_root() / "tests" / "fixtures" / "benign"


def _same_path(left: Path, right: Path) -> bool:
    return left.expanduser().resolve() == right.expanduser().resolve()


def _readable_shipped_local() -> Path | None:
    path = shipped_local_dir()
    try:
        files = [
            item for item in path.iterdir() if item.is_file() and item.suffix in {".yar", ".yara"}
        ]
        if not files:
            return None
        files[0].read_bytes()
    except OSError:
        return None
    return path


def _is_shipped_tree(rules_dir: Path) -> bool:
    """True when local/ already contains every packaged rule name."""
    shipped = _readable_shipped_local()
    local = rules_dir / "local"
    if shipped is None or not local.is_dir():
        return False
    names = {
        item.name
        for item in shipped.iterdir()
        if item.is_file() and item.suffix in {".yar", ".yara"}
    }
    present = {item.name for item in local.iterdir() if item.is_file()}
    return bool(names) and names <= present


def _installed_overlay(rules_dir: Path) -> bool:
    """Packaged rules stay underneath a writable install root.

    The platform data directory always overlays, even when a user copied the
    shipped filenames into it. ``YARA_GATE_RULES`` overlays only when that
    directory is not already a copy of the shipped rules. An explicit
    ``--rules`` tree that contains those names is loaded once.
    """
    if _same_path(rules_dir, installed_rules_root()):
        return True
    env = os.environ.get("YARA_GATE_RULES")
    if not env or not _same_path(rules_dir, Path(env)):
        return False
    return not _is_shipped_tree(rules_dir)


def installed_rules_root() -> Path:
    return Path(platformdirs.user_data_dir("yara-gate"))


def default_rules_dir() -> Path:
    env = os.environ.get("YARA_GATE_RULES")
    if env:
        return Path(env)
    checkout = project_root() / "rules"
    if (checkout / "local").is_dir():
        return checkout
    return installed_rules_root()


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
    temporary.write_text(lock.model_dump_json(indent=2, exclude_none=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def rule_files(rules_dir: Path, *, overlay: bool | None = None) -> list[Path]:
    use_overlay = _installed_overlay(rules_dir) if overlay is None else overlay
    if use_overlay:
        return _overlay_rule_files(rules_dir)
    return _checkout_rule_files(rules_dir)


def _checkout_rule_files(rules_dir: Path) -> list[Path]:
    found: list[Path] = []
    local = rules_dir / "local"
    if local.is_dir():
        _collect_rules(local, found)
    elif _same_path(rules_dir, installed_rules_root()):
        shipped = _readable_shipped_local()
        if shipped is not None:
            _collect_rules(shipped, found)
    vendor = rules_dir / "vendor"
    if vendor.is_dir():
        _collect_rules(vendor, found)
    if found:
        return found
    _collect_rules(rules_dir, found, nested=False)
    return found


def _overlay_rule_files(rules_dir: Path) -> list[Path]:
    shipped = _readable_shipped_local()
    if shipped is None:
        return []
    found: list[Path] = []
    _collect_rules(shipped, found)
    names = {path.name for path in found}
    local = rules_dir / "local"
    if local.is_dir():
        extra: list[Path] = []
        _collect_rules(local, extra)
        for path in extra:
            if path.name in names:
                continue
            found.append(path)
    vendor = rules_dir / "vendor"
    if vendor.is_dir():
        _collect_rules(vendor, found)
    return found


def shadowed_rule_lines(rules_dir: Path, *, overlay: bool | None = None) -> list[str]:
    use_overlay = _installed_overlay(rules_dir) if overlay is None else overlay
    if not use_overlay:
        return []
    shipped = _readable_shipped_local()
    local = rules_dir / "local"
    if shipped is None or not local.is_dir():
        return []
    names = {
        item.name
        for item in shipped.iterdir()
        if item.is_file() and item.suffix in {".yar", ".yara"}
    }
    extra: list[Path] = []
    _collect_rules(local, extra)
    lines: list[str] = []
    for path in extra:
        if path.name not in names:
            continue
        lines.append(f"local/{path.relative_to(local).as_posix()}: shadowed by bundled")
    return lines


def _collect_rules(folder: Path, found: list[Path], *, nested: bool = True) -> None:
    if not nested:
        found.extend(sorted(folder.glob("*.yar")))
        found.extend(sorted(folder.glob("*.yara")))
        return
    key = str(folder)
    stamp = _directory_stamp(folder)
    cached = _LISTING.get(key)
    if cached is not None and stamp is not None and cached[0] == stamp:
        found.extend(cached[1])
        return
    listing = sorted(folder.rglob("*.yar"))
    listing.extend(sorted(folder.rglob("*.yara")))
    found.extend(listing)
    if stamp is None:
        _LISTING.pop(key, None)
    else:
        _LISTING[key] = (stamp, list(listing))


def _directory_stamp(folder: Path) -> tuple[tuple[str, int], ...] | None:
    """The mtime of every directory under ``folder``, or None when one changed too recently.

    Adding, deleting, or renaming a rule file changes its directory's mtime; an edit in place
    is caught by the per-file stat in ``ruleset_digest``. Symlinked directories are followed
    so a staged vendor tree reached through a link is stamped too.
    """
    now = time.time_ns()
    rows: list[tuple[str, int]] = []
    for dirpath, dirnames, _files in os.walk(folder, followlinks=True):
        try:
            info = os.stat(dirpath)
        except OSError:
            return None
        if now - info.st_mtime_ns < _RACY_WINDOW_NS:
            return None
        rows.append((dirpath, info.st_mtime_ns))
        dirnames.sort()
    return tuple(rows)


@functools.cache
def yara_x_version() -> str:
    """The installed engine version. Looked up once: the metadata scan costs milliseconds."""
    import importlib.metadata

    return importlib.metadata.version("yara-x")


def _rule_key(path: Path, rules_dir: Path) -> str:
    # Slicing normalized strings gives relative_to's answer without building a Path per rule file,
    # and this runs for every rule file on every scanned input. Anything else takes the slow path.
    prefix = str(rules_dir)
    if not prefix.endswith(os.sep):
        prefix += os.sep
    text = str(path)
    if len(text) > len(prefix) and text.startswith(prefix):
        return text[len(prefix) :].replace(os.sep, "/")
    try:
        return path.relative_to(rules_dir).as_posix()
    except ValueError:
        shipped = _readable_shipped_local()
        if shipped is not None:
            try:
                return f"local/{path.relative_to(shipped).as_posix()}"
            except ValueError:
                pass
        return path.name


def _under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


def is_candidate(text: str) -> bool:
    match = _STATUS.search(text)
    return match is not None and match.group(1) == "candidate"


def compile_sources(
    rules_dir: Path, *, overlay: bool | None = None
) -> tuple[object | None, list[str], str | None, int, int]:
    """Return compiled rules, skip lines, fatal error, compiled rule count, skipped rule count."""
    rules, skipped, error, compiled, skip_count, _digest = compile_ruleset(
        rules_dir, overlay=overlay
    )
    return rules, skipped, error, compiled, skip_count


def compile_ruleset(
    rules_dir: Path, *, overlay: bool | None = None
) -> tuple[object | None, list[str], str | None, int, int, str | None]:
    """Like ``compile_sources``, plus the ruleset digest when rules were found."""
    use_overlay = _installed_overlay(rules_dir) if overlay is None else overlay
    if use_overlay and _readable_shipped_local() is None:
        return None, [], "bundled rules missing", 0, 0, None
    try:
        import yara_x
    except ImportError:
        return None, [], "yara-x missing", 0, 0, None

    files = rule_files(rules_dir, overlay=use_overlay)
    shadows = shadowed_rule_lines(rules_dir, overlay=use_overlay)
    try:
        installed = load_lock(rules_dir).installed_vendor_files
    except (OSError, ValueError):
        return None, shadows, "invalid rules.lock", 0, _count_skipped(shadows), None
    if installed is not None:
        vendor = str(rules_dir / "vendor") + os.sep
        present = {
            text[len(vendor) :].replace(os.sep, "/")
            for text in map(str, files)
            if text.startswith(vendor) and os.path.isfile(text)
        }
        if not installed or not set(installed) <= present:
            return None, shadows, "installed vendor rules missing", 0, _count_skipped(shadows), None
    if not files:
        if use_overlay:
            return None, shadows, "bundled rules missing", 0, _count_skipped(shadows), None
        return None, [], "no rules compiled", 0, 0, None
    digest = ruleset_digest(rules_dir, overlay=use_overlay, files=files, shadows=shadows)
    memo = _MEMO.get(digest)
    if memo is not None:
        rules, remembered, compiled, skip_count = memo
        return rules, list(remembered), None, compiled, skip_count, digest
    good: list[tuple[Path, str]] = []
    skipped: list[str] = []
    cached = _read_cache(digest)
    if cached is not None:
        rules, skipped = cached
        good = _files_except(files, rules_dir, skipped)
        _remember(digest, rules, skipped, _count_rules(good))
        return rules, skipped, None, _count_rules(good), _count_skipped(skipped), digest

    shipped_root = _readable_shipped_local() if use_overlay else None
    for path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            if shipped_root is not None and _under(path, shipped_root):
                return None, [], "bundled rules missing", 0, 0, digest
            skipped.append(f"{_rule_key(path, rules_dir)}: OSError")
            continue
        if is_candidate(text):
            continue
        try:
            _validate_one(yara_x, path, text)
        except yara_x.CompileError as exc:
            skipped.append(f"{_rule_key(path, rules_dir)}: {exc.__class__.__name__}")
            continue
        good.append((path, text))
    skipped.extend(shadows)
    if not good:
        reason = "bundled rules missing" if use_overlay else "no rules compiled"
        return None, skipped, reason, 0, _count_skipped(skipped), digest

    if _local_compile_failed(skipped):
        return None, skipped, "local rule compile failed", 0, _count_skipped(skipped), digest

    compiler = yara_x.Compiler(relaxed_re_syntax=True)
    compiler.define_global("yara_gate_ext", "bin")
    _add_include_dirs(compiler, rules_dir, overlay=use_overlay)
    for index, (path, text) in enumerate(good):
        compiler.new_namespace(f"gate_{index}")
        compiler.add_source(text, origin=path.name)
    rules = compiler.build()
    _write_cache(digest, rules, skipped)
    _remember(digest, rules, skipped, _count_rules(good))
    return rules, skipped, None, _count_rules(good), _count_skipped(skipped), digest


def _remember(digest: str, rules: object, skipped: list[str], compiled: int) -> None:
    _MEMO.clear()
    _MEMO[digest] = (rules, list(skipped), compiled, _count_skipped(skipped))


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
    lock = _lock_for_install(root)
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
    try:
        tag = str(meta["tag_name"])
        asset = next(item for item in meta["assets"] if item["name"] == "yara-forge-rules-core.zip")
        url = str(asset["browser_download_url"])
    except (KeyError, StopIteration, TypeError):
        raise RuleDownloadError("yara-forge release has no yara-forge-rules-core.zip") from None
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
    commit_url = f"https://api.github.com/repos/{repo}/commits/"
    try:
        commit = _json(commit_url + str(description["default_branch"]), transport=transport)
        sha = str(commit["sha"])
    except (KeyError, TypeError):
        raise RuleDownloadError(f"unexpected commit data for {repo}") from None
    # The pin becomes part of the download URL; accept only a full commit id.
    if _COMMIT_SHA.fullmatch(sha) is None:
        raise RuleDownloadError(f"unexpected commit data for {repo}")
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


@functools.cache
def _redirect_handler() -> type:
    """The redirect handler class. urllib.request and http.client load only when a download runs."""
    import urllib.request
    from http.client import HTTPMessage
    from typing import IO

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
            joined = urllib.parse.urljoin(req.full_url, newurl)
            _allowed_url(joined)
            new = super().redirect_request(req, fp, code, msg, headers, newurl)
            if new is None:
                return None
            old_host = urllib.parse.urlparse(req.full_url).hostname
            new_host = urllib.parse.urlparse(new.full_url).hostname
            if new_host != old_host:
                new.headers.pop("Authorization", None)
                new.unredirected_hdrs.pop("Authorization", None)
            elif new_host == "api.github.com":
                token = req.get_header("Authorization")
                if token and not new.has_header("Authorization"):
                    new.add_unredirected_header("Authorization", token)
            return new

    return _PinnedRedirect


def __getattr__(name: str) -> Any:
    # Tests and callers reach the handler class as yara_gate.rules._PinnedRedirect.
    if name == "_PinnedRedirect":
        return _redirect_handler()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def _github_token(url: str) -> str | None:
    if urllib.parse.urlparse(url).hostname != "api.github.com":
        return None
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return None


def _format_reset(value: str | None) -> str:
    if value is None or not str(value).isdigit():
        return "unknown"
    when = datetime.fromtimestamp(int(value)).astimezone()
    zone = when.tzname() or when.strftime("%z")
    return f"{when.strftime('%Y-%m-%d %H:%M:%S')} {zone}"


def _download_http_error(url: str, exc: urllib.error.HTTPError) -> RuleDownloadError:
    code = int(exc.code)
    host = urllib.parse.urlparse(url).hostname or ""
    headers = exc.headers
    remaining = headers.get("X-RateLimit-Remaining") if headers is not None else None
    if code in {403, 429} and str(remaining) == "0":
        reset = headers.get("X-RateLimit-Reset") if headers is not None else None
        when = _format_reset(None if reset is None else str(reset))
        return RuleDownloadError(f"rate limited by api.github.com until {when}; set GITHUB_TOKEN")
    if code == 404:
        return RuleDownloadError(f"not found: {url}")
    return RuleDownloadError(f"HTTP {code} from {host}")


def bundled_lock_path() -> Path | None:
    packaged = Path(__file__).resolve().parent / "bundled_rules" / "rules.lock"
    if packaged.is_file():
        return packaged
    checkout = project_root() / "rules" / "rules.lock"
    if checkout.is_file():
        return checkout
    return None


def _lock_for_install(root: Path) -> RulesLock:
    if (root / "rules.lock").is_file():
        return load_lock(root)
    bundled = bundled_lock_path()
    if bundled is None:
        return RulesLock(packs=[])
    return RulesLock.model_validate(json.loads(bundled.read_text(encoding="utf-8")))


def _bytes(url: str, *, transport: Transport | None = None) -> bytes:
    clean = _allowed_url(url)
    if transport is not None:
        body = transport(clean)
    else:
        import urllib.request

        # An empty proxy map stops HTTP_PROXY from sending this call elsewhere.
        request = urllib.request.Request(clean)  # noqa: S310
        request.add_unredirected_header("User-Agent", "yara-gate")
        request.add_unredirected_header("Accept", "application/vnd.github+json")
        token = _github_token(clean)
        if token:
            request.add_unredirected_header("Authorization", f"Bearer {token}")
        opener = urllib.request.build_opener(_redirect_handler(), urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=180) as response:
                body = _read_capped(response)
        except urllib.error.HTTPError as exc:
            raise _download_http_error(clean, exc) from None
        except (urllib.error.URLError, TimeoutError):
            raise RuleDownloadError("network unreachable") from None
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
        _compiled, skipped, error, _count, _skip = compile_sources(
            check, overlay=_installed_overlay(root)
        )
        if error:
            raise ValueError(error)
        _write_skipped(staging, skipped)
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
    files: list[Path] = []
    _collect_rules(staging, files)
    if not files:
        raise ValueError("no vendor rule files")
    lock.installed_vendor_files = sorted(path.relative_to(staging).as_posix() for path in files)
    vendor = root / "vendor"
    old = root / f".vendor-old-{secrets.token_hex(4)}"
    moved = False
    installed = False
    try:
        if vendor.exists():
            os.rename(vendor, old)
            moved = True
        os.rename(staging, vendor)
        installed = True
        save_lock(lock, root)
    except Exception:
        if installed:
            shutil.rmtree(vendor, ignore_errors=True)
        if moved and old.exists() and not vendor.exists():
            os.rename(old, vendor)
        raise
    if moved and old.exists():
        # The tree and lock are committed; backup cleanup must not roll them back.
        shutil.rmtree(old, ignore_errors=True)


def _validate_one(yara_x: Any, path: Path, text: str) -> None:
    compiler_type = yara_x.Compiler
    compiler = compiler_type(relaxed_re_syntax=True)
    compiler.define_global("yara_gate_ext", "bin")
    include = getattr(compiler, "add_include_dir", None)
    if callable(include):
        include(str(path.parent))
    compiler.add_source(text, origin=path.name)
    compiler.build()


def _add_include_dirs(compiler: object, rules_dir: Path, *, overlay: bool | None = None) -> None:
    add = getattr(compiler, "add_include_dir", None)
    if not callable(add):
        return
    seen: set[Path] = set()
    for path in rule_files(rules_dir, overlay=overlay):
        if path.parent in seen:
            continue
        seen.add(path.parent)
        add(str(path.parent))


def _local_compile_failed(skipped: list[str]) -> bool:
    for line in skipped:
        if line.startswith("vendor/") or line.endswith(": shadowed by bundled"):
            continue
        return True
    return False


def _files_except(files: list[Path], rules_dir: Path, skipped: list[str]) -> list[tuple[Path, str]]:
    names = {
        line.split(":", 1)[0] for line in skipped if not line.endswith(": shadowed by bundled")
    }
    good: list[tuple[Path, str]] = []
    for path in files:
        # A skipped file may be unreadable, so check the name before reading.
        if _rule_key(path, rules_dir) in names:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if is_candidate(text):
            continue
        good.append((path, text))
    return good


def ruleset_digest(
    rules_dir: Path,
    *,
    overlay: bool | None = None,
    files: list[Path] | None = None,
    shadows: list[str] | None = None,
) -> str:
    """Digest of the rule files in load order. ``files`` and ``shadows`` skip a second directory
    walk for a caller that just listed them."""
    use_overlay = _installed_overlay(rules_dir) if overlay is None else overlay
    if files is None:
        files = rule_files(rules_dir, overlay=use_overlay)
    shadow_lines = tuple(
        shadowed_rule_lines(rules_dir, overlay=use_overlay) if shadows is None else shadows
    )
    keys = [_rule_key(path, rules_dir) for path in files]
    stamp_rows: list[tuple[str, int, int]] = []
    for rule_key, path in zip(keys, files, strict=True):
        try:
            stat = os.stat(path)
        except OSError:
            stamp_rows.append((rule_key, -1, -1))
            continue
        stamp_rows.append((rule_key, stat.st_mtime_ns, stat.st_size))
    stamp = (use_overlay, tuple(stamp_rows), shadow_lines)
    # A same-size same-mtime rewrite is caught on the next process. Inside one run the
    # directory is the operator's rules, and hashing every file per scanned input missed the budget.
    key = str(rules_dir)
    if _DIGEST_STAMP.get(key) == stamp:
        return _DIGEST_VALUE[key]
    hasher = hashlib.sha256(_CACHE_SALT)
    hasher.update(yara_x_version().encode())
    hasher.update(b"overlay\x00" if use_overlay else b"checkout\x00")
    for rule_key, path in zip(keys, files, strict=True):
        hasher.update(rule_key.encode())
        hasher.update(b"\x00")
        try:
            hasher.update(path.read_bytes())
        except OSError:
            # compile_sources reports an unreadable file; the digest must not abort the scan.
            hasher.update(b"\x01unreadable")
        hasher.update(b"\x00")
    for line in shadow_lines:
        hasher.update(line.encode())
        hasher.update(b"\x00")
    digest = hasher.hexdigest()
    _DIGEST_STAMP[key] = stamp
    _DIGEST_VALUE[key] = digest
    return digest


def _user_cache_dir() -> Path:
    return Path(platformdirs.user_cache_dir("yara-gate"))


def _read_cache(digest: str) -> tuple[object, list[str]] | None:
    path = _user_cache_dir() / f"{digest}.yarc"
    if not path.is_file():
        return None
    import yara_x

    try:
        with path.open("rb") as handle:
            rules = yara_x.Rules.deserialize_from(handle)
    except OSError:
        return None
    skip_path = _user_cache_dir() / f"{digest}.skipped"
    try:
        text = skip_path.read_text(encoding="utf-8")
    except OSError:
        # Without the skip list a vendor skip would vanish from reports. Recompile instead.
        return None
    skipped = [line for line in text.splitlines() if line]
    return rules, skipped


def _write_cache(digest: str, rules: Any, skipped: list[str]) -> None:
    try:
        cache = _user_cache_dir()
        cache.mkdir(parents=True, exist_ok=True)
        # The skip list lands first and each file is renamed into place whole, so a
        # reader never pairs compiled rules with a missing or partial skip list.
        token = secrets.token_hex(4)
        skip_tmp = cache / f".{digest}.{token}.skipped.tmp"
        skip_tmp.write_text("\n".join(skipped) + "\n", encoding="utf-8")
        os.replace(skip_tmp, cache / f"{digest}.skipped")
        rules_tmp = cache / f".{digest}.{token}.yarc.tmp"
        with rules_tmp.open("wb") as handle:
            serialize = rules.serialize_into
            serialize(handle)
        os.replace(rules_tmp, cache / f"{digest}.yarc")
    except OSError:
        return


def _clear_cache(rules_dir: Path) -> None:
    _MEMO.clear()
    _DIGEST_STAMP.clear()
    _DIGEST_VALUE.clear()
    _LISTING.clear()
    cache = _user_cache_dir()
    if cache.exists():
        shutil.rmtree(cache, ignore_errors=True)
    legacy = rules_dir / ".cache"
    if legacy.exists():
        shutil.rmtree(legacy, ignore_errors=True)


def _write_skipped(vendor: Path, skipped: list[str]) -> None:
    """Write the skip list. Only rules install and rules update call this."""
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
