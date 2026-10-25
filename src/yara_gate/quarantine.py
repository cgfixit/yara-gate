"""Drop-folder intake. Downstream readers only see clean/."""

import errno
import hashlib
import os
import secrets
import shutil
import signal
import stat
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from yara_gate.models import ScanPolicy, ScanResult, Verdict
from yara_gate.report import write_reports
from yara_gate.scanner import scan_file

# The common per-component limit on Linux and macOS, in encoded bytes.
_NAME_MAX = 255
# A regular file whose last write is at least this old is treated as fully written.
_SETTLE_AGE_NS = 1_000_000_000
# A fresher file must look the same on two looks at least this far apart (the watch loop
# interval), so a writer that pauses between chunks is not mistaken for a finished one.
_SETTLE_WINDOW_NS = 500_000_000


@dataclass(frozen=True)
class GatePaths:
    root: Path

    @property
    def inbox(self) -> Path:
        return self.root / "inbox"

    @property
    def quarantine(self) -> Path:
        return self.root / "quarantine"

    @property
    def clean(self) -> Path:
        return self.root / "clean"

    @property
    def blocked(self) -> Path:
        return self.root / "blocked"

    @property
    def reports(self) -> Path:
        return self.root / "reports"

    def ensure(self) -> None:
        """Create the gate folders and keep them private to this user."""
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, stat.S_IRWXU)
        for folder in (self.inbox, self.quarantine, self.clean, self.blocked, self.reports):
            folder.mkdir(parents=True, exist_ok=True)
            os.chmod(folder, stat.S_IRWXU)


def default_home() -> GatePaths:
    return GatePaths(Path.home() / "YaraGate")


class IntakeRejected(Exception):
    """The inbox entry was not a single regular file. Its target was not read."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def intake(home: GatePaths, src: Path) -> Path:
    """Copy one regular file into quarantine/<sha256>/ and strip the executable bit."""
    home.ensure()
    fd = _open_regular(src)
    try:
        digest = _hash_fd(fd)
        existing = _existing_slot(home, digest)
        if existing is not None:
            quarantine = home.quarantine / digest
            if existing.parent != quarantine:
                # Every rescan must pass through quarantine, including a stricter policy.
                os.replace(existing.parent, quarantine)
                existing = quarantine / existing.name
            if _same_file(fd, existing):
                return existing
            _unlink_entry(src)
            return existing
        slot = home.quarantine / digest
        slot.mkdir(parents=True, exist_ok=True)
        dest = slot / src.name
        _copy_fd(fd, dest)
        if not _same_file(fd, dest):
            _unlink_entry(src)
        return dest
    finally:
        os.close(fd)


def process_inbox_file(
    home: GatePaths,
    src: Path,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
) -> ScanResult:
    try:
        placed = intake(home, src)
    except IntakeRejected as exc:
        return _reject_entry(home, src, exc.reason, policy)
    result = scan_file(placed, timeout_s=timeout_s, rules_dir=rules_dir, policy=policy)
    write_reports(home.reports, result)
    _relocate(home, result)
    return result


def scan_in_place(
    home: GatePaths,
    src: Path,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
) -> ScanResult:
    """Scan a path that did not come from the inbox. The file stays where it is."""
    home.ensure()
    result = scan_file(src, timeout_s=timeout_s, rules_dir=rules_dir, policy=policy)
    write_reports(home.reports, result)
    return result


def watch(
    home: GatePaths,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
) -> None:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer

    home.ensure()
    _acquire_lock(home)
    handler = _InboxHandler(home, rules_dir, timeout_s, policy)

    class Handler(FileSystemEventHandler):
        def on_created(self, event: object) -> None:
            _dispatch(event, handler)

        def on_moved(self, event: object) -> None:
            _dispatch(event, handler)

    observer = Observer()
    observer.schedule(Handler(), str(home.inbox), recursive=False)
    observer.start()
    stop = False

    def _request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, _request_stop)
    signal.signal(signal.SIGTERM, _request_stop)
    try:
        while not stop:
            # A fresh file is recorded on one pass and scanned on the next if it has not
            # changed, so the loop never sleeps per file and never holds the lock while waiting.
            _drain(handler, home, wait=False)
            time.sleep(0.5)
    finally:
        observer.stop()
        observer.join(timeout=5)
        lock = home.root / ".watch.pid"
        if lock.exists():
            lock.unlink()


def drain_inbox(
    home: GatePaths,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
) -> None:
    """Scan files already sitting in inbox/. A file still being written is given 0.2 s."""
    _drain(_InboxHandler(home, rules_dir, timeout_s, policy), home, wait=True)


def _drain(handler: "_InboxHandler", home: GatePaths, *, wait: bool) -> None:
    entries = sorted(home.inbox.iterdir())
    for path in entries:
        handler.handle(path, wait=wait)
    handler.forget_missing({str(path) for path in entries})


def _dispatch(event: object, handler: "_InboxHandler") -> None:
    path = getattr(event, "dest_path", None) or getattr(event, "src_path", None)
    if not path or getattr(event, "is_directory", False):
        return
    # The watch loop drains again within 0.5 s; a file still being written waits for that.
    handler.handle(Path(str(path)), wait=False)


class _InboxHandler:
    def __init__(
        self,
        home: GatePaths,
        rules_dir: Path | None,
        timeout_s: int,
        policy: ScanPolicy = ScanPolicy.default,
    ) -> None:
        self.home = home
        self.rules_dir = rules_dir
        self.timeout_s = timeout_s
        self.policy = policy
        self._lock = threading.Lock()
        # Size, mtime, and the time of the first look at each fresh regular file, keyed by path.
        self._pending: dict[str, tuple[int, int, int]] = {}

    def handle(self, path: Path, *, wait: bool = True) -> None:
        with self._lock:
            if path.name.startswith("."):
                return
            try:
                info = path.lstat()
            except OSError:
                return
            if stat.S_ISDIR(info.st_mode):
                return
            if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode) and info.st_nlink == 1:
                if not self._settled(path, info, wait):
                    return
            try:
                result = process_inbox_file(
                    self.home,
                    path,
                    rules_dir=self.rules_dir,
                    timeout_s=self.timeout_s,
                    policy=self.policy,
                )
            except OSError:
                return
            print(f"{result.verdict} sha256={result.sha256}", flush=True)

    def forget_missing(self, present: set[str]) -> None:
        with self._lock:
            for key in [key for key in self._pending if key not in present]:
                del self._pending[key]

    def _settled(self, path: Path, info: os.stat_result, wait: bool) -> bool:
        """True when the file has stopped changing.

        A last write at least one second old counts as settled at once. Otherwise the file
        must show the same size and mtime on two looks at least half a second apart: a
        previous pass of the watch loop (``wait=False``), or a 0.2 s pause here
        (``wait=True``, the one-shot drain, as before).
        """
        key = str(path)
        now = time.time_ns()
        stamp = (info.st_size, info.st_mtime_ns)
        if now - info.st_mtime_ns >= _SETTLE_AGE_NS:
            self._pending.pop(key, None)
            return True
        prior = self._pending.get(key)
        if prior is not None and prior[:2] == stamp:
            if now - prior[2] >= _SETTLE_WINDOW_NS:
                self._pending.pop(key, None)
                return True
            if not wait:
                return False
        if not wait:
            self._pending[key] = (*stamp, now)
            return False
        time.sleep(0.2)
        try:
            again = path.stat()
        except OSError:
            return False
        return stat.S_ISREG(again.st_mode) and (again.st_size, again.st_mtime_ns) == stamp


def _existing_slot(home: GatePaths, digest: str) -> Path | None:
    if digest == "_rejected":
        return None
    for root in (home.clean, home.blocked, home.quarantine):
        slot = root / digest
        if slot.name == "_rejected" or not slot.is_dir():
            continue
        files = [item for item in slot.iterdir() if item.is_file() and not _is_partial(item.name)]
        if files:
            return files[0]
    return None


def _is_partial(name: str) -> bool:
    """A copy in progress. A dotfile from the inbox is a real submission."""
    return name.startswith(".partial-") or (name.startswith(".") and name.endswith(".partial"))


def _relocate(home: GatePaths, result: ScanResult) -> None:
    src = home.quarantine / result.sha256
    if result.verdict is Verdict.incomplete or not src.exists():
        return
    dest_root = home.blocked if result.verdict is Verdict.block else home.clean
    dest = dest_root / result.sha256
    dest_root.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        shutil.rmtree(src, ignore_errors=True)
        return
    os.replace(src, dest)


def _acquire_lock(home: GatePaths) -> None:
    lock = home.root / ".watch.pid"
    if lock.exists():
        try:
            pid = int(lock.read_text(encoding="utf-8").strip())
        except ValueError:
            pid = -1
        if pid > 0 and _alive(pid):
            raise RuntimeError("watch already running")
        lock.unlink()
    lock.write_text(str(os.getpid()), encoding="utf-8")


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _open_regular(src: Path) -> int:
    """Open a regular file with one link. Symlinks raise IntakeRejected and are not read."""
    flags = os.O_RDONLY | os.O_NOFOLLOW
    nonblock = getattr(os, "O_NONBLOCK", 0)
    if isinstance(nonblock, int):
        flags |= nonblock
    try:
        fd = os.open(src, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise IntakeRejected("symlink rejected") from exc
        info = _lstat_or_raise(src)
        reason = _reject_reason(info)
        if reason is None:
            raise
        raise IntakeRejected(reason) from exc
    info = os.fstat(fd)
    reason = _reject_reason(info)
    if reason is None:
        return fd
    os.close(fd)
    raise IntakeRejected(reason)


def _lstat_or_raise(src: Path) -> os.stat_result:
    try:
        return src.lstat()
    except OSError as exc:
        raise IntakeRejected("not a regular file") from exc


def _reject_reason(info: os.stat_result) -> str | None:
    if stat.S_ISLNK(info.st_mode):
        return "symlink rejected"
    if not stat.S_ISREG(info.st_mode):
        return "not a regular file"
    if info.st_nlink != 1:
        return "hardlink rejected"
    return None


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    hasher = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            return hasher.hexdigest()
        hasher.update(chunk)


def _copy_fd(fd: int, dest: Path) -> None:
    os.lseek(fd, 0, os.SEEK_SET)
    # A name derived from dest could exceed NAME_MAX for a long but valid inbox name.
    partial = dest.with_name(f".partial-{secrets.token_hex(4)}")
    with partial.open("wb") as handle:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)
    os.chmod(partial, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    os.replace(partial, dest)


def _same_file(fd: int, other: Path) -> bool:
    try:
        return os.path.samestat(os.fstat(fd), other.stat())
    except OSError:
        return False


def _unlink_entry(src: Path) -> None:
    try:
        src.unlink()
    except OSError:
        return


def _fit_name(prefix: str, name: str) -> str:
    """Join prefix and name, shortening the name so the entry stays within NAME_MAX."""
    while name and len(os.fsencode(prefix + name)) > _NAME_MAX:
        name = name[:-1]
    return prefix + name


def _reject_entry(
    home: GatePaths, src: Path, reason: str, policy: ScanPolicy = ScanPolicy.default
) -> ScanResult:
    """Move the inbox entry aside. Never readlink and never open the target."""
    home.ensure()
    rejected = home.quarantine / "_rejected"
    rejected.mkdir(parents=True, exist_ok=True)
    os.chmod(rejected, stat.S_IRWXU)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    dest = rejected / _fit_name(f"{stamp}-", src.name)
    if dest.exists():
        dest = rejected / _fit_name(f"{stamp}-{secrets.token_hex(2)}-", src.name)
    os.rename(src, dest)
    token = hashlib.sha256(f"{src.name}{stamp}".encode()).hexdigest()
    result = ScanResult(
        sha256=token,
        verdict=Verdict.incomplete,
        incomplete_reason=reason,
        path=str(dest),
        policy=policy,
    )
    write_reports(home.reports, result, stem=f"rejected-{token}")
    return result
