"""Drop-folder intake. Downstream readers only see clean/."""

import errno
import hashlib
import json
import os
import secrets
import shutil
import signal
import stat
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from yara_gate.models import DOCUMENT_HOLD, ScanPolicy, ScanResult, Verdict
from yara_gate.release import (
    apply_release,
    release_key,
    release_log,
    release_refusal,
    reviewed_result,
)
from yara_gate.report import atomic_write_text, compact_report, write_reports
from yara_gate.rules import _installed_overlay, default_rules_dir
from yara_gate.scanner import MAX_FILE_BYTES, scan_bytes, scan_file

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

# The common per-component limit on Linux and macOS, in encoded bytes.
_NAME_MAX = 255
# A regular file whose last write is at least this old is treated as fully written.
_SETTLE_AGE_NS = 1_000_000_000
# A fresher file must look the same on two looks at least this far apart (the watch loop
# interval), so a writer that pauses between chunks is not mistaken for a finished one.
_SETTLE_WINDOW_NS = 500_000_000
# Python defines O_NOFOLLOW only on POSIX. Without it, intake checks the entry with lstat
# before the open and checks the opened file's identity after it.
_NOFOLLOW: int | None = getattr(os, "O_NOFOLLOW", None)
# Windows opens in text mode unless asked, which rewrites CRLF and stops reading at Ctrl-Z.
_BINARY: int = getattr(os, "O_BINARY", 0)
# Windows attributes of a symlink, junction, or cloud-file placeholder, or of data that is not
# on the local disk. Opening one can follow it or recall it over the network. RECALL_ON_OPEN
# is left out: it shares 0x40000 with FILE_ATTRIBUTE_EA, which ordinary files can carry.
_FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
_UNREAD_ATTRIBUTES = (
    stat.FILE_ATTRIBUTE_REPARSE_POINT
    | stat.FILE_ATTRIBUTE_OFFLINE
    | _FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)


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

    @property
    def pending_intake(self) -> Path:
        return self.root / ".intake-pending.json"

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
    """The entry is unsafe to open or exceeds the intake byte limit."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def intake(
    home: GatePaths,
    src: Path,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
    use_releases: bool = False,
) -> Path:
    """Copy one regular file into quarantine/<sha256>/<its name> and strip the executable bit.

    A digest has one slot holding one file, named as the latest submission. The bytes are
    copied in and scanned under the name they arrived with, because type checks depend on
    the name: the same bytes can be an ordinary tool.exe and a disguised invoice.pdf. An
    earlier copy under any name comes back through quarantine and is replaced.
    """
    home.ensure()
    fd = _open_regular(src)
    opened = os.fstat(fd)
    consumed = False
    try:
        digest = _hash_fd(fd)
        slot = home.quarantine / digest
        for root in (home.clean, home.blocked):
            earlier = root / digest
            if earlier.is_dir():
                # Every rescan passes through quarantine, including a stricter policy.
                if slot.exists():
                    shutil.rmtree(earlier)
                else:
                    os.replace(earlier, slot)
        slot.mkdir(parents=True, exist_ok=True)
        dest = slot / src.name
        _copy_fd(fd, dest)
        for item in slot.iterdir():
            if item.name != dest.name and not item.is_dir():
                item.unlink()
        scan_rules = (rules_dir or default_rules_dir()).absolute()
        atomic_write_text(
            home.pending_intake,
            json.dumps(
                {
                    "sha256": digest,
                    "name": dest.name,
                    "rules_dir": str(scan_rules),
                    "rules_overlay": _installed_overlay(scan_rules),
                    "timeout_s": timeout_s,
                    "policy": policy.value,
                    "use_releases": use_releases,
                }
            ),
        )
        consumed = not _same_file(fd, dest)
        return dest
    finally:
        os.close(fd)
        # Windows refuses to unlink a file while any handle to it is open, this one included.
        if consumed:
            _unlink_entry(src, opened)


def process_inbox_file(
    home: GatePaths,
    src: Path,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
    use_releases: bool = False,
) -> ScanResult:
    home.ensure()
    # One submission at a time per gate home, from intake to relocation, so a CLI scan and
    # watch cannot interleave on the same slot.
    with _gate_lock(home):
        _finish_pending_intake(home)
        try:
            intake(
                home,
                src,
                rules_dir=rules_dir,
                timeout_s=timeout_s,
                policy=policy,
                use_releases=use_releases,
            )
        except IntakeRejected as exc:
            return _reject_entry(home, src, exc.reason, policy)
        result = _finish_pending_intake(home)
        if result is None:
            raise OSError("pending intake disappeared")
        return result


def _finish_pending_intake(home: GatePaths) -> ScanResult | None:
    """Under the intake lock, finish the recorded submission before taking another."""
    marker = home.pending_intake
    try:
        pending = json.loads(marker.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    if not isinstance(pending, dict):
        raise ValueError("invalid pending intake")
    digest = pending.get("sha256")
    name = pending.get("name")
    rules_dir = pending.get("rules_dir")
    rules_overlay = pending.get("rules_overlay")
    timeout_s = pending.get("timeout_s")
    policy_name = pending.get("policy")
    use_releases = pending.get("use_releases")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
        or not isinstance(name, str)
        or Path(name).name != name
        or name in {"", ".", ".."}
        or not isinstance(rules_dir, str)
        or not Path(rules_dir).is_absolute()
        or not isinstance(rules_overlay, bool)
        or type(timeout_s) is not int
        or not isinstance(policy_name, str)
        or not isinstance(use_releases, bool)
    ):
        raise ValueError("invalid pending intake")
    placed = home.quarantine / digest / name
    policy = ScanPolicy(policy_name)
    try:
        slot = placed.parent.lstat()
        if (
            stat.S_ISDIR(slot.st_mode)
            and not (getattr(slot, "st_file_attributes", 0) & _UNREAD_ATTRIBUTES)
            and list(placed.parent.iterdir()) == [placed]
        ):
            info = placed.lstat()
        else:
            info = None
    except FileNotFoundError:
        # A crash after relocation leaves the marker, but no quarantined copy.
        if (home.clean / digest / name).is_file() or (home.blocked / digest / name).is_file():
            marker.unlink()
            return None
        info = None
    reason = _reject_reason(info) if info is not None else "pending quarantine copy unavailable"
    if reason is None and _installed_overlay(Path(rules_dir)) != rules_overlay:
        reason = "pending intake rules overlay changed"
    if reason is None:
        result = scan_file(
            placed,
            timeout_s=timeout_s,
            rules_dir=Path(rules_dir),
            policy=policy,
        )
        if result.verdict is not Verdict.incomplete and result.sha256 != digest:
            result = replace(
                result,
                verdict=Verdict.incomplete,
                advisory=False,
                note=False,
                policy_reason=None,
                incomplete_reason="quarantined copy changed during the scan",
            )
        if use_releases:
            result = apply_release(result, home.root)
    else:
        result = ScanResult(
            sha256="0" * 64,
            verdict=Verdict.incomplete,
            incomplete_reason=reason,
            path=str(placed),
            policy=policy,
        )
    write_reports(home.reports, result)
    _relocate(home, result)
    marker.unlink()
    return result


def scan_in_place(
    home: GatePaths,
    src: Path,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
    use_releases: bool = False,
) -> ScanResult:
    """Scan a path that did not come from the inbox. The file stays where it is."""
    home.ensure()
    result = scan_file(src, timeout_s=timeout_s, rules_dir=rules_dir, policy=policy)
    if use_releases:
        result = apply_release(result, home.root)
    write_reports(home.reports, result)
    return result


def release_file(
    home: GatePaths,
    digest: str,
    path: Path | None,
    *,
    reason: str,
    rules_dir: Path | None,
    timeout_s: int,
) -> tuple[ScanResult, str]:
    """Rescan the reviewed bytes and record the approval before moving any held copy."""
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise ValueError("SHA256 must be 64 hex digits")
    if timeout_s <= 0:
        raise ValueError("scan timeout must be positive")
    home.ensure()
    with _gate_lock(home):
        slot = home.blocked / digest
        if path is None:
            if slot.is_symlink() or slot.is_junction() or not slot.is_dir():
                raise ValueError("no blocked copy with that digest")
            copies = list(slot.iterdir())
            if len(copies) != 1:
                raise ValueError("blocked slot must contain exactly one file")
            target = copies[0]
            dest = home.clean / digest
            if os.path.lexists(dest):
                raise ValueError("clean slot already exists")
        else:
            target = path
            if target.resolve().is_relative_to(home.root.resolve()):
                raise ValueError("release gate-owned copies by digest, without --path")

        report_path = home.reports / f"{digest}.json"
        try:
            prior = json.loads(report_path.read_bytes())
        except FileNotFoundError:
            raise ValueError("no report for that digest in this gate home") from None
        if (
            not isinstance(prior, dict)
            or prior.get("sha256") != digest
            or prior.get("policy") != ScanPolicy.agent_document.value
            or prior.get("verdict") != Verdict.block.value
            or prior.get("policy_reason") != DOCUMENT_HOLD
            or prior.get("incomplete_reason") is not None
        ):
            raise ValueError("the last report is not a complete agent-document policy hold")

        fd = _open_regular(target)
        try:
            payload = b"".join(_bounded_chunks(fd))
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("file bytes do not match the reviewed digest")
            result = scan_bytes(
                payload,
                name=target.name,
                timeout_s=timeout_s,
                rules_dir=rules_dir,
                policy=ScanPolicy.agent_document,
            )
            refusal = release_refusal(result)
            if refusal is not None:
                raise ValueError(refusal)
            entry = target.lstat()
            if (
                result.path != target.name
                or _reject_reason(entry) is not None
                or not os.path.samestat(os.fstat(fd), entry)
                or _hash_fd(fd) != digest
            ):
                raise ValueError("file changed or its name could not be preserved during review")
        finally:
            os.close(fd)

        current = compact_report(result)
        if any(
            prior.get(field) != current[field]
            for field in ("ruleset_sha256", "findings", "engine_version", "detector_sha256")
        ):
            raise ValueError("the scan differs from the reviewed report; scan and review again")
        log = release_log(home.root)
        key = release_key(result)
        head = log.append(key, reason=reason)
        released = reviewed_result(
            replace(result, path=str(target if path else dest / target.name))
        )
        write_reports(home.reports, released, record_event=False)
        if path is None:
            try:
                os.replace(slot, dest)
            except OSError:
                write_reports(home.reports, replace(result, path=str(target)), record_event=False)
                raise
        return released, head


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
    lock_fd = _acquire_lock(home)
    try:
        with _gate_lock(home):
            recovered = _finish_pending_intake(home)
        if recovered is not None:
            reason = f" reason={recovered.incomplete_reason}" if recovered.incomplete_reason else ""
            print(f"recovered {recovered.verdict} sha256={recovered.sha256}{reason}", flush=True)
    except BaseException:
        os.close(lock_fd)
        raise
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
        os.close(lock_fd)  # Releases the watcher lock; the OS also does if the process dies.


def drain_inbox(
    home: GatePaths,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
) -> None:
    """Scan files already sitting in inbox/. A file still being written is given 0.2 s."""
    home.ensure()
    with _gate_lock(home):
        _finish_pending_intake(home)
    _drain(_InboxHandler(home, rules_dir, timeout_s, policy), home, wait=True)


def _drain(handler: "_InboxHandler", home: GatePaths, *, wait: bool) -> None:
    entries = sorted(home.inbox.iterdir())
    for path in entries:
        handler.handle(path, wait=wait)
    handler.forget_missing({str(path) for path in entries})


def _dispatch(event: object, handler: "_InboxHandler") -> None:
    path = getattr(event, "dest_path", None) or getattr(event, "src_path", None)
    if not path:
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
            # Watchdog also reports the inbox itself; only its immediate entries are intake.
            if path.parent.absolute() != self.home.inbox.absolute():
                return
            try:
                info = path.lstat()
            except OSError:
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
            reason = f" reason={result.incomplete_reason}" if result.incomplete_reason else ""
            print(f"{result.verdict} sha256={result.sha256}{reason}", flush=True)

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


@contextmanager
def _gate_lock(home: GatePaths) -> Iterator[None]:
    """Hold the gate home's intake lock. The OS releases it if the process dies."""
    fd = os.open(home.root / ".intake.lock", os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
    try:
        if sys.platform == "win32":
            while True:
                try:
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                    break
                except OSError:
                    continue  # LK_LOCK gives up after about ten seconds; keep waiting.
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
    finally:
        os.close(fd)


def _relocate(home: GatePaths, result: ScanResult) -> None:
    src = home.quarantine / result.sha256
    if result.verdict is Verdict.incomplete or not src.exists():
        return
    dest_root = home.blocked if result.verdict is Verdict.block else home.clean
    dest_root.mkdir(parents=True, exist_ok=True)
    # One slot per digest: a copy left in either folder holds an earlier verdict.
    for root in (home.clean, home.blocked):
        earlier = root / result.sha256
        if earlier.exists():
            shutil.rmtree(earlier)
    os.replace(src, dest_root / result.sha256)


def _acquire_lock(home: GatePaths) -> int:
    """Take the gate home's watcher lock and return its descriptor, held while watch runs.

    An OS lock, not a PID file: two watchers starting together cannot both take it, a crash
    releases it, and a reused PID cannot keep a new watcher out. The file holds the owner's
    PID for an operator to read; it is never trusted.
    """
    fd = os.open(home.root / ".watch.lock", os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
    try:
        if sys.platform == "win32":
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise RuntimeError("watch already running") from None
    try:
        os.ftruncate(fd, 0)
        os.write(fd, str(os.getpid()).encode())
        # An earlier release's PID file is not a lock; a stale one would only mislead.
        (home.root / ".watch.pid").unlink(missing_ok=True)
    except OSError:
        pass
    return fd


def _open_regular(src: Path) -> int:
    """Open a regular file with one link. Symlinks raise IntakeRejected and are not read."""
    if _NOFOLLOW is None:
        return _open_regular_checked(src)
    flags = os.O_RDONLY | _NOFOLLOW | _BINARY
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


def _open_regular_checked(src: Path) -> int:
    """The same contract without O_NOFOLLOW, as on Windows.

    The entry is refused from its lstat before any open, so a link is never followed and a
    placeholder is never opened. After the open, the file must be the one lstat saw, which
    refuses an entry swapped for a link in between.
    """
    before = _lstat_or_raise(src)
    reason = _reject_reason(before)
    if reason is not None:
        raise IntakeRejected(reason)
    fd = os.open(src, os.O_RDONLY | _BINARY)
    info = os.fstat(fd)
    reason = _reject_reason(info)
    if reason is None and not os.path.samestat(before, info):
        reason = "entry changed during intake"
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
    if getattr(info, "st_file_attributes", 0) & _UNREAD_ATTRIBUTES:
        return "reparse point or placeholder rejected"
    if not stat.S_ISREG(info.st_mode):
        return "not a regular file"
    if info.st_nlink != 1:
        return "hardlink rejected"
    return None


def _bounded_chunks(fd: int) -> Iterator[bytes]:
    """Bound every pass, including a file that grows after the size check."""
    if os.fstat(fd).st_size > MAX_FILE_BYTES:
        raise IntakeRejected("file exceeds 100MB")
    os.lseek(fd, 0, os.SEEK_SET)
    remaining = MAX_FILE_BYTES
    while True:
        chunk = os.read(fd, min(1024 * 1024, remaining + 1))
        if not chunk:
            return
        if len(chunk) > remaining:
            raise IntakeRejected("file exceeds 100MB")
        remaining -= len(chunk)
        yield chunk


def _hash_fd(fd: int) -> str:
    hasher = hashlib.sha256()
    for chunk in _bounded_chunks(fd):
        hasher.update(chunk)
    return hasher.hexdigest()


def _copy_fd(fd: int, dest: Path) -> None:
    # A name derived from dest could exceed NAME_MAX for a long but valid inbox name.
    partial = dest.with_name(f".partial-{secrets.token_hex(4)}")
    try:
        with partial.open("wb") as handle:
            for chunk in _bounded_chunks(fd):
                handle.write(chunk)
        os.chmod(partial, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
        os.replace(partial, dest)
    finally:
        partial.unlink(missing_ok=True)


def _same_file(fd: int, other: Path) -> bool:
    try:
        return os.path.samestat(os.fstat(fd), other.stat())
    except OSError:
        return False


def _unlink_entry(src: Path, copied: os.stat_result) -> None:
    """Remove the inbox entry only if it is still the file that was copied.

    A file renamed onto the entry after it was opened has not been scanned, so it stays in
    the inbox for its own intake.
    """
    try:
        if not os.path.samestat(src.lstat(), copied):
            return
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
    token = hashlib.sha256(f"{src.name}{stamp}".encode()).hexdigest()
    result = ScanResult(
        sha256=token,
        verdict=Verdict.incomplete,
        incomplete_reason=reason,
        path=str(dest),
        policy=policy,
    )
    write_reports(home.reports, result, stem=f"rejected-{token}")
    os.rename(src, dest)
    return result
