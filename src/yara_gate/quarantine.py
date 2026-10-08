"""Drop-folder intake. Downstream readers only see clean/."""

import os
import shutil
import stat
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from yara_gate.models import ScanPolicy, ScanResult, Verdict
from yara_gate.report import write_reports
from yara_gate.scanner import hash_file, scan_file


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


def intake(home: GatePaths, src: Path) -> Path:
    """Copy a file into quarantine/<sha256>/ and strip the executable bit."""
    home.ensure()
    digest = hash_file(src)
    existing = _existing_slot(home, digest)
    if existing is not None:
        quarantine = home.quarantine / digest
        if existing.parent != quarantine:
            # Every rescan must pass through quarantine, including a stricter policy.
            os.replace(existing.parent, quarantine)
            existing = quarantine / existing.name
        if src.resolve() != existing.resolve():
            src.unlink()
        return existing
    slot = home.quarantine / digest
    slot.mkdir(parents=True, exist_ok=True)
    dest = slot / src.name
    partial = slot / f".{src.name}.partial"
    shutil.copyfile(src, partial)
    os.chmod(partial, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    os.replace(partial, dest)
    if src.resolve() != dest.resolve():
        src.unlink()
    return dest


def process_inbox_file(
    home: GatePaths,
    src: Path,
    *,
    rules_dir: Path | None = None,
    timeout_s: int = 30,
    policy: ScanPolicy = ScanPolicy.default,
) -> ScanResult:
    placed = intake(home, src)
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
    try:
        while True:
            _drain(handler, home)
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
    """Scan files already sitting in inbox/."""
    _drain(_InboxHandler(home, rules_dir, timeout_s, policy), home)


def _drain(handler: "_InboxHandler", home: GatePaths) -> None:
    for path in sorted(home.inbox.iterdir()):
        handler.handle(path)


def _dispatch(event: object, handler: "_InboxHandler") -> None:
    path = getattr(event, "dest_path", None) or getattr(event, "src_path", None)
    if not path or getattr(event, "is_directory", False):
        return
    handler.handle(Path(str(path)))


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

    def handle(self, path: Path) -> None:
        with self._lock:
            if path.name.startswith(".") or not path.is_file():
                return
            if not _size_settled(path):
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


def _size_settled(path: Path) -> bool:
    try:
        first = path.stat().st_size
        time.sleep(0.2)
        return path.is_file() and path.stat().st_size == first
    except OSError:
        return False


def _existing_slot(home: GatePaths, digest: str) -> Path | None:
    for root in (home.clean, home.blocked, home.quarantine):
        slot = root / digest
        if not slot.is_dir():
            continue
        files = [
            item for item in slot.iterdir() if item.is_file() and not item.name.startswith(".")
        ]
        if files:
            return files[0]
    return None


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
