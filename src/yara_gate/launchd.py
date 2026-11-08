"""Write a launchd plist for `yara-gate watch`. This module does not load the agent."""

import plistlib
import shutil
import sys
from pathlib import Path


def console_binary() -> Path:
    argv = Path(sys.argv[0])
    if argv.is_file():
        return argv.resolve()
    found = shutil.which("yara-gate")
    if found is None:
        raise RuntimeError("yara-gate binary not found")
    return Path(found)


def write_launch_agent(
    dest: Path, *, home: Path, binary: Path | None = None, log_dir: Path | None = None
) -> Path:
    """Write an unloaded watch agent. The plist has no environment secrets.

    launchd restarts the watcher when it exits non-zero, including a start refused because
    another watcher holds the gate home's lock, at most every ``ThrottleInterval`` seconds.
    """
    program = binary or console_binary()
    log_dir = log_dir or Path.home() / "Library" / "Logs" / "yara-gate"
    payload = {
        "Label": "com.cgfixit.yaragate.watch",
        "ProgramArguments": [str(program), "watch", "--home", str(home)],
        "RunAtLoad": True,
        # Restart after a crash or a failed start; a clean stop (exit 0) stays stopped.
        "KeepAlive": {"SuccessfulExit": False},
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardOutPath": str(log_dir / "watch.log"),
        "StandardErrorPath": str(log_dir / "watch.log"),
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    # launchd opens the log paths but does not create their directory.
    log_dir.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as handle:
        plistlib.dump(payload, handle, fmt=plistlib.FMT_XML)
    return dest
