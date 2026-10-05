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


def write_launch_agent(dest: Path, *, home: Path, binary: Path | None = None) -> Path:
    """Write an unloaded watch agent. The plist has no environment secrets."""
    program = binary or console_binary()
    log_dir = Path.home() / "Library" / "Logs" / "yara-gate"
    payload = {
        "Label": "com.cgfixit.yaragate.watch",
        "ProgramArguments": [str(program), "watch", "--home", str(home)],
        "RunAtLoad": True,
        "KeepAlive": False,
        "ThrottleInterval": 10,
        "ProcessType": "Background",
        "StandardOutPath": str(log_dir / "watch.log"),
        "StandardErrorPath": str(log_dir / "watch.log"),
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("wb") as handle:
        plistlib.dump(payload, handle, fmt=plistlib.FMT_XML)
    return dest
