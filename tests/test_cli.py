import subprocess
from pathlib import Path

from yara_gate.samples import clean_text, eicar_bytes, injection_markdown

ROOT = Path(__file__).resolve().parents[1]


def _run(home: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["yara-gate", *args, "--home", str(home)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def test_version() -> None:
    proc = subprocess.run(
        ["yara-gate", "--version"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == "yara-gate 0.1.0"


def test_rules_update_refuses_without_the_flag() -> None:
    proc = subprocess.run(
        ["yara-gate", "rules", "update"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "allow-network" in proc.stderr


def test_scan_exit_codes(tmp_path: Path) -> None:
    home = tmp_path / "gate"
    clean = tmp_path / "notes.txt"
    clean.write_bytes(clean_text())
    noted = tmp_path / "note.md"
    noted.write_bytes(injection_markdown())
    blocked = tmp_path / "eicar.com"
    blocked.write_bytes(eicar_bytes())
    missing = tmp_path / "nope.txt"
    clean_proc = _run(home, "scan", str(clean))
    noted_proc = _run(home, "scan", str(noted))
    blocked_proc = _run(home, "scan", str(blocked))
    missing_proc = _run(home, "scan", str(missing))
    assert clean_proc.returncode == 0
    assert "clean" in clean_proc.stdout
    assert noted_proc.returncode == 0
    assert "advisory" in noted_proc.stdout
    assert blocked_proc.returncode == 1
    assert "block" in blocked_proc.stdout
    assert missing_proc.returncode == 2
    assert clean.is_file()
    assert blocked.is_file()
