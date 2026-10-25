import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

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
    assert proc.stdout.strip() == "yara-gate 0.2.0"


def test_cli_scan_of_inbox_symlink_exits_2(tmp_path: Path) -> None:
    home = tmp_path / "gate"
    inbox = home / "inbox"
    inbox.mkdir(parents=True)
    outside = tmp_path / "outside.txt"
    outside.write_text("secret-target", encoding="utf-8")
    link = inbox / "link.txt"
    link.symlink_to(outside)
    rules = tmp_path / "rules"
    local = rules / "local"
    local.mkdir(parents=True)
    (local / "ok.yar").write_text(
        "rule ok { condition: false }\n",
        encoding="utf-8",
    )
    proc = _run(home, "scan", str(link), "--rules", str(rules))
    assert proc.returncode == 2
    assert "symlink rejected" in proc.stdout
    assert "secret-target" not in proc.stdout
    assert "secret-target" not in proc.stderr
    assert outside.read_text(encoding="utf-8") == "secret-target"
    assert not any((home / "clean").glob("*"))


def test_dir_scan_does_not_follow_symlinks(tmp_path: Path) -> None:
    home = tmp_path / "gate"
    home.mkdir()
    folder = tmp_path / "folder"
    folder.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("secret-target", encoding="utf-8")
    (folder / "link.txt").symlink_to(outside)
    (folder / "plain.txt").write_text("hello\n", encoding="utf-8")
    rules = tmp_path / "rules"
    local = rules / "local"
    local.mkdir(parents=True)
    (local / "ok.yar").write_text("rule ok { condition: false }\n", encoding="utf-8")
    proc = _run(home, "scan", str(folder), "--rules", str(rules))
    assert proc.returncode == 2
    assert "symlink not followed" in proc.stdout
    assert "secret-target" not in proc.stdout
    assert outside.read_text(encoding="utf-8") == "secret-target"


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


def _false_rules(tmp_path: Path) -> Path:
    rules = tmp_path / "rules"
    (rules / "local").mkdir(parents=True)
    (rules / "local" / "ok.yar").write_text("rule ok { condition: false }\n", encoding="utf-8")
    return rules


def test_dir_scan_reports_a_symlinked_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "eicar.com").write_bytes(eicar_bytes())
    rules = _false_rules(tmp_path)
    folder = tmp_path / "folder"
    folder.mkdir()
    (folder / "linkdir").symlink_to(outside, target_is_directory=True)
    proc = _run(tmp_path / "gate", "scan", str(folder), "--rules", str(rules))
    assert proc.returncode == 2
    assert "symlink not followed" in proc.stdout

    home = tmp_path / "gate2"
    (home / "inbox").mkdir(parents=True)
    link = home / "inbox" / "linkdir"
    link.symlink_to(outside, target_is_directory=True)
    proc = _run(home, "scan", str(home / "inbox"), "--rules", str(rules))
    assert proc.returncode == 2
    assert "symlink rejected" in proc.stdout
    assert not link.is_symlink()
    assert (outside / "eicar.com").read_bytes() == eicar_bytes()


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads a mode 000 directory")
def test_dir_scan_reports_an_unreadable_directory(tmp_path: Path) -> None:
    folder = tmp_path / "folder"
    hidden = folder / "sub"
    hidden.mkdir(parents=True)
    (hidden / "eicar.com").write_bytes(eicar_bytes())
    (folder / "plain.txt").write_bytes(clean_text())
    hidden.chmod(0)
    try:
        proc = _run(tmp_path / "gate", "scan", str(folder), "--rules", str(_false_rules(tmp_path)))
    finally:
        hidden.chmod(stat.S_IRWXU)
    assert proc.returncode == 2
    assert "directory not readable" in proc.stdout


def test_cli_import_does_not_load_the_scanner() -> None:
    """--version, rules, and demo start without compiling anything (issue #44)."""
    code = (
        "import sys, yara_gate.cli\n"
        "loaded = sorted(m for m in sys.modules if m.startswith(('yara_gate.', 'yara_x', "
        "'urllib.request', 'importlib.metadata')))\n"
        "print(' '.join(loaded))\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    ).stdout.split()
    assert "yara_gate.cli" in out
    for heavy in ("yara_gate.scanner", "yara_gate.rules", "yara_gate.quarantine", "yara_x"):
        assert heavy not in out, out


def test_package_exports_resolve_lazily() -> None:
    code = (
        "import sys, yara_gate\n"
        "assert 'yara_gate.scanner' not in sys.modules\n"
        "yara_gate.scan_bytes, yara_gate.scan_file, yara_gate.ScanResult\n"
        "assert 'yara_gate.scanner' in sys.modules\n"
        "from yara_gate.rules import _PinnedRedirect\n"
        "import yara_gate.rules\n"
        "assert _PinnedRedirect is yara_gate.rules._PinnedRedirect\n"
        "try:\n"
        "    yara_gate.nothing\n"
        "except AttributeError:\n"
        "    print('ok')\n"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "ok"
