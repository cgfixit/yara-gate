"""The sync-folder example must read the entry it listed, never what a later link points at."""

import importlib.util
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
MARKER = "OUTSIDE-FOLDER-INERT-MARKER"


def _example() -> ModuleType:
    path = ROOT / "docs" / "examples" / "sync_folder_gate.py"
    spec = importlib.util.spec_from_file_location("sync_folder_gate", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _to_link(victim: Path, outside: Path) -> None:
    victim.unlink()
    victim.symlink_to(outside / "note.txt")


def _parent_to_link(victim: Path, outside: Path) -> None:
    shutil.rmtree(victim.parent)
    victim.parent.symlink_to(outside, target_is_directory=True)


def _to_fifo(victim: Path, outside: Path) -> None:
    victim.unlink()
    os.mkfifo(victim)


def _vanish(victim: Path, outside: Path) -> None:
    victim.unlink()


@pytest.mark.skipif(os.name == "nt", reason="these swaps use POSIX links and FIFOs")
@pytest.mark.parametrize("beneath", [True, False], ids=["openat", "lstat-then-open"])
@pytest.mark.parametrize("swap", [_to_link, _parent_to_link, _to_fifo, _vanish])
def test_an_entry_swapped_after_listing_is_not_read(
    tmp_path: Path,
    rules_copy: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    swap: Callable[[Path, Path], None],
    beneath: bool,
) -> None:
    example = _example()
    if not beneath:
        # The path Windows takes: no O_NOFOLLOW and no dir_fd.
        monkeypatch.setattr(example, "_OPEN_BENEATH", False)
    sync = tmp_path / "sync"
    victim = sync / "sub" / "note.txt"
    victim.parent.mkdir(parents=True)
    victim.write_text("an ordinary note\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "note.txt").write_text(MARKER + "\n", encoding="utf-8")
    settled_long_ago = victim.stat().st_mtime - 60
    os.utime(victim, (settled_long_ago, settled_long_ago))
    settled = example._settled

    def swap_after_the_listing(path: Path, info: os.stat_result) -> bool:
        ok = settled(path, info)
        swap(victim, outside)
        return bool(ok)

    monkeypatch.setattr(example, "_settled", swap_after_the_listing)
    home = tmp_path / "gate"
    argv = ["sync_folder_gate.py", str(sync), str(home), "--rules", str(rules_copy)]
    monkeypatch.setattr(sys, "argv", argv)

    assert example.main() == 0
    log = capsys.readouterr().out
    assert "skip\t'sub/note.txt'\t" in log
    assert "allowed" not in log and "held" not in log
    # Nothing was copied anywhere: not into the read set, not into review, not left in staging.
    for name in ("allowed", "held", "staging"):
        assert not any((home / name).iterdir())
    assert (outside / "note.txt").read_text(encoding="utf-8") == MARKER + "\n"


def test_a_settled_regular_file_is_still_staged_and_allowed(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    example = _example()
    sync = tmp_path / "sync"
    (sync / "sub").mkdir(parents=True)
    note = sync / "sub" / "note.txt"
    note.write_text("an ordinary note\n", encoding="utf-8")
    settled_long_ago = note.stat().st_mtime - 60
    os.utime(note, (settled_long_ago, settled_long_ago))
    home = tmp_path / "gate"
    argv = ["sync_folder_gate.py", str(sync), str(home), "--rules", str(rules_copy)]
    monkeypatch.setattr(sys, "argv", argv)

    assert example.main() == 0
    copies = [path for path in (home / "allowed").rglob("note.txt")]
    assert len(copies) == 1
    assert copies[0].read_text(encoding="utf-8") == "an ordinary note\n"
    assert note.read_text(encoding="utf-8") == "an ordinary note\n"


def test_staging_retries_a_regular_replacement_on_the_next_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    example = _example()
    # Exercise the same fallback on POSIX that runs natively on Windows.
    monkeypatch.setattr(example, "_OPEN_BENEATH", False)
    sync = tmp_path / "sync"
    sync.mkdir()
    note = sync / "note.txt"
    note.write_bytes(b"Monday")
    updated = sync / "updated.tmp"
    updated.write_bytes(b"Friday")
    staging = tmp_path / "staging"
    staging.mkdir()
    lstat = Path.lstat

    def finish_sync(path: Path) -> os.stat_result:
        info = lstat(path)
        if path == note:
            updated.replace(note)
        return info

    with monkeypatch.context() as patch:
        patch.setattr(Path, "lstat", finish_sync)
        with pytest.raises(example._NotRead):
            example._stage(sync, note, staging)

    assert list(staging.iterdir()) == []
    staged = example._stage(sync, note, staging)
    assert staged is not None and staged.read_bytes() == b"Friday"
