import hashlib
import os
import stat
from pathlib import Path

from yara_gate.models import ScanPolicy, Verdict, exit_code
from yara_gate.quarantine import GatePaths, _InboxHandler, drain_inbox, process_inbox_file
from yara_gate.samples import EICAR, bidi_markdown, clean_text, eicar_bytes, injection_markdown


def _home(tmp_path: Path) -> GatePaths:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    return home


def test_gate_directories_are_owner_only(tmp_path: Path) -> None:
    home = _home(tmp_path)
    folders = (home.root, home.inbox, home.quarantine, home.clean, home.blocked, home.reports)
    for folder in folders:
        assert stat.S_IMODE(folder.stat().st_mode) == 0o700


def test_clean_lands_in_clean_with_reports(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    src = home.inbox / "notes.txt"
    src.write_bytes(clean_text())
    src.chmod(0o755)
    result = process_inbox_file(home, src, rules_dir=rules_copy)
    slot = home.clean / result.sha256
    assert result.verdict is Verdict.clean
    assert exit_code(result) == 0
    assert not src.exists()
    assert slot.is_dir()
    stored = next(slot.iterdir())
    assert stat.S_IMODE(stored.stat().st_mode) & 0o111 == 0
    assert (home.reports / f"{result.sha256}.sarif").is_file()
    assert (home.reports / f"{result.sha256}.json").is_file()
    assert EICAR.decode() not in (home.reports / f"{result.sha256}.json").read_text()


def test_block_lands_in_blocked_and_advisory_in_clean(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    blocked_src = home.inbox / "eicar.com"
    blocked_src.write_bytes(eicar_bytes())
    blocked = process_inbox_file(home, blocked_src, rules_dir=rules_copy)
    assert blocked.verdict is Verdict.block
    assert (home.blocked / blocked.sha256).is_dir()
    assert not (home.clean / blocked.sha256).exists()

    noted_src = home.inbox / "note.md"
    noted_src.write_bytes(injection_markdown())
    noted = process_inbox_file(home, noted_src, rules_dir=rules_copy)
    assert noted.verdict is Verdict.advisory
    assert (home.clean / noted.sha256).is_dir()


def test_bidi_blocks(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    src = home.inbox / "hidden.md"
    src.write_bytes(bidi_markdown())
    result = process_inbox_file(home, src, rules_dir=rules_copy)
    assert result.verdict is Verdict.block
    assert (home.blocked / result.sha256).is_dir()


def test_oversize_stays_in_quarantine(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    src = home.inbox / "big.bin"
    src.touch()
    with src.open("wb") as handle:
        handle.truncate(100 * 1024 * 1024 + 1)
    result = process_inbox_file(home, src, rules_dir=rules_copy)
    assert result.verdict is Verdict.incomplete
    assert exit_code(result) == 2
    assert (home.quarantine / result.sha256).is_dir()
    assert not (home.clean / result.sha256).exists()
    assert not (home.blocked / result.sha256).exists()


def test_second_drop_of_the_same_bytes_converges(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    first = home.inbox / "a.txt"
    first.write_bytes(clean_text())
    process_inbox_file(home, first, rules_dir=rules_copy)
    second = home.inbox / "b.txt"
    second.write_bytes(clean_text())
    again = process_inbox_file(home, second, rules_dir=rules_copy)
    assert not second.exists()
    assert again.verdict is Verdict.clean
    assert again.sha256 == hashlib.sha256(clean_text()).hexdigest()


def test_drain_scans_files_already_in_the_inbox(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    src = home.inbox / "notes.txt"
    src.write_bytes(clean_text())
    drain_inbox(home, rules_dir=rules_copy)
    digest = hashlib.sha256(clean_text()).hexdigest()
    assert (home.clean / digest).is_dir()
    assert not src.exists()


def test_handler_ignores_dotfiles(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    hidden = home.inbox / ".secret"
    hidden.write_bytes(clean_text())
    _InboxHandler(home, rules_copy, 30).handle(hidden)
    assert hidden.is_file()
    assert list(home.clean.iterdir()) == []


def _rejected_report(home: GatePaths, result_sha: str) -> str:
    return (home.reports / f"rejected-{result_sha}.json").read_text(encoding="utf-8")


def test_symlink_in_inbox_is_rejected_not_copied(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    outside = tmp_path / "outside.txt"
    marker = "OUTSIDE-TARGET-do-not-copy"
    outside.write_text(marker, encoding="utf-8")
    link = home.inbox / "link.txt"
    link.symlink_to(outside)
    drain_inbox(home, rules_dir=rules_copy)
    assert outside.read_text(encoding="utf-8") == marker
    assert list(home.clean.iterdir()) == []
    assert list(home.blocked.iterdir()) == []
    assert not link.exists()
    rejected = list((home.quarantine / "_rejected").iterdir())
    assert len(rejected) == 1
    assert rejected[0].is_symlink()
    reports = list(home.reports.glob("rejected-*.json"))
    assert len(reports) == 1
    body = reports[0].read_text(encoding="utf-8")
    assert "symlink rejected" in body
    assert marker not in body
    assert str(outside) not in body


def test_long_inbox_name_is_quarantined_and_scanned(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    src = home.inbox / ("a" * 251 + ".txt")
    src.write_bytes(clean_text())
    result = process_inbox_file(home, src, rules_dir=rules_copy)
    assert result.verdict is Verdict.clean
    assert not src.exists()
    assert [item.name for item in (home.clean / result.sha256).iterdir()] == [src.name]


def test_long_symlink_name_is_rejected(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    link = home.inbox / ("\u00e9" * 120 + ".txt")
    link.symlink_to(outside)
    result = process_inbox_file(home, link, rules_dir=rules_copy)
    assert result.incomplete_reason == "symlink rejected"
    assert not link.exists()
    rejected = list((home.quarantine / "_rejected").iterdir())
    assert len(rejected) == 1
    assert rejected[0].is_symlink()
    assert len(os.fsencode(rejected[0].name)) <= 255


def test_dangling_symlink_is_rejected_with_report(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    link = home.inbox / "missing.txt"
    link.symlink_to(tmp_path / "no-such-file")
    result = process_inbox_file(home, link, rules_dir=rules_copy)
    assert result.verdict is Verdict.incomplete
    assert exit_code(result) == 2
    assert result.incomplete_reason == "symlink rejected"
    assert not link.exists()
    body = _rejected_report(home, result.sha256)
    assert "symlink rejected" in body
    assert "no-such-file" not in body


def test_hardlink_in_inbox_is_rejected(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    outside = tmp_path / "outside.txt"
    marker = "HARDLINK-TARGET-do-not-copy"
    outside.write_text(marker, encoding="utf-8")
    link = home.inbox / "hard.txt"
    os.link(outside, link)
    result = process_inbox_file(home, link, rules_dir=rules_copy)
    assert result.verdict is Verdict.incomplete
    assert result.incomplete_reason == "hardlink rejected"
    assert exit_code(result) == 2
    assert outside.read_text(encoding="utf-8") == marker
    assert list(home.clean.iterdir()) == []
    assert marker not in _rejected_report(home, result.sha256)


def test_fifo_in_inbox_is_rejected(tmp_path: Path, rules_copy: Path) -> None:
    if not hasattr(os, "mkfifo"):
        return
    home = _home(tmp_path)
    fifo = home.inbox / "pipe.fifo"
    os.mkfifo(fifo)
    result = process_inbox_file(home, fifo, rules_dir=rules_copy)
    assert result.incomplete_reason == "not a regular file"
    assert exit_code(result) == 2
    assert list(home.clean.iterdir()) == []
    assert not fifo.exists()


def test_regular_file_intake_unchanged(tmp_path: Path, rules_copy: Path) -> None:
    home = _home(tmp_path)
    src = home.inbox / "notes.txt"
    src.write_bytes(clean_text())
    result = process_inbox_file(home, src, rules_dir=rules_copy)
    assert result.verdict is Verdict.clean
    assert exit_code(result) == 0
    assert (home.clean / result.sha256 / "notes.txt").read_bytes() == clean_text()
    assert not src.exists()


def test_dotfile_rescan_under_a_stricter_policy_leaves_clean(
    tmp_path: Path, rules_copy: Path
) -> None:
    home = _home(tmp_path)
    first = home.inbox / ".note.md"
    first.write_bytes(injection_markdown())
    assert process_inbox_file(home, first, rules_dir=rules_copy).verdict is Verdict.advisory
    again = home.inbox / ".note.md"
    again.write_bytes(injection_markdown())
    result = process_inbox_file(home, again, rules_dir=rules_copy, policy=ScanPolicy.agent_ingest)
    assert result.verdict is Verdict.block
    assert not any(home.clean.rglob(".note.md"))
    assert len(list(home.blocked.rglob(".note.md"))) == 1
