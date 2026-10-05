import hashlib
import stat
from pathlib import Path

from yara_gate.models import Verdict, exit_code
from yara_gate.quarantine import GatePaths, _InboxHandler, drain_inbox, process_inbox_file
from yara_gate.samples import EICAR, bidi_markdown, clean_text, eicar_bytes, injection_markdown


def _home(tmp_path: Path) -> GatePaths:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    return home


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
