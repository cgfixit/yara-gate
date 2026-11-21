import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from yara_gate.models import ScanPolicy, Verdict
from yara_gate.quarantine import GatePaths, _acquire_lock, process_inbox_file
from yara_gate.rescan import rescan_clean
from yara_gate.samples import injection_markdown


def admit(home: GatePaths, rules: Path, data: bytes, name: str = "sample.txt") -> str:
    home.ensure()
    path = home.inbox / name
    path.write_bytes(data)
    return process_inbox_file(home, path, rules_dir=rules).sha256


def command(home: GatePaths, rules: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-c",
            "from yara_gate.cli import app; app()",
            "rescan",
            "--home",
            str(home.root),
            "--rules",
            str(rules),
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_rule_change_dry_run_and_identical_resubmission(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    attack = b"Cobalt review marker."
    bad = admit(home, rules_copy, attack)
    good = admit(home, rules_copy, b"Cobalt meeting notes.")
    before = {p.relative_to(home.root): p.read_bytes() for p in home.root.rglob("*") if p.is_file()}
    (rules_copy / "local" / "rescan_probe.yar").write_text(
        'rule rescan_probe { strings: $a="Cobalt review marker" condition: $a }'
    )
    preview = command(home, rules_copy, "--dry-run")
    assert preview.returncode == 1, preview.stderr
    assert json.loads(preview.stdout.splitlines()[-1])["newly_held"] == 1
    for p, data in before.items():
        if p.name not in {".watch.lock", ".intake.lock"}:
            assert (home.root / p).read_bytes() == data
    actual = command(home, rules_copy)
    assert actual.returncode == 1, actual.stderr
    assert (home.blocked / bad / "sample.txt").read_bytes() == attack
    assert not (home.clean / bad).exists()
    assert (home.clean / good).is_dir()
    assert json.loads((home.reports / f"{good}.json").read_text())["ruleset_sha256"]
    assert command(home, rules_copy).returncode == 0
    (rules_copy / "local" / "rescan_probe.yar").unlink()
    assert admit(home, rules_copy, attack, "again.txt") == bad
    assert (home.clean / bad / "again.txt").read_bytes() == attack
    assert not (home.blocked / bad).exists()


@pytest.mark.parametrize(
    "field", ["ruleset_sha256", "detector_sha256", "policy", "corrupt", "missing"]
)
def test_stale_report_rescanned(tmp_path: Path, rules_copy: Path, field: str) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, b"Ordinary meeting notes.")
    report = home.reports / f"{digest}.json"
    prior = json.loads(report.read_text())
    if field == "missing":
        report.unlink()
    elif field == "corrupt":
        report.write_text("{broken")
    else:
        prior[field] = "outdated"
        report.write_text(json.dumps(prior))
    results = list(rescan_clean(home, rules_dir=rules_copy))
    assert len(results) == 1 and results[0] is not None
    assert results[0].verdict is Verdict.clean
    assert list(rescan_clean(home, rules_dir=rules_copy)) == [None]


def test_advisory_and_policy_change(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, injection_markdown(), "note.md")
    assert list(rescan_clean(home, rules_dir=rules_copy))[0].verdict is Verdict.advisory
    assert command(home, rules_copy, "--policy", "agent-ingest").returncode == 1
    assert (home.blocked / digest).is_dir()
    assert command(home, rules_copy, "--policy", "default").returncode == 0
    assert (home.blocked / digest).is_dir()


def test_missing_vendor_withdraws(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, b"Ordinary notes.")
    (rules_copy / "vendor.installed.json").write_text(
        json.dumps({"installed_vendor_files": ["pack/missing.yar"]})
    )
    result = command(home, rules_copy)
    assert result.returncode == 2
    assert (home.quarantine / digest).is_dir()
    assert not (home.clean / digest).exists()
    assert (
        json.loads((home.reports / f"{digest}.json").read_text())["incomplete_reason"]
        == "installed vendor rules missing"
    )


def test_watch_lock_refuses(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, b"Ordinary notes.")
    lock = _acquire_lock(home)
    try:
        result = command(home, rules_copy)
        assert result.returncode == 2
        assert "watch already running" in result.stderr
        assert (home.clean / digest).is_dir()
    finally:
        os.close(lock)


@pytest.mark.parametrize("kind", ["changed", "symlink", "hardlink"])
def test_changed_copy_withdrawn_without_reading_link(
    tmp_path: Path, rules_copy: Path, kind: str
) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, b"Ordinary notes.")
    target = home.clean / digest / "sample.txt"
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"Outside bytes must remain untouched.")
    if kind == "changed":
        target.write_bytes(b"Changed bytes.")
    else:
        target.unlink()
        if kind == "symlink":
            try:
                target.symlink_to(outside)
            except OSError:
                pytest.skip("file symlinks unavailable")
        else:
            os.link(outside, target)
    results = list(rescan_clean(home, rules_dir=rules_copy))
    assert results[0].verdict is Verdict.incomplete
    assert results[0].sha256 == "0" * 64
    assert (home.quarantine / digest).is_dir()
    assert outside.read_bytes() == b"Outside bytes must remain untouched."
    assert not (home.clean / digest).exists()


def test_report_precedes_move(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yara_gate.rescan as module

    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, injection_markdown(), "note.md")
    original = module.write_reports

    def report(*args, **kwargs):
        assert (home.clean / digest).exists()
        assert not (home.blocked / digest).exists()
        return original(*args, **kwargs)

    monkeypatch.setattr(module, "write_reports", report)
    list(rescan_clean(home, rules_dir=rules_copy, policy=ScanPolicy.agent_ingest))
    assert (home.blocked / digest).exists()


def test_held_slots_untouched_and_collision_refused(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, injection_markdown(), "note.md")
    held = home.blocked / digest
    held.mkdir()
    (held / "retained").write_bytes(b"Retained")
    result = command(home, rules_copy, "--policy", "agent-ingest")
    assert result.returncode == 2
    assert "held slot already exists" in result.stderr
    assert (held / "retained").read_bytes() == b"Retained"
    assert (home.clean / digest).exists()


def test_report_failure_then_retry(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yara_gate.rescan as module

    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, injection_markdown(), "note.md")
    original = module.write_reports

    def fail(*args, **kwargs):
        raise OSError("synthetic report failure")

    monkeypatch.setattr(module, "write_reports", fail)
    with pytest.raises(OSError, match="synthetic report failure"):
        list(rescan_clean(home, rules_dir=rules_copy, policy=ScanPolicy.agent_ingest))
    assert (home.clean / digest / "note.md").read_bytes() == injection_markdown()
    monkeypatch.setattr(module, "write_reports", original)
    list(rescan_clean(home, rules_dir=rules_copy, policy=ScanPolicy.agent_ingest))
    assert (home.blocked / digest / "note.md").read_bytes() == injection_markdown()


def test_incomplete_precedence_and_checked_open(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from yara_gate import quarantine

    monkeypatch.setattr(quarantine, "_NOFOLLOW", None)
    home = GatePaths(tmp_path / "gate")
    bad = admit(home, rules_copy, injection_markdown(), "note.md")
    changed = admit(home, rules_copy, b"Ordinary notes.")
    (home.clean / changed / "sample.txt").write_bytes(b"Changed")
    results = list(rescan_clean(home, rules_dir=rules_copy, policy=ScanPolicy.agent_ingest))
    assert {r.verdict for r in results} == {Verdict.block, Verdict.incomplete}
    assert (home.blocked / bad).is_dir()
    assert (home.quarantine / changed).is_dir()


def test_pending_intake_and_slot_link_refused(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, b"Ordinary notes.")
    home.pending_intake.write_text("{}")
    assert command(home, rules_copy).returncode == 2
    assert (home.clean / digest).is_dir()
    home.pending_intake.unlink()
    original = home.clean / digest
    moved = tmp_path / "outside-slot"
    original.rename(moved)
    try:
        original.symlink_to(moved, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks unavailable")
    assert command(home, rules_copy).returncode == 2
    assert (moved / "sample.txt").read_bytes() == b"Ordinary notes."


def test_path_and_descriptor_timestamp_precision(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yara_gate.rescan as module

    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, injection_markdown(), "note.md")
    original = os.fstat

    class RoundedTimes:
        def __init__(self, info):
            self.info = info
            self.st_mtime_ns = info.st_mtime_ns // 1_000_000_000 * 1_000_000_000
            self.st_ctime_ns = info.st_ctime_ns // 1_000_000_000 * 1_000_000_000

        def __getattr__(self, name):
            return getattr(self.info, name)

    monkeypatch.setattr(module.os, "fstat", lambda fd: RoundedTimes(original(fd)))
    results = list(rescan_clean(home, rules_dir=rules_copy, policy=ScanPolicy.agent_ingest))
    assert results[0].verdict is Verdict.block
    assert (home.blocked / digest).exists()


def test_mutation_during_scan_is_incomplete(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import yara_gate.rescan as module

    home = GatePaths(tmp_path / "gate")
    digest = admit(home, rules_copy, injection_markdown(), "note.md")
    original = module.scan_bytes

    def scan(data, **kwargs):
        result = original(data, **kwargs)
        if data:
            (home.clean / digest / "note.md").write_bytes(b"Changed during scan.")
        return result

    monkeypatch.setattr(module, "scan_bytes", scan)
    results = list(rescan_clean(home, rules_dir=rules_copy))
    assert results[0].verdict is Verdict.incomplete
    assert (home.quarantine / digest).exists()


@pytest.mark.parametrize(
    ("error", "message"),
    [(BrokenPipeError, None), (OSError, "incomplete: output unwritable (OSError)")],
)
@pytest.mark.parametrize("line", ['{"dry_run": false, "sha256"', '{"dry_run": false, "rescanned"'])
def test_output_that_cannot_be_written_is_exit_2_not_1(
    tmp_path: Path,
    rules_copy: Path,
    monkeypatch: pytest.MonkeyPatch,
    error: type[OSError],
    message: str | None,
    line: str,
) -> None:
    import typer
    from typer.testing import CliRunner

    from yara_gate.cli import app

    home = GatePaths(tmp_path / "gate")
    admit(home, rules_copy, b"hello\n")
    real = typer.echo

    def echo(text: object = None, *args: object, **kwargs: Any) -> None:
        # A copy's line, or the summary: the reader of stdout has gone, or the device is full.
        if isinstance(text, str) and text.startswith(line):
            raise error(32 if error is BrokenPipeError else 28, "refused")
        real(text, *args, **kwargs)

    monkeypatch.setattr(typer, "echo", echo)
    # Another policy makes the stored report stale, so the copy is scanned and printed.
    result = CliRunner().invoke(
        app,
        [
            "rescan",
            "--home",
            str(home.root),
            "--rules",
            str(rules_copy),
            "--policy",
            "agent-ingest",
        ],
    )
    assert result.exit_code == 2
    assert (message in result.stderr) if message else result.stderr == ""
