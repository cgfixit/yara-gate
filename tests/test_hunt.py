from pathlib import Path

from yara_gate.hunt import hunt
from yara_gate.models import Verdict
from yara_gate.quarantine import GatePaths, process_inbox_file
from yara_gate.rules import compile_sources, promote
from yara_gate.samples import eicar_bytes
from yara_gate.scanner import scan_file


def test_hunt_on_confirmed_eicar(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    src = home.inbox / "eicar.com"
    src.write_bytes(eicar_bytes())
    blocked = process_inbox_file(home, src, rules_dir=rules_copy)
    assert blocked.verdict is Verdict.block
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "copy.com").write_bytes(eicar_bytes())
    (scope / "ok.txt").write_text("ordinary notes about a meeting\n", encoding="utf-8")
    rule_path, hits = hunt(
        home,
        blocked.sha256,
        reason="selftest confirmed eicar",
        scope=scope,
        rules_dir=rules_copy,
    )
    text = rule_path.read_text(encoding="utf-8")
    assert 'status = "candidate"' in text
    assert any(path.name == "copy.com" for path in hits)
    assert all(path.name != "ok.txt" for path in hits)
    _rules, _skipped, error, _compiled, _skip = compile_sources(rules_copy)
    assert error is None
    copy = tmp_path / "again.com"
    copy.write_bytes(eicar_bytes())
    before = scan_file(copy, rules_dir=rules_copy)
    assert all(not item.rule_id.startswith("hunt_") for item in before.findings)
    promote(blocked.sha256[:12], rules_copy)
    after = scan_file(copy, rules_dir=rules_copy)
    hunt_hits = [item for item in after.findings if item.rule_id.startswith("hunt_")]
    assert hunt_hits
    assert hunt_hits[0].severity.value == "block"


def test_hunt_requires_a_reason_and_a_blocked_file(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    try:
        hunt(home, "a" * 64, reason="   ", scope=tmp_path, rules_dir=rules_copy)
    except ValueError as exc:
        assert "reason" in str(exc)
    else:
        raise AssertionError("empty reason was accepted")
