import io
import re
import shutil
import zipfile
from pathlib import Path

import yara_x

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


def test_hunt_rejects_traversal_sha(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    digest = "b" * 64
    escaped = home.clean / digest
    escaped.mkdir(parents=True)
    (escaped / "note.txt").write_text("not in blocked\n", encoding="utf-8")
    try:
        hunt(home, f"../clean/{digest}", reason="confirmed", scope=tmp_path, rules_dir=rules_copy)
    except ValueError as exc:
        assert str(exc) == "invalid sha256"
    else:
        raise AssertionError("traversal sha was accepted")
    assert (escaped / "note.txt").is_file()


def test_hunt_rejects_non_hex_sha(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    try:
        hunt(home, "not-a-sha", reason="confirmed", scope=tmp_path, rules_dir=rules_copy)
    except ValueError as exc:
        assert str(exc) == "invalid sha256"
    else:
        raise AssertionError("non-hex sha was accepted")


def test_hunt_persists_reason_and_scope_in_meta(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    src = home.inbox / "eicar.com"
    src.write_bytes(eicar_bytes())
    blocked = process_inbox_file(home, src, rules_dir=rules_copy)
    scope = tmp_path / "scope"
    scope.mkdir()
    rule_path, _hits = hunt(
        home,
        blocked.sha256,
        reason='quoted "marker"\nsecond line',
        scope=scope,
        rules_dir=rules_copy,
        confirmed_by="reviewer",
    )
    text = rule_path.read_text(encoding="utf-8")
    assert 'reason = "quoted \\"marker\\" second line"' in text
    assert f'confirmed_sha256 = "{blocked.sha256}"' in text
    assert f'scope = "{scope}"' in text
    assert 'confirmed_by = "reviewer"' in text
    assert 'created = "' in text
    assert "\nsecond line" not in text


def test_hunt_meta_truncates_before_escaping(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    src = home.inbox / "eicar.com"
    src.write_bytes(eicar_bytes())
    blocked = process_inbox_file(home, src, rules_dir=rules_copy)
    scope = tmp_path / "scope"
    scope.mkdir()
    cases = (
        (("a" * 299) + "\\", ("a" * 299) + "\\\\"),
        ('say "hello"\nnext line\x01', 'say \\"hello\\" next line'),
        ("déjà vu — 東京", "déjà vu — 東京"),
    )
    for reason, expected in cases:
        rule_path, _hits = hunt(
            home,
            blocked.sha256,
            reason=reason,
            scope=scope,
            rules_dir=rules_copy,
        )
        text = rule_path.read_text(encoding="utf-8")
        yara_x.compile(text)
        assert f'reason = "{expected}"' in text
        assert "\x01" not in text


def test_all_local_rules_have_required_meta() -> None:
    required = {"author", "description", "severity", "verdict_on_match", "reference"}
    root = Path(__file__).resolve().parents[1] / "rules" / "local"
    for path in sorted(root.glob("*.yar")):
        text = path.read_text(encoding="utf-8")
        if 'status = "candidate"' in text:
            continue
        meta = text.split("strings:", 1)[0]
        pairs = dict(re.findall(r'(?m)^\s*(\w+)\s*=\s*"([^"]*)"', meta))
        missing = required - pairs.keys()
        assert not missing, path.name
        assert pairs["severity"] == pairs["verdict_on_match"], path.name


def test_hunt_candidate_zero_hits_on_grown_benign_corpus(tmp_path: Path, rules_copy: Path) -> None:
    benign = tmp_path / "benign"
    shutil.copytree(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "benign", benign)
    (benign / "note.pdf").write_bytes(
        b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n"
    )
    document = io.BytesIO()
    with zipfile.ZipFile(document, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types></Types>")
        archive.writestr("word/document.xml", "<w:document><w:t>hello notes</w:t></w:document>")
    (benign / "note.docx").write_bytes(document.getvalue())
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    src = home.inbox / "eicar.com"
    src.write_bytes(eicar_bytes())
    blocked = process_inbox_file(home, src, rules_dir=rules_copy)
    scope = tmp_path / "scope"
    scope.mkdir()
    rule_path, hits = hunt(
        home,
        blocked.sha256,
        reason="synthetic eicar",
        scope=scope,
        rules_dir=rules_copy,
        benign_dir=benign,
    )
    assert rule_path.is_file()
    assert hits == []
    assert (benign / "long.md").is_file()
    assert (benign / "note.pdf").is_file()
    assert (benign / "note.docx").is_file()


def test_hunt_requires_a_reason_and_a_blocked_file(tmp_path: Path, rules_copy: Path) -> None:
    home = GatePaths(tmp_path / "gate")
    home.ensure()
    try:
        hunt(home, "a" * 64, reason="   ", scope=tmp_path, rules_dir=rules_copy)
    except ValueError as exc:
        assert "reason" in str(exc)
    else:
        raise AssertionError("empty reason was accepted")
