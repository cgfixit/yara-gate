from pathlib import Path

from yara_gate.rules import _vendor_member, compile_sources


def test_vendor_member_rejects_parent_segments(tmp_path: Path) -> None:
    dest = tmp_path / "vendor"
    dest.mkdir()
    kept = _vendor_member(dest, "repo-sha/yara/pack/rule.yar", "yara")
    assert kept == dest / "pack" / "rule.yar"
    assert _vendor_member(dest, "repo-sha/yara/../../etc/passwd.yar", "yara") is None
    assert _vendor_member(dest, "repo-sha/other/rule.yar", "yara") is None
    assert _vendor_member(dest, "repo-sha/yara/notes.md", "yara") is None


def test_whole_set_failure(tmp_path: Path) -> None:
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "bad.yar").write_text(
        "rule nope { condition: not_a_real_identifier }\n",
        encoding="utf-8",
    )
    compiled, skipped, error, count, skip_count = compile_sources(rules)
    assert compiled is None
    assert error == "no rules compiled"
    assert count == 0
    assert skip_count == 1
    assert skipped
    assert (rules / "vendor" / "SKIPPED.md").is_file()
