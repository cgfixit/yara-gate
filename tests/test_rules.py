from pathlib import Path

import pytest

from yara_gate.rules import _allowed_url, _vendor_member, compile_sources


def test_rule_download_url_allowlist() -> None:
    kept = _allowed_url("https://github.com/YARAHQ/yara-forge/releases/download/x/y.zip")
    assert kept.startswith("https://github.com/")
    assert _allowed_url("https://codeload.github.com/org/repo/tar.gz/abc").startswith("https://")
    refused = (
        "http://github.com/org/repo",
        "https://evil.example/rule.zip",
        "https://user:pass@github.com/org/repo",
        "https://github.com.evil/org/repo",
        "https://github.com:8443/org/repo",
    )
    for url in refused:
        with pytest.raises(ValueError, match="refusing rule URL"):
            _allowed_url(url)


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
