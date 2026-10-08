import hashlib
import io
import urllib.request
import zipfile
from pathlib import Path

import pytest

from yara_gate.rules import (
    PackPin,
    RulesLock,
    _allowed_url,
    _PinnedRedirect,
    _vendor_member,
    compile_sources,
    install_packs,
    save_lock,
    update_packs,
)


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


def _kept_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("kept.yar", "rule kept { condition: false }\n")
    return buffer.getvalue()


def _rules_tree(tmp_path: Path) -> Path:
    root = tmp_path / "rules"
    vendor = root / "vendor"
    vendor.mkdir(parents=True)
    (vendor / "retained.yar").write_text("rule retained { condition: false }\n", encoding="utf-8")
    (vendor / "SKIPPED.md").write_text("keep\n", encoding="utf-8")
    (root / "local").mkdir()
    (root / "local" / "local.yar").write_text(
        "rule local_ok { condition: false }\n", encoding="utf-8"
    )
    return root


def test_update_failure_keeps_existing_vendor(tmp_path: Path) -> None:
    root = _rules_tree(tmp_path)
    retained = (root / "vendor" / "retained.yar").read_bytes()
    skipped = (root / "vendor" / "SKIPPED.md").read_bytes()

    def transport(_url: str) -> bytes:
        raise ValueError("refusing rule URL")

    with pytest.raises(ValueError, match="refusing rule URL"):
        update_packs(root, transport=transport)
    assert (root / "vendor" / "retained.yar").read_bytes() == retained
    assert (root / "vendor" / "SKIPPED.md").read_bytes() == skipped
    assert list(root.glob(".staging-*")) == []


def test_install_verifies_lock_sha256_and_keeps_old_on_mismatch(tmp_path: Path) -> None:
    root = _rules_tree(tmp_path)
    blob = _kept_zip()
    save_lock(
        RulesLock(
            packs=[
                PackPin(
                    name="yara-forge-core",
                    url="https://github.com/YARAHQ/yara-forge/releases/download/x/core.zip",
                    pin="x",
                    sha256="0" * 64,
                )
            ]
        ),
        root,
    )
    retained = (root / "vendor" / "retained.yar").read_bytes()
    with pytest.raises(ValueError, match="sha256 mismatch"):
        install_packs(root, transport=lambda _url: blob)
    assert (root / "vendor" / "retained.yar").read_bytes() == retained


def test_redirect_to_disallowed_host_is_refused() -> None:
    handler = _PinnedRedirect()
    request = urllib.request.Request(
        "https://github.com/YARAHQ/yara-forge/releases/download/x/y.zip"
    )
    with pytest.raises(ValueError, match="refusing rule URL"):
        handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/stolen.zip")


def test_api_github_metadata_host_allowed() -> None:
    api = _allowed_url("https://api.github.com/repos/YARAHQ/yara-forge/releases/latest")
    asset = _allowed_url(
        "https://release-assets.githubusercontent.com/github-production-release-asset/1"
    )
    assert api.startswith("https://api.github.com/")
    assert asset.startswith("https://release-assets.githubusercontent.com/")


def test_successful_install_swaps_atomically_and_writes_lock(tmp_path: Path) -> None:
    root = _rules_tree(tmp_path)
    blob = _kept_zip()
    digest = hashlib.sha256(blob).hexdigest()
    save_lock(
        RulesLock(
            packs=[
                PackPin(
                    name="yara-forge-core",
                    url="https://github.com/YARAHQ/yara-forge/releases/download/x/core.zip",
                    pin="x",
                    sha256=digest,
                )
            ]
        ),
        root,
    )
    lock = install_packs(root, transport=lambda _url: blob)
    assert lock.packs[0].sha256 == digest
    assert (root / "vendor" / "yara-forge" / "kept.yar").is_file()
    assert not (root / "vendor" / "retained.yar").exists()
    assert digest in (root / "rules.lock").read_text(encoding="utf-8")
    assert list(root.glob(".staging-*")) == []
    assert list(root.glob(".vendor-old-*")) == []


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
