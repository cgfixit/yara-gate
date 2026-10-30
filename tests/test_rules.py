import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from http.client import HTTPMessage
from pathlib import Path

import pytest
from typer.testing import CliRunner

from yara_gate.cli import app
from yara_gate.models import Verdict
from yara_gate.rules import (
    PackPin,
    RuleDownloadError,
    RulesLock,
    _allowed_url,
    _bytes,
    _PinnedRedirect,
    _rule_key,
    _swap_vendor,
    _vendor_member,
    compile_sources,
    default_rules_dir,
    install_packs,
    load_lock,
    rule_files,
    ruleset_digest,
    save_lock,
    shipped_local_dir,
    update_packs,
)
from yara_gate.samples import clean_text, eicar_bytes
from yara_gate.scanner import scan_file

_CANDIDATE = """\
rule hunt_0123456789ab {
    meta:
        status = "candidate"
        verdict_on_match = "block"
    strings:
        $s = "CANDIDATE_SHOULD_NOT_FIRE" ascii
    condition:
        $s
}
"""


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


def test_update_without_core_asset_is_a_download_error(tmp_path: Path) -> None:
    root = _rules_tree(tmp_path)
    retained = (root / "vendor" / "retained.yar").read_bytes()

    def transport(_url: str) -> bytes:
        return json.dumps({"tag_name": "20261004", "assets": []}).encode()

    with pytest.raises(RuleDownloadError, match="yara-forge-rules-core.zip"):
        update_packs(root, transport=transport)
    assert (root / "vendor" / "retained.yar").read_bytes() == retained
    assert list(root.glob(".staging-*")) == []


def test_private_and_global_rules_are_counted(tmp_path: Path) -> None:
    (tmp_path / "local").mkdir()
    (tmp_path / "local" / "a.yar").write_text(
        'private rule helper { strings: $a = "zz" condition: $a }\n'
        "global private rule g { condition: true }\n"
        "rule top : tag { condition: helper }\n",
        encoding="utf-8",
    )
    _rules, _skipped, error, compiled, _skip = compile_sources(tmp_path)
    assert error is None
    assert compiled == 3


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


def test_old_vendor_cleanup_failure_keeps_committed_tree_and_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _rules_tree(tmp_path)
    save_lock(RulesLock(packs=[]), root)
    staging = root / ".staging-new"
    staging.mkdir()
    (staging / "new.yar").write_text("rule new_rule { condition: false }\n")
    lock = RulesLock(
        packs=[
            PackPin(name="new", url="https://github.com/org/new.zip", pin="new", sha256="ab" * 32)
        ]
    )
    unlink = os.unlink

    def refuse_old_file(path: str, *, dir_fd: int | None = None) -> None:
        if path == "retained.yar":
            raise PermissionError("old vendor cleanup denied")
        unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "unlink", refuse_old_file)
    _swap_vendor(root, staging, lock)
    assert (root / "vendor" / "new.yar").is_file()
    assert not (root / "vendor" / "retained.yar").exists()
    assert load_lock(root) == lock
    backups = list(root.glob(".vendor-old-*"))
    assert len(backups) == 1
    assert (backups[0] / "retained.yar").is_file()


@pytest.mark.parametrize("existing_vendor", [True, False])
def test_lock_write_failure_restores_previous_vendor_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_vendor: bool
) -> None:
    root = _rules_tree(tmp_path)
    if not existing_vendor:
        shutil.rmtree(root / "vendor")
    save_lock(RulesLock(packs=[]), root)
    previous = (root / "rules.lock").read_bytes()
    staging = root / ".staging-new"
    staging.mkdir()
    (staging / "new.yar").write_text("rule new_rule { condition: false }\n")

    def fail_lock(_lock: RulesLock, _root: Path) -> None:
        raise PermissionError("lock write denied")

    monkeypatch.setattr("yara_gate.rules.save_lock", fail_lock)
    with pytest.raises(PermissionError, match="lock write denied"):
        _swap_vendor(root, staging, RulesLock(packs=[]))
    assert (root / "rules.lock").read_bytes() == previous
    assert (root / "vendor").exists() == existing_vendor
    assert not (root / "vendor" / "new.yar").exists()
    if existing_vendor:
        assert (root / "vendor" / "retained.yar").is_file()


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
    assert not (rules / "vendor" / "SKIPPED.md").exists()


def test_default_rules_resolve_from_package_data() -> None:
    text = (shipped_local_dir() / "agent_eicar.yar").read_text(encoding="utf-8")
    assert "rule agent_eicar" in text


def test_wheel_install_smoke(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(dist)], cwd=root, check=True)
    wheel = next(dist.glob("*.whl"))
    names = subprocess.run(["unzip", "-l", str(wheel)], check=True, capture_output=True, text=True)
    assert "yara_gate/bundled_rules/local/agent_eicar.yar" in names.stdout
    assert "yara_gate/bundled_rules/rules.lock" in names.stdout
    assert "elastic/" not in names.stdout
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", str(venv), "--python", "3.12"], check=True)
    python = venv / "bin" / "python"
    subprocess.run(["uv", "pip", "install", "--python", str(python), str(wheel)], check=True)
    cli = venv / "bin" / "yara-gate"
    home = tmp_path / "gate"
    clean = tmp_path / "clean.txt"
    clean.write_bytes(clean_text())
    eicar = tmp_path / "eicar.com"
    eicar.write_bytes(eicar_bytes())
    scanned = subprocess.run(
        [str(cli), "scan", str(clean), "--home", str(home)],
        check=False,
        capture_output=True,
        text=True,
    )
    blocked = subprocess.run(
        [str(cli), "scan", str(eicar), "--home", str(home)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert scanned.returncode == 0
    assert blocked.returncode == 1


def test_selftest_unexpected_error_exits_2(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> int:
        raise RuntimeError("boom")

    monkeypatch.setattr("yara_gate.cli.run_selftest", boom)
    result = CliRunner().invoke(app, ["selftest"])
    text = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2
    assert "incomplete: RuntimeError" in text
    assert "Traceback" not in text


def test_watch_names_the_running_watcher(tmp_path: Path, rules_copy: Path) -> None:
    # A live pid in the lock file is the "already running" case; nothing is watched.
    home = tmp_path / "gate"
    home.mkdir()
    (home / ".watch.pid").write_text(str(os.getpid()), encoding="utf-8")
    result = CliRunner().invoke(app, ["watch", "--home", str(home), "--rules", str(rules_copy)])
    text = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2
    assert "incomplete: watch already running" in text
    assert "RuntimeError" not in text


def test_promote_names_the_missing_candidate(rules_copy: Path) -> None:
    result = CliRunner().invoke(app, ["rules", "promote", "nosuch", "--rules", str(rules_copy)])
    text = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2
    assert "incomplete: not found: nosuch" in text
    assert "FileNotFoundError" not in text


@pytest.mark.slow
def test_wheel_install_end_to_end(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    dist = tmp_path / "dist"
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(dist)], cwd=root, check=True)
    wheel = next(dist.glob("*.whl"))
    venv = tmp_path / "venv"
    subprocess.run(["uv", "venv", str(venv), "--python", "3.12"], check=True)
    python = venv / "bin" / "python"
    subprocess.run(["uv", "pip", "install", "--python", str(python), str(wheel)], check=True)
    cli = venv / "bin" / "yara-gate"
    env = os.environ.copy()
    env["HOME"] = str(tmp_path / "home")
    env["XDG_DATA_HOME"] = str(tmp_path / "xdg")
    env["XDG_CACHE_HOME"] = str(tmp_path / "cache")
    env.pop("YARA_GATE_RULES", None)
    env.pop("GITHUB_TOKEN", None)
    env.pop("GH_TOKEN", None)
    gate = tmp_path / "home" / "YaraGate"

    def run(args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(cli), *args],
            cwd=tmp_path,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

    selftest = run(["selftest"])
    assert selftest.returncode == 0, selftest.stderr[-2000:]
    assert "SELFTEST PASS" in selftest.stdout

    eicar_path = tmp_path / "eicar.bin"
    subprocess.run(
        [
            str(python),
            "-c",
            "from yara_gate.samples import eicar_bytes\n"
            f"open({str(eicar_path)!r}, 'wb').write(eicar_bytes())\n",
        ],
        check=True,
        env=env,
    )
    payload = eicar_path.read_bytes()
    inbox = gate / "inbox"
    inbox.mkdir(parents=True)
    (inbox / "eicar.com").write_bytes(payload)
    blocked = run(["scan", str(inbox / "eicar.com"), "--home", str(gate)])
    assert blocked.returncode == 1, blocked.stdout + blocked.stderr
    sha = next(
        line.split("sha256=", 1)[1].split()[0]
        for line in blocked.stdout.splitlines()
        if "sha256=" in line
    )
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "copy.com").write_bytes(payload)
    hunted = run(
        [
            "hunt",
            "--confirmed",
            sha,
            "--reason",
            "wheel confirmed eicar",
            "--scope",
            str(scope),
            "--home",
            str(gate),
        ]
    )
    assert hunted.returncode == 0, hunted.stderr

    def scan_bytes(name: str, body: bytes) -> int:
        path = tmp_path / "drops" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        result = run(["scan", str(path), "--home", str(gate)])
        return result.returncode

    assert scan_bytes("zero.md", "\u200b".encode()) == 1
    assert scan_bytes("bidi.md", "\u202e".encode()) == 1
    assert scan_bytes("eicar.com", payload) == 1
    assert scan_bytes("clean.txt", b"ordinary notes\n") == 0
    promoted = run(["rules", "promote", sha[:12]])
    assert promoted.returncode == 0, promoted.stderr
    assert scan_bytes("zero-again.md", "\u200b".encode()) == 1
    copy_scan = run(["scan", str(scope / "copy.com"), "--home", str(gate)])
    assert copy_scan.returncode == 1, copy_scan.stdout
    report = json.loads((gate / "reports" / f"{sha}.json").read_text(encoding="utf-8"))
    assert any(str(item["rule_id"]).startswith("hunt_") for item in report["findings"])


def _use_installed_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr("yara_gate.rules.installed_rules_root", lambda: root)
    return root


def test_installed_root_always_loads_bundled_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rules_copy: Path
) -> None:
    checkout_names = [path.name for path in rule_files(rules_copy)]
    assert checkout_names.count("agent_invisible_unicode.yar") == 1

    root = _use_installed_root(monkeypatch, tmp_path / "user-data")
    local = root / "local"
    local.mkdir()
    (local / "hunt_0123456789ab.yar").write_text(_CANDIDATE, encoding="utf-8")
    bait = tmp_path / "bait.txt"
    bait.write_text("CANDIDATE_SHOULD_NOT_FIRE\n", encoding="utf-8")
    bait_result = scan_file(bait, rules_dir=root)
    assert bait_result.verdict is Verdict.clean
    assert all(not item.rule_id.startswith("hunt_") for item in bait_result.findings)
    zero_width = tmp_path / "zero.md"
    zero_width.write_text("\u200b", encoding="utf-8")
    blocked = scan_file(zero_width, rules_dir=root)
    assert blocked.verdict is Verdict.block
    assert any(item.rule_id == "agent_invisible_unicode" for item in blocked.findings)

    relocated = tmp_path / "relocated"
    (relocated / "local").mkdir(parents=True)
    (relocated / "local" / "hunt_0123456789ab.yar").write_text(_CANDIDATE, encoding="utf-8")
    monkeypatch.setenv("YARA_GATE_RULES", str(relocated))
    moved = tmp_path / "moved.md"
    moved.write_text("\u200b", encoding="utf-8")
    via_env = scan_file(moved)
    assert via_env.verdict is Verdict.block
    assert any(item.rule_id == "agent_invisible_unicode" for item in via_env.findings)


def test_user_local_rule_layers_on_top(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _use_installed_root(monkeypatch, tmp_path / "user-data")
    local = root / "local"
    vendor = root / "vendor"
    local.mkdir()
    vendor.mkdir()
    (local / "operator_layer.yar").write_text(
        'rule operator_layer { strings: $s = "OPERATOR_LAYER_TOKEN" ascii condition: $s }\n',
        encoding="utf-8",
    )
    (vendor / "vendor_layer.yar").write_text(
        'rule vendor_layer { strings: $s = "VENDOR_LAYER_TOKEN" ascii condition: $s }\n',
        encoding="utf-8",
    )
    operator = tmp_path / "operator.txt"
    operator.write_text("OPERATOR_LAYER_TOKEN\n", encoding="utf-8")
    vendor_hit = tmp_path / "vendor.txt"
    vendor_hit.write_text("VENDOR_LAYER_TOKEN\n", encoding="utf-8")
    zero_width = tmp_path / "zero.md"
    zero_width.write_text("\u200b", encoding="utf-8")
    operator_result = scan_file(operator, rules_dir=root)
    vendor_result = scan_file(vendor_hit, rules_dir=root)
    bundled_result = scan_file(zero_width, rules_dir=root)
    assert any(item.rule_id == "operator_layer" for item in operator_result.findings)
    assert any(item.rule_id == "vendor_layer" for item in vendor_result.findings)
    assert bundled_result.verdict is Verdict.block


def test_cache_without_skip_list_recompiles(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    monkeypatch.setattr("yara_gate.rules._user_cache_dir", lambda: cache)
    monkeypatch.setattr("yara_gate.rules._MEMO", {})
    (rules_copy / "vendor" / "bad.yar").write_text(
        "rule broken { condition: nope }\n", encoding="utf-8"
    )
    assert compile_sources(rules_copy)[4] == 1
    for path in cache.glob("*.skipped"):
        path.unlink()
    monkeypatch.setattr("yara_gate.rules._MEMO", {})
    _rules, skipped, error, _count, skip_count = compile_sources(rules_copy)
    assert error is None
    assert skip_count == 1
    assert skipped == ["vendor/bad.yar: CompileError"]
    assert sorted(path.suffix for path in cache.iterdir()) == [".skipped", ".yarc"]


def test_user_file_cannot_shadow_bundled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _use_installed_root(monkeypatch, tmp_path / "user-data")
    local = root / "local"
    local.mkdir()
    (local / "agent_invisible_unicode.yar").write_text(
        "rule agent_invisible_unicode { condition: false }\n",
        encoding="utf-8",
    )
    _rules, skipped, error, _count, skip_count = compile_sources(root)
    assert error is None
    assert "local/agent_invisible_unicode.yar: shadowed by bundled" in skipped
    assert skip_count == 1
    zero_width = tmp_path / "zero.md"
    zero_width.write_text("\u200b", encoding="utf-8")
    blocked = scan_file(zero_width, rules_dir=root)
    assert blocked.verdict is Verdict.block
    assert blocked.skipped_rule_files == 1

    def _no_download(rules_dir: Path, transport: object = None) -> RulesLock:
        return RulesLock(packs=[])

    monkeypatch.setattr("yara_gate.cli.install_packs", _no_download)
    monkeypatch.setattr("yara_gate.cli.update_packs", _no_download)
    runner = CliRunner()
    installed = runner.invoke(app, ["rules", "install", "--allow-network", "--rules", str(root)])
    updated = runner.invoke(app, ["rules", "update", "--allow-network", "--rules", str(root)])
    assert installed.exit_code == 0
    assert updated.exit_code == 0
    assert "local/agent_invisible_unicode.yar: shadowed by bundled" in installed.stdout
    assert "local/agent_invisible_unicode.yar: shadowed by bundled" in updated.stdout


def test_missing_bundled_rules_exit_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = _use_installed_root(monkeypatch, tmp_path / "user-data")
    local = root / "local"
    local.mkdir()
    (local / "only_user.yar").write_text(
        'rule only_user { strings: $s = "ONLY_USER_TOKEN" ascii condition: $s }\n',
        encoding="utf-8",
    )
    monkeypatch.setattr("yara_gate.rules.shipped_local_dir", lambda: tmp_path / "missing-shipped")
    sample = tmp_path / "user-only.txt"
    sample.write_text("ONLY_USER_TOKEN\n", encoding="utf-8")
    missing = scan_file(sample, rules_dir=root)
    assert missing.verdict is Verdict.incomplete
    assert missing.incomplete_reason == "bundled rules missing"
    assert missing.findings == []
    home = tmp_path / "gate"
    cli_result = CliRunner().invoke(
        app, ["scan", str(sample), "--home", str(home), "--rules", str(root)]
    )
    assert cli_result.exit_code == 2
    assert "bundled rules missing" in cli_result.stdout

    locked = tmp_path / "unreadable"
    locked.mkdir()
    yar = locked / "agent_eicar.yar"
    yar.write_text("rule agent_eicar { condition: false }\n", encoding="utf-8")
    real_open = Path.open

    def denied_open(self: Path, *args: object, **kwargs: object) -> object:
        # chmod(0) does not stop uid 0, so refuse the read itself for every user.
        if self.resolve() == yar.resolve():
            raise PermissionError(13, "Permission denied", str(self))
        return real_open(self, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(Path, "open", denied_open)
    monkeypatch.setattr("yara_gate.rules.shipped_local_dir", lambda: locked)
    unreadable = scan_file(sample, rules_dir=root)
    assert unreadable.verdict is Verdict.incomplete
    assert unreadable.incomplete_reason == "bundled rules missing"
    assert unreadable.findings == []


class _Body(io.BytesIO):
    def __enter__(self) -> "_Body":
        return self

    def __exit__(self, *_args: object) -> bool:
        return False


class _Opener:
    def __init__(self, action: object) -> None:
        self.action = action
        self.requests: list[urllib.request.Request] = []

    def open(self, request: urllib.request.Request, timeout: int = 180) -> _Body:
        self.requests.append(request)
        result = self.action(request)  # type: ignore[operator]
        if isinstance(result, _Body):
            return result
        raise result


def _patch_opener(monkeypatch: pytest.MonkeyPatch, action: object) -> _Opener:
    opener = _Opener(action)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_args, **_kwargs: opener)
    return opener


def _http_error(
    url: str,
    code: int,
    headers: HTTPMessage | None = None,
    body: bytes = b"",
) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "status", headers or HTTPMessage(), io.BytesIO(body))


def _rate_headers(reset: str) -> HTTPMessage:
    headers = HTTPMessage()
    headers["X-RateLimit-Remaining"] = "0"
    headers["X-RateLimit-Reset"] = reset
    return headers


def test_rate_limit_403_message_includes_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    reset = "1800000000"
    when = datetime.fromtimestamp(int(reset)).astimezone()
    zone = when.tzname() or when.strftime("%z")
    stamp = f"{when.strftime('%Y-%m-%d %H:%M:%S')} {zone}"
    expected = f"rate limited by api.github.com until {stamp}; set GITHUB_TOKEN"
    url = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"

    def denied(request: urllib.request.Request) -> urllib.error.HTTPError:
        return _http_error(request.full_url, 403, _rate_headers(reset), b"nope")

    _patch_opener(monkeypatch, denied)
    with pytest.raises(RuleDownloadError, match="rate limited by api.github.com until") as first:
        _bytes(url)
    assert str(first.value) == expected

    def limited(request: urllib.request.Request) -> urllib.error.HTTPError:
        return _http_error(request.full_url, 429, _rate_headers(reset))

    _patch_opener(monkeypatch, limited)
    with pytest.raises(RuleDownloadError) as second:
        _bytes(url)
    assert str(second.value) == expected


def test_404_and_network_off_messages(monkeypatch: pytest.MonkeyPatch) -> None:
    url = "https://api.github.com/repos/missing/missing"
    _patch_opener(
        monkeypatch,
        lambda request: _http_error(request.full_url, 404, body=b"missing"),
    )
    with pytest.raises(RuleDownloadError) as missing:
        _bytes(url)
    assert str(missing.value) == f"not found: {url}"

    _patch_opener(monkeypatch, lambda _request: urllib.error.URLError("offline"))
    with pytest.raises(RuleDownloadError, match="^network unreachable$"):
        _bytes("https://codeload.github.com/org/repo/tar.gz/abc")

    _patch_opener(monkeypatch, lambda _request: TimeoutError("timed out"))
    with pytest.raises(RuleDownloadError, match="^network unreachable$"):
        _bytes("https://github.com/org/repo/file.zip")

    _patch_opener(monkeypatch, lambda request: _http_error(request.full_url, 500))
    with pytest.raises(RuleDownloadError, match="^HTTP 500 from api.github.com$"):
        _bytes(url)


def test_token_sent_only_to_api_github(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "github-token-value")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    opener = _patch_opener(monkeypatch, lambda _request: _Body(b"{}"))
    _bytes("https://api.github.com/repos/org/repo")
    _bytes("https://github.com/org/repo/file.zip")
    _bytes("https://codeload.github.com/org/repo/tar.gz/abc")
    assert opener.requests[0].get_header("Authorization") == "Bearer github-token-value"
    assert opener.requests[1].get_header("Authorization") is None
    assert opener.requests[2].get_header("Authorization") is None
    monkeypatch.delenv("GITHUB_TOKEN")
    monkeypatch.setenv("GH_TOKEN", "gh-token-value")
    _bytes("https://api.github.com/repos/org/other")
    assert opener.requests[3].get_header("Authorization") == "Bearer gh-token-value"


def test_token_not_forwarded_on_redirect_to_other_host() -> None:
    request = urllib.request.Request("https://api.github.com/repos/org/repo")
    request.add_header("Authorization", "Bearer sent-token-value")
    request.add_unredirected_header("Authorization", "Bearer sent-token-value")
    handler = _PinnedRedirect()
    moved = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        HTTPMessage(),
        "https://github.com/org/repo/file.zip",
    )
    assert moved is not None
    assert moved.headers.get("Authorization") is None
    assert moved.unredirected_hdrs.get("Authorization") is None
    stayed = handler.redirect_request(
        request,
        None,
        302,
        "Found",
        HTTPMessage(),
        "https://api.github.com/repos/org/repo/releases/latest",
    )
    assert stayed is not None
    assert stayed.get_header("Authorization") == "Bearer sent-token-value"


def test_token_never_in_output_or_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rules_copy: Path
) -> None:
    secret = "yg-test-token-not-for-logs"  # noqa: S105
    monkeypatch.setenv("GITHUB_TOKEN", secret)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    url = "https://api.github.com/repos/missing/missing"

    def denied(request: urllib.request.Request) -> urllib.error.HTTPError:
        headers = HTTPMessage()
        headers["Authorization"] = f"Bearer {secret}"
        headers["X-RateLimit-Remaining"] = "0"
        headers["X-RateLimit-Reset"] = "1800000000"
        return _http_error(request.full_url, 403, headers, secret.encode())

    _patch_opener(monkeypatch, denied)
    with pytest.raises(RuleDownloadError) as exc:
        _bytes(url)
    assert secret not in str(exc.value)
    assert "Authorization" not in str(exc.value)
    root = tmp_path / "download-root"
    (root / "local").mkdir(parents=True)
    (root / "vendor").mkdir()
    result = CliRunner().invoke(app, ["rules", "update", "--allow-network", "--rules", str(root)])
    text = (result.stdout or "") + (result.stderr or "")
    assert result.exit_code == 2
    assert secret not in text
    assert "Authorization" not in text
    assert "incomplete: rate limited by api.github.com until " in text
    assert "HTTPError" not in text
    assert "RuleDownloadError" not in text
    sample = tmp_path / "notes.txt"
    sample.write_bytes(clean_text())
    scanned = scan_file(sample, rules_dir=rules_copy)
    blob = json.dumps(
        {
            "verdict": scanned.verdict.value,
            "findings": [item.rule_id for item in scanned.findings],
            "reason": scanned.incomplete_reason,
        }
    )
    assert secret not in blob


def test_install_uses_bundled_lock_when_root_has_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "installed"
    root.mkdir()
    blob = _kept_zip()
    digest = hashlib.sha256(blob).hexdigest()
    lock_file = tmp_path / "bundled.lock"
    lock_file.write_text(
        RulesLock(
            packs=[
                PackPin(
                    name="yara-forge-core",
                    url="https://github.com/YARAHQ/yara-forge/releases/download/x/core.zip",
                    pin="x",
                    sha256=digest,
                )
            ]
        ).model_dump_json(),
        encoding="utf-8",
    )
    monkeypatch.setattr("yara_gate.rules.bundled_lock_path", lambda: lock_file)
    seen: list[str] = []

    def transport(url: str) -> bytes:
        seen.append(url)
        return blob

    lock = install_packs(root, transport=transport)
    assert seen == ["https://github.com/YARAHQ/yara-forge/releases/download/x/core.zip"]
    assert lock.packs[0].sha256 == digest
    assert (root / "vendor" / "yara-forge" / "kept.yar").is_file()
    written = (root / "rules.lock").read_text(encoding="utf-8")
    assert digest in written
    assert not (root / "rules.lock").samefile(lock_file)


def test_failed_update_keeps_vendor_and_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _rules_tree(tmp_path)
    save_lock(
        RulesLock(
            packs=[
                PackPin(
                    name="yara-forge-core",
                    url="https://github.com/YARAHQ/yara-forge/releases/download/x/core.zip",
                    pin="old",
                    sha256="ab" * 32,
                )
            ],
            installed_vendor_files=["retained.yar"],
        ),
        root,
    )
    retained = (root / "vendor" / "retained.yar").read_bytes()
    lock_bytes = (root / "rules.lock").read_bytes()
    _patch_opener(monkeypatch, lambda _request: TimeoutError("timed out"))
    with pytest.raises(RuleDownloadError, match="^network unreachable$"):
        update_packs(root)
    assert (root / "vendor" / "retained.yar").read_bytes() == retained
    assert (root / "rules.lock").read_bytes() == lock_bytes
    assert list(root.glob(".staging-*")) == []


def test_vendor_entry_that_is_not_a_file_stays_a_visible_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rules_copy: Path
) -> None:
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    (rules_copy / "vendor" / "pack" / "odd.yar").mkdir(parents=True)
    (rules_copy / "vendor" / "gone.yar").symlink_to(tmp_path / "missing.yar")
    target = tmp_path / "plain.txt"
    target.write_text("hello\n", encoding="utf-8")
    for _attempt in ("cold cache", "warm cache"):
        result = scan_file(target, rules_dir=rules_copy)
        assert result.verdict is Verdict.clean
        assert result.skipped_rule_files == 2


@pytest.mark.parametrize("loss", ["file", "pack", "vendor"])
def test_installed_vendor_loss_holds_identical_resubmission(
    tmp_path: Path, rules_copy: Path, loss: str
) -> None:
    blob = _kept_zip()
    save_lock(
        RulesLock(
            packs=[
                PackPin(
                    name="yara-forge-core",
                    url="https://github.com/YARAHQ/yara-forge/releases/download/x/core.zip",
                    pin="x",
                    sha256=hashlib.sha256(blob).hexdigest(),
                )
            ]
        ),
        rules_copy,
    )
    home = tmp_path / "gate"
    inbox = home / "inbox"
    inbox.mkdir(parents=True)
    sample = inbox / "plain.txt"

    def resubmit(expected_code: int, verdict: str) -> dict[str, object]:
        sample.write_bytes(clean_text())
        result = CliRunner().invoke(
            app,
            ["scan", str(sample), "--home", str(home), "--rules", str(rules_copy), "--json"],
        )
        assert result.exit_code == expected_code, result.output
        report = json.loads(result.stdout)
        assert report["verdict"] == verdict
        return report

    # A lock alone is not proof of installation: bundled-only scans stay usable.
    resubmit(0, "clean")
    install_packs(rules_copy, transport=lambda _url: blob)
    resubmit(0, "clean")
    vendor = rules_copy / "vendor"
    if loss == "file":
        (vendor / "yara-forge" / "kept.yar").unlink()
    else:
        shutil.rmtree(vendor / "yara-forge" if loss == "pack" else vendor)
    report = resubmit(2, "incomplete")
    assert report["incomplete_reason"] == "installed vendor rules missing"
    assert list((home / "clean").iterdir()) == []
    assert list((home / "quarantine").glob("*/plain.txt"))
    assert not sample.exists()
    install_packs(rules_copy, transport=lambda _url: blob)
    resubmit(0, "clean")


def test_ruleset_digest_reuses_stamp_and_still_sees_edits(
    rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repeat call stats the rule files but must not reread them; any edit must still show."""
    reads: list[Path] = []
    read_bytes = Path.read_bytes

    def counting(self: Path) -> bytes:
        reads.append(self)
        return read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", counting)
    first = ruleset_digest(rules_copy, overlay=False)
    assert reads
    reads.clear()
    assert ruleset_digest(rules_copy, overlay=False) == first
    assert reads == []
    extra = rules_copy / "vendor" / "extra.yar"
    extra.write_text("rule extra_rule { condition: false }\n", encoding="utf-8")
    added = ruleset_digest(rules_copy, overlay=False)
    assert added != first
    extra.write_text("rule extra_rule { condition: true }\n", encoding="utf-8")
    assert ruleset_digest(rules_copy, overlay=False) != added
    extra.unlink()
    assert ruleset_digest(rules_copy, overlay=False) == first


@pytest.mark.parametrize(
    ("path", "root"),
    [
        ("/r/local/a.yar", "/r"),
        ("/r/vendor/x/é.yar", "/r"),
        ("/r/../r/a.yar", "/r"),
        ("/a.yar", "/"),
        ("rel/a/b.yar", "rel"),
        ("/r", "/r"),
        ("/rr/a.yar", "/r"),
        ("/elsewhere/q.yar", "/r"),
    ],
)
def test_rule_key_matches_relative_to(path: str, root: str) -> None:
    candidate, base = Path(path), Path(root)
    try:
        expected = candidate.relative_to(base).as_posix()
    except ValueError:
        # Outside the root, the key falls back to the bare name (or the shipped-local form).
        assert _rule_key(candidate, base) in {candidate.name, f"local/{candidate.name}"}
    else:
        assert _rule_key(candidate, base) == expected


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"packs": "x"},
        {"packs": [], "unexpected": 1},
        {"packs": [None]},
        {"packs": [{"name": "n"}]},
        {"packs": [{"name": 1, "url": "u", "pin": "p", "sha256": "s"}]},
        {"packs": [{"name": "n", "url": "u", "pin": "p", "sha256": "s", "x": 1}]},
        {"packs": [], "installed_vendor_files": "x"},
        {"packs": [], "installed_vendor_files": [1]},
    ],
)
def test_lock_with_unexpected_shape_is_rejected(tmp_path: Path, payload: object) -> None:
    """The scan path maps ValueError to `invalid rules.lock`, so every bad shape must raise it."""
    with pytest.raises(ValueError, match="invalid"):
        RulesLock.model_validate(payload)
    (tmp_path / "rules.lock").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid"):
        load_lock(tmp_path)


def test_checked_in_lock_round_trips_byte_for_byte(tmp_path: Path) -> None:
    source = default_rules_dir() / "rules.lock"
    save_lock(load_lock(default_rules_dir()), tmp_path)
    assert (tmp_path / "rules.lock").read_bytes() == source.read_bytes()
    pin = PackPin(name="é", url="https://github.com/o/r.zip", pin="p", sha256="ab" * 32)
    lock = RulesLock(packs=[pin], installed_vendor_files=["a/b.yar"])
    save_lock(lock, tmp_path)
    assert load_lock(tmp_path) == lock
    assert '"é"' in (tmp_path / "rules.lock").read_text(encoding="utf-8")
    assert json.loads(lock.model_dump_json())["installed_vendor_files"] == ["a/b.yar"]


def test_scan_path_does_not_import_pydantic() -> None:
    """Every `yara-gate scan` is a new process for callers that shell out per file."""
    code = "import sys, yara_gate.cli; sys.exit('pydantic' in sys.modules)"
    assert subprocess.run([sys.executable, "-c", code], check=False).returncode == 0


def test_rule_listing_is_cached_and_still_sees_adds_deletes_and_same_tick_files(
    rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The walk is skipped only while every directory mtime is old and unchanged."""
    import os
    import time

    from yara_gate.rules import _LISTING, rule_files

    walks: list[Path] = []
    real_rglob = Path.rglob

    def counting(self: Path, pattern: str, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        walks.append(self)
        return real_rglob(self, pattern, *args, **kwargs)

    monkeypatch.setattr(Path, "rglob", counting)
    _LISTING.clear()
    old = time.time() - 10
    for folder in (rules_copy / "local", rules_copy / "vendor"):
        os.utime(folder, (old, old))
    first = rule_files(rules_copy, overlay=False)
    assert walks
    walks.clear()
    assert rule_files(rules_copy, overlay=False) == first
    assert walks == [], "an unchanged old tree must not be walked again"
    # A file created now changes the directory mtime to now: the listing is rebuilt and the
    # fresh directory is not cached again until the racy window has passed.
    extra = rules_copy / "vendor" / "extra.yar"
    extra.write_text("rule extra_rule { condition: false }\n", encoding="utf-8")
    added = rule_files(rules_copy, overlay=False)
    assert extra in added and len(added) == len(first) + 1
    walks.clear()
    rule_files(rules_copy, overlay=False)
    assert walks, "a directory touched within the racy window is walked every time"
    os.utime(rules_copy / "vendor", (old, old))
    rule_files(rules_copy, overlay=False)
    walks.clear()
    assert rule_files(rules_copy, overlay=False) == added
    assert walks == []
    extra.unlink()
    assert rule_files(rules_copy, overlay=False) == first
    # Load order is the sorted order the walk produces, with .yar before .yara.
    assert first == sorted(p for p in first if p.suffix == ".yar") + sorted(
        p for p in first if p.suffix == ".yara"
    )
