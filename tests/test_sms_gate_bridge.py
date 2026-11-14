"""The SMS bridge example must keep message queues owner-only, including ones that already exist."""

import errno
import importlib.util
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the bridge example is POSIX-only")


def _bridge() -> ModuleType:
    path = ROOT / "docs" / "examples" / "sms_gate_bridge.py"
    spec = importlib.util.spec_from_file_location("sms_gate_bridge", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["sms_gate_bridge"] = module
    spec.loader.exec_module(module)
    return module


bridge = _bridge()


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_an_existing_queue_is_narrowed_and_keeps_its_entries(tmp_path: Path) -> None:
    queue = tmp_path / "queue"
    queue.mkdir()
    os.chmod(queue, 0o755)  # noqa: S103 - the readable queue this test must narrow
    for name in bridge.QUEUE_FILES:
        (queue / name).write_text('{"earlier": 1}\n', encoding="utf-8")
        os.chmod(queue / name, 0o644)

    gate = bridge.Gate(queue, None)
    try:
        for name in bridge.QUEUE_FILES:
            assert gate._commit(name, {"message_sid": "", "later": 2})
            gate._commit()
            assert _mode(queue / name) == 0o600
            assert (queue / name).read_text(encoding="utf-8").splitlines() == [
                '{"earlier": 1}',
                '{"message_sid": "", "later": 2}',
            ]
        assert _mode(queue) == 0o700
    finally:
        os.close(gate.dir_fd)


def test_a_linked_queue_path_is_refused_and_its_target_untouched(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("untouched\n", encoding="utf-8")
    os.chmod(outside, 0o644)

    real = tmp_path / "real"
    real.mkdir()
    linked_dir = tmp_path / "linked-dir"
    linked_dir.symlink_to(real)
    linked_file = tmp_path / "linked-file"
    linked_file.mkdir()
    (linked_file / "allowed.jsonl").symlink_to(outside)
    hardlinked = tmp_path / "hardlinked"
    hardlinked.mkdir()
    os.link(outside, hardlinked / "held.jsonl")

    for queue in (linked_dir, linked_file, hardlinked):
        with pytest.raises(OSError):
            bridge.Gate(queue, None)

    assert outside.read_text(encoding="utf-8") == "untouched\n"
    assert _mode(outside) == 0o644


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs")
@pytest.mark.parametrize("inherited", [False, True])
def test_macos_acl_grants_are_removed(tmp_path: Path, inherited: bool) -> None:
    queue = tmp_path / "queue"
    queue.mkdir()
    subprocess.run(
        [
            "/bin/chmod",
            "+a",
            "everyone allow read,search,file_inherit,directory_inherit",
            str(queue),
        ],
        check=True,
    )
    for name in bridge.QUEUE_FILES:
        path = queue / name
        path.write_bytes(b'{"earlier": 1}\n')
        if not inherited:
            subprocess.run(["/bin/chmod", "-N", str(path)], check=True)
            subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(path)], check=True)
    paths = [queue, *(queue / name for name in bridge.QUEUE_FILES)]
    for path in paths:
        assert " allow " in subprocess.check_output(["/bin/ls", "-lde", str(path)], text=True)

    gate = bridge.Gate(queue, None)
    try:
        for path in paths:
            assert " allow " not in subprocess.check_output(
                ["/bin/ls", "-lde", str(path)], text=True
            )
        for name in bridge.QUEUE_FILES:
            path = queue / name
            # A replacement/rotated queue must be secured on append as well as at startup.
            subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(path)], check=True)
            assert gate._commit(name, {"message_sid": "", "later": 2})
            gate._commit()
            assert " allow " not in subprocess.check_output(
                ["/bin/ls", "-lde", str(path)], text=True
            )
            assert path.read_bytes() == b'{"earlier": 1}\n{"message_sid": "", "later": 2}\n'
    finally:
        os.close(gate.dir_fd)


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS extended ACLs")
@pytest.mark.parametrize("operation", ["acl_init", "acl_set_fd"])
def test_acl_failure_refuses_startup_and_append(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str
) -> None:
    queue = tmp_path / "queue"
    gate = bridge.Gate(queue, None)
    libc = bridge.ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)

    def denied(*args: object) -> int:
        bridge.ctypes.set_errno(errno.EPERM)
        return 0 if operation == "acl_init" else -1

    monkeypatch.setattr(libc, operation, denied)
    monkeypatch.setattr(bridge.ctypes, "CDLL", lambda *args, **kwargs: libc)
    try:
        with pytest.raises(OSError, match="queue ACL"):
            bridge.Gate(queue, None)
        for name in bridge.QUEUE_FILES:
            path = queue / name
            path.write_bytes(b'{"earlier": 1}\n')
            with pytest.raises(OSError, match="queue ACL"):
                gate._commit(name, {"message_sid": "", "later": 2})
            assert path.read_bytes() == b'{"earlier": 1}\n'
    finally:
        os.close(gate.dir_fd)


def test_each_message_sid_is_processed_once(tmp_path: Path, rules_copy: Path) -> None:
    queue = tmp_path / "queue"
    fields = {"MessageSid": "SM1", "From": "+15550100", "Body": "See you at 6.", "NumMedia": "0"}
    gate = bridge.Gate(queue, rules_copy)
    assert gate.decide(fields) == "allowed"
    # A Twilio retry or a replayed signed request, then the same after a restart.
    assert gate.decide(fields) == "duplicate"
    gate.db.close()
    assert bridge.Gate(queue, rules_copy).decide(fields) == "duplicate"
    assert (queue / "allowed.jsonl").read_text(encoding="utf-8").count('"SM1"') == 1
    assert stat.S_IMODE((queue / bridge.PROCESSED).stat().st_mode) == 0o600
    # Without an ID a replay cannot be told apart, so the message is held.
    unnamed = {key: value for key, value in fields.items() if key != "MessageSid"}
    assert bridge.Gate(queue, rules_copy).decide(unnamed) == "held"


@pytest.mark.parametrize("write_fraction", [0, 1, 2])
def test_sms_restart_finishes_a_pending_jsonl_write(
    tmp_path: Path, rules_copy: Path, monkeypatch: pytest.MonkeyPatch, write_fraction: int
) -> None:
    queue = tmp_path / "queue"
    fields = {"MessageSid": "SM2", "From": "+15550100", "Body": "See you at 6."}
    gate = bridge.Gate(queue, rules_copy)

    def interrupt(name: str, device: int, inode: int, offset: int, payload: bytes) -> None:
        with (queue / name).open("ab") as handle:
            handle.write(payload[: len(payload) * write_fraction // 2])
        raise OSError("interrupted queue write")

    with monkeypatch.context() as patch:
        patch.setattr(gate, "_finish_write", interrupt)
        with pytest.raises(OSError, match="interrupted queue write"):
            gate.decide(fields)
    gate.db.close()
    os.close(gate.dir_fd)

    resumed = bridge.Gate(queue, rules_copy)
    try:
        assert resumed.decide(fields) == "duplicate"
        lines = (queue / "allowed.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1 and '"SM2"' in lines[0]
        assert resumed.db.execute("SELECT count(*) FROM pending").fetchone() == (0,)
    finally:
        resumed.db.close()
        os.close(resumed.dir_fd)
