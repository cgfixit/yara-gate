"""The SMS bridge example must keep message queues owner-only, including ones that already exist."""

import importlib.util
import os
import stat
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
    allowed = queue / "allowed.jsonl"
    allowed.write_text('{"earlier": 1}\n', encoding="utf-8")
    os.chmod(allowed, 0o644)

    gate = bridge.Gate(queue, None)
    gate._append("allowed.jsonl", {"later": 2})

    assert _mode(queue) == 0o700
    assert _mode(allowed) == 0o600 and _mode(queue / "held.jsonl") == 0o600
    assert allowed.read_text(encoding="utf-8").splitlines() == ['{"earlier": 1}', '{"later": 2}']


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
