import shutil
from pathlib import Path

import pytest

from yara_gate.rules import default_rules_dir


@pytest.fixture
def rules_copy(tmp_path: Path) -> Path:
    dest = tmp_path / "rules"
    shutil.copytree(default_rules_dir() / "local", dest / "local")
    (dest / "vendor").mkdir()
    (dest / "rules.lock").write_text('{"packs": []}\n', encoding="utf-8")
    return dest
