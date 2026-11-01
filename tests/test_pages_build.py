"""The public artifact must exclude unrelated files and reject content-entry regressions."""

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def builder(tmp_path: Path):
    spec = importlib.util.spec_from_file_location("pages_builder", ROOT / "scripts/build_pages.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.SOURCE = tmp_path / "source"
    shutil.copytree(ROOT / "web-demo", module.SOURCE)
    return module


def test_pages_artifact_contains_only_public_assets(builder, tmp_path: Path) -> None:
    (builder.SOURCE / "private.env").write_text("SYNTHETIC_PRIVATE_MARKER")
    output = tmp_path / "site"
    builder.build(output)
    assert {p.name for p in output.iterdir()} == {
        "index.html",
        "style.css",
        "app.mjs",
        "recordings.mjs",
    }
    assert all("SYNTHETIC_PRIVATE_MARKER" not in p.read_text() for p in output.iterdir())
    with pytest.raises(FileExistsError):
        builder.build(output)
    assert (output / "index.html").is_file()


@pytest.mark.parametrize("field", ["path", "matched_bytes"])
def test_pages_rejects_private_record_fields(builder, tmp_path: Path, field: str) -> None:
    source = builder.SOURCE / "recordings.json"
    data = json.loads(source.read_text())
    data["cases"][0]["results"]["default"][field] = "SYNTHETIC_PRIVATE_MARKER"
    source.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unreviewed fields"):
        builder.build(tmp_path / "site")
    assert not (tmp_path / "site").exists()


def test_pages_rejects_paste_box_and_linked_source(builder, tmp_path: Path) -> None:
    page = builder.SOURCE / "index.html"
    page.write_text(page.read_text().replace("</main>", "<textarea></textarea></main>"))
    with pytest.raises(ValueError, match="content-entry"):
        builder.build(tmp_path / "site")
    page.unlink()
    page.symlink_to(ROOT / "web-demo/index.html")
    with pytest.raises(ValueError, match="regular single-link file"):
        builder.build(tmp_path / "site")
