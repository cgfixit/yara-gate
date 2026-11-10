"""The public artifact must exclude unrelated files and reject content-entry regressions."""

import importlib.util
import json
import re
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


def _edit_recordings(builder, change) -> None:
    source = builder.SOURCE / "recordings.json"
    data = json.loads(source.read_text())
    change({case["id"]: case for case in data["cases"]})
    source.write_text(json.dumps(data))


def test_pages_rejects_a_control_with_findings(builder, tmp_path: Path) -> None:
    def add_finding(cases) -> None:
        cases["b64_tool_benign"]["results"]["default"]["findings"] = cases["b64_tool"]["results"][
            "default"
        ]["findings"]

    _edit_recordings(builder, add_finding)
    with pytest.raises(ValueError, match="benign control must be clean"):
        builder.build(tmp_path / "site")


def test_pages_rejects_a_detection_ingest_lets_through(builder, tmp_path: Path) -> None:
    def release(cases) -> None:
        cases["devcontainer"]["results"]["agent-ingest"]["verdict"] = "clean"

    _edit_recordings(builder, release)
    with pytest.raises(ValueError, match="held by agent-ingest"):
        builder.build(tmp_path / "site")


@pytest.mark.parametrize(
    ("case_id", "pair"), [("pdf_glyph", "pickle_benign"), ("pdf_glyph", "note"), ("plain", None)]
)
def test_pages_rejects_a_broken_pair(builder, tmp_path: Path, case_id: str, pair) -> None:
    _edit_recordings(builder, lambda cases: cases[case_id].update(pair=pair))
    with pytest.raises(ValueError, match="pair must join"):
        builder.build(tmp_path / "site")


def test_pages_rejects_an_attack_without_a_twin(builder, tmp_path: Path) -> None:
    def unpair(cases: dict) -> None:
        cases["zip_concat"]["pair"] = None
        cases["zip_concat_benign"]["pair"] = None

    _edit_recordings(builder, unpair)
    with pytest.raises(ValueError, match="Every detection and control is paired"):
        builder.build(tmp_path / "site")


def test_pages_rejects_a_paired_failure(builder, tmp_path: Path) -> None:
    _edit_recordings(builder, lambda cases: cases["incomplete"].update(pair="plain"))
    with pytest.raises(ValueError, match="Every detection and control is paired"):
        builder.build(tmp_path / "site")


def test_documented_demo_links_name_recorded_examples() -> None:
    """A link such as .../yara-gate/#lookalike/agent-ingest must open a recording that exists."""
    recorded = {
        case["id"]
        for case in json.loads((ROOT / "web-demo" / "recordings.json").read_text())["cases"]
    }
    link = re.compile(r"cgfixit\.github\.io/yara-gate/#([A-Za-z0-9_]+)(?:/([a-z-]+))?")
    found = []
    for path in [ROOT / "README.md", ROOT / "user-guide.md", *sorted((ROOT / "docs").glob("*.md"))]:
        found += link.findall(path.read_text(encoding="utf-8"))
    assert len(found) >= 8
    for example, policy in found:
        assert example in recorded, example
        assert policy in {"", "default", "agent-ingest", "agent-document"}, policy
