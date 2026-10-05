"""The demo page and the launchd plist, called the way a browser and plutil call them."""

import json
import plistlib
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from yara_gate.demo import bind_demo, serve_in_thread
from yara_gate.launchd import write_launch_agent


def _post(port: int, payload: object) -> tuple[int, dict[str, object]]:
    raw = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/api/scan",
        data=raw,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.loads(response.read().decode("utf-8"))
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = json.loads(exc.read().decode("utf-8"))
        return exc.code, body


def test_demo_samples_and_rejected_bodies(rules_copy: Path) -> None:
    server, thread = serve_in_thread(rules_copy)
    port = int(server.server_address[1])
    marker = "SECRETPASTE-do-not-echo"
    try:
        status, plain = _post(port, {"sample": "plain"})
        assert status == 200
        assert plain["verdict"] == "clean"
        assert plain["exit_code"] == 0
        assert "path" not in plain

        status, advisory = _post(port, {"sample": "base64"})
        assert status == 200
        assert advisory["verdict"] == "advisory"
        assert advisory["exit_code"] == 0

        status, blocked = _post(port, {"sample": "pe_pdf"})
        assert status == 200
        assert blocked["verdict"] == "block"
        assert blocked["exit_code"] == 1
        assert blocked["findings"][0]["rule_id"] == "filetype_mismatch_pe"

        status, empty = _post(port, {"text": ""})
        assert status == 400
        assert empty["error"] == "empty text"

        status, both = _post(port, {"sample": "plain", "text": "hi"})
        assert status == 400
        assert both["error"] == "send a sample or text, not both"

        status, leaked = _post(port, {"path": "/etc/passwd", "text": marker})
        assert status == 400
        assert leaked == {"error": "rejected"}
        assert marker not in json.dumps(leaked)
        assert "/etc/passwd" not in json.dumps(leaked)

        huge = "A" * ((64 * 1024) + 1)
        status, oversized = _post(port, {"text": huge})
        assert status == 400
        assert oversized["error"] == "text too large"

        status, pasted = _post(port, {"text": "hello from the paste box"})
        assert status == 200
        assert pasted["verdict"] == "clean"
        assert "hello from the paste box" not in json.dumps(pasted)

        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10)
        html = page.read().decode("utf-8")
        policy = page.headers["Content-Security-Policy"]
        assert page.status == 200
        assert "Scan plain note" in html
        assert "__NONCE__" not in html
        assert "nonce-" in policy
        assert page.headers["X-Content-Type-Options"] == "nosniff"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_demo_refuses_public_bind() -> None:
    try:
        bind_demo("0.0.0.0", 0, None)
    except ValueError as exc:
        assert str(exc) == "demo binds loopback only"
    else:
        raise AssertionError("public bind was accepted")


def test_install_agent_plist_is_private(tmp_path: Path) -> None:
    dest = tmp_path / "com.cgfixit.yaragate.watch.plist"
    write_launch_agent(dest, home=tmp_path / "gate", binary=Path("/usr/bin/true"))
    plutil = Path("/usr/bin/plutil")
    if plutil.is_file():
        lint = subprocess.run(
            [str(plutil), "-lint", str(dest)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert lint.returncode == 0, lint.stderr
    with dest.open("rb") as handle:
        payload = plistlib.load(handle)
    assert "EnvironmentVariables" not in payload
    assert payload["ProgramArguments"] == [
        "/usr/bin/true",
        "watch",
        "--home",
        str(tmp_path / "gate"),
    ]
    text = dest.read_text(encoding="utf-8")
    assert "PRIVATE" not in text
    assert "AKIA" not in text
