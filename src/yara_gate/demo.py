"""Loopback page that scans samples. It does not move files and it does not download rules."""

from __future__ import annotations

import importlib.resources
import json
import os
import secrets
import shutil
import tempfile
import threading
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator

from yara_gate.models import ScanPolicy, ScanResult, exit_code
from yara_gate.samples import base64_text, clean_text, mini_pe
from yara_gate.scanner import scan_file

_MAX_TEXT = 64 * 1024
_MAX_BODY = (128 * 1024) + 256
_PAGE = importlib.resources.files("yara_gate").joinpath("demo_page.html")
_KNOWN_ERRORS = ("send a sample or text, not both", "empty text", "text too large")


class DemoSample(StrEnum):
    plain = "plain"
    base64 = "base64"
    pe_pdf = "pe_pdf"


class DemoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sample: DemoSample | None = None
    text: str | None = None
    policy: ScanPolicy = ScanPolicy.default

    @model_validator(mode="after")
    def _one_input(self) -> DemoRequest:
        has_sample = self.sample is not None
        has_text = self.text is not None
        if has_sample == has_text:
            raise ValueError("send a sample or text, not both")
        if self.text is not None and self.text == "":
            raise ValueError("empty text")
        if self.text is not None and len(self.text.encode("utf-8")) > _MAX_TEXT:
            raise ValueError("text too large")
        return self


class DemoFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    offset: int | None
    length: int | None
    severity: str
    source: str
    view: str
    member_path: list[str]


class DemoResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str
    exit_code: int
    sha256: str
    advisory: bool
    incomplete_reason: str | None
    findings: list[DemoFinding]
    policy: str
    policy_reason: str | None


def view_result(result: ScanResult) -> DemoResponse:
    """Copy the verdict fields the page is allowed to show."""
    return DemoResponse(
        verdict=result.verdict.value,
        exit_code=exit_code(result),
        sha256=result.sha256,
        advisory=result.advisory,
        incomplete_reason=result.incomplete_reason,
        policy=result.policy.value,
        policy_reason=result.policy_reason,
        findings=[
            DemoFinding(
                rule_id=item.rule_id,
                offset=item.offset,
                length=item.length,
                severity=item.severity.value,
                source=item.source.value,
                view=item.view,
                member_path=item.member_path,
            )
            for item in result.findings
        ],
    )


def _sample_file(sample: DemoSample) -> tuple[str, bytes]:
    if sample is DemoSample.plain:
        return "note.txt", clean_text()
    if sample is DemoSample.base64:
        return "blob.txt", base64_text()
    return "report.pdf", mini_pe()


def scan_request(request: DemoRequest, *, rules_dir: Path | None) -> DemoResponse:
    if request.sample is not None:
        name, payload = _sample_file(request.sample)
    else:
        name, payload = "paste.txt", (request.text or "").encode("utf-8")
    root = Path(tempfile.mkdtemp(prefix="yara-gate-demo-"))
    os.chmod(root, 0o700)
    try:
        path = root / name
        path.write_bytes(payload)
        result = scan_file(path, rules_dir=rules_dir, policy=request.policy)
    finally:
        shutil.rmtree(root, ignore_errors=True)
    return view_result(result)


def _known_error(exc: ValidationError) -> str:
    blob = " ".join(str(item.get("msg", "")) for item in exc.errors())
    for known in _KNOWN_ERRORS:
        if known in blob:
            return known
    return "rejected"


def _csp(nonce: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )


def render_page() -> tuple[bytes, str]:
    nonce = secrets.token_urlsafe(16)
    text = _PAGE.read_text(encoding="utf-8").replace("__NONCE__", nonce)
    return text.encode("utf-8"), nonce


class DemoHandler(BaseHTTPRequestHandler):
    server: DemoHTTPServer

    def log_message(self, format: str, *args: Any) -> None:
        # The request line has no body. Skip it so a pasted document never reaches stderr.
        return

    def do_GET(self) -> None:
        if self.path.split("?", 1)[0] != "/":
            self._send(404, b'{"error":"not found"}', "application/json")
            return
        body, nonce = render_page()
        self._send(200, body, "text/html; charset=utf-8", nonce)

    def do_POST(self) -> None:
        if self.path.split("?", 1)[0] != "/api/scan":
            self._send(404, b'{"error":"not found"}', "application/json")
            return
        if not self._same_origin():
            self._error(403, "rejected")
            return
        try:
            raw = self._read_body()
            payload = json.loads(raw)
            request = DemoRequest.model_validate(payload)
        except DemoHTTPError as exc:
            self._error(exc.status, exc.detail)
            return
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(400, "bad json")
            return
        except ValidationError as exc:
            self._error(400, _known_error(exc))
            return
        try:
            view = scan_request(request, rules_dir=self.server.rules_dir)
        except Exception:
            self._error(500, "scan failed")
            return
        self._send(200, view.model_dump_json().encode("utf-8"), "application/json")

    def _same_origin(self) -> bool:
        port = int(self.server.server_address[1])
        if self.headers.get("Host", "") != f"127.0.0.1:{port}":
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != f"http://127.0.0.1:{port}":
            return False
        content_type = self.headers.get("Content-Type", "")
        return content_type.split(";", 1)[0].strip().lower() == "application/json"

    def _read_body(self) -> bytes:
        header = self.headers.get("Content-Length")
        if header is None:
            raise DemoHTTPError(411, "length required")
        try:
            length = int(header)
        except ValueError as exc:
            raise DemoHTTPError(400, "bad length") from exc
        if length < 0 or length > _MAX_BODY:
            raise DemoHTTPError(413, "body too large")
        return self.rfile.read(length)

    def _error(self, status: int, detail: str) -> None:
        body = json.dumps({"error": detail}).encode("utf-8")
        self._send(status, body, "application/json")

    def _send(self, status: int, body: bytes, content_type: str, nonce: str | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        policy = _csp(nonce) if nonce is not None else "default-src 'none'"
        self.send_header("Content-Security-Policy", policy)
        self.end_headers()
        self.wfile.write(body)


class DemoHTTPError(Exception):
    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class DemoHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    rules_dir: Path | None

    def __init__(self, port: int, rules_dir: Path | None) -> None:
        self.rules_dir = rules_dir
        super().__init__(("127.0.0.1", port), DemoHandler)


def bind_demo(host: str, port: int, rules_dir: Path | None) -> DemoHTTPServer:
    if host != "127.0.0.1":
        raise ValueError("demo binds loopback only")
    return DemoHTTPServer(port, rules_dir)


def serve_demo(port: int, rules_dir: Path | None) -> None:
    server = bind_demo("127.0.0.1", port, rules_dir)
    bound = server.server_address[1]
    print(f"http://127.0.0.1:{bound}/", flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def serve_in_thread(
    rules_dir: Path | None,
    port: int = 0,
) -> tuple[DemoHTTPServer, threading.Thread]:
    """Start a loopback server for a caller that will shut it down."""
    server = bind_demo("127.0.0.1", port, rules_dir)
    thread = threading.Thread(target=server.serve_forever, name="yara-gate-demo", daemon=True)
    thread.start()
    return server, thread
