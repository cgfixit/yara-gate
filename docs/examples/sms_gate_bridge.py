"""A reference bridge between a public SMS number (Twilio) and an agent: scan, then hold or pass.

Twilio POSTs each inbound message to this server. The bridge:

1. refuses any request whose ``X-Twilio-Signature`` does not verify against the auth token and
   the public URL Twilio was configured with (HMAC-SHA1 over the URL plus the sorted form
   fields, base64), so only Twilio can submit messages;
2. holds every MMS for a person: the gate never fetches media URLs, and pixels cannot be
   checked for text, so an image's instructions would otherwise pass unread;
3. scans the message body with ``scan_bytes(..., policy="agent-ingest")`` and also scans the
   sender's recent messages joined together, so an instruction split across two texts is
   seen whole;
4. appends a message to ``allowed.jsonl`` only when both scans are complete ``clean`` records
   for these exact bytes, and everything else to ``held.jsonl`` with the rule IDs for review.

It answers Twilio with an empty TwiML response: no automatic reply, nothing echoed back. The
agent side reads ``allowed.jsonl`` and must still fence each body as untrusted data and keep
its own approval checks on any action. A held message reaches the agent only after a person
reviews it; this example has no release command (see docs/integrations.md).

Run it on loopback behind the HTTPS reverse proxy or tunnel whose URL Twilio calls:

    TWILIO_AUTH_TOKEN=... uv run python docs/examples/sms_gate_bridge.py \\
        --public-url https://sms.example.com/twilio/sms --queue ~/sms-gate --port 8787

The token is read from the environment, never from argv or a file in the repository.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from yara_gate import scan_bytes

MAX_BODY = 64 * 1024  # Twilio form posts are a few KB; anything larger is refused unread.
WINDOW_MESSAGES = 5  # How many of a sender's recent messages are rescanned together.
WINDOW_SECONDS = 15 * 60
RATE_PER_MINUTE = 12  # Per sender; a flood is held for review rather than scanned and passed.
EMPTY_TWIML = b'<?xml version="1.0" encoding="UTF-8"?><Response></Response>'


def twilio_signature(auth_token: str, url: str, fields: list[tuple[str, str]]) -> str:
    """Twilio's request signature: HMAC-SHA1 of the URL followed by each sorted key and value."""
    payload = url + "".join(key + value for key, value in sorted(fields))
    digest = hmac.new(auth_token.encode(), payload.encode("utf-8"), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def readable(result: Any, data: bytes) -> bool:
    """The agent-ingest read rule: one complete clean record for exactly these bytes."""
    return (
        result.policy.value == "agent-ingest"
        and result.verdict.value == "clean"
        and result.incomplete_reason is None
        and result.sha256 == hashlib.sha256(data).hexdigest()
    )


class Gate:
    """Per-sender scan state. Message text lives only in memory and in the owner's queue files."""

    def __init__(self, queue: Path, rules_dir: Path | None) -> None:
        self.queue = queue
        self.rules_dir = rules_dir
        self.lock = threading.Lock()
        self.recent: dict[str, deque[tuple[float, str]]] = defaultdict(deque)
        self.arrivals: dict[str, deque[float]] = defaultdict(deque)
        queue.mkdir(mode=0o700, parents=True, exist_ok=True)

    def _append(self, name: str, entry: dict[str, Any]) -> None:
        path = self.queue / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def decide(self, fields: dict[str, str]) -> str:
        sender = fields.get("From", "")
        body = fields.get("Body", "")
        now = time.time()
        entry: dict[str, Any] = {
            "message_sid": fields.get("MessageSid", ""),
            "from": sender,
            "received_at": int(now),
            "body": body,
        }
        with self.lock:
            arrivals = self.arrivals[sender]
            while arrivals and now - arrivals[0] > 60:
                arrivals.popleft()
            arrivals.append(now)
            recent = self.recent[sender]
            while recent and now - recent[0][0] > WINDOW_SECONDS:
                recent.popleft()
            window = "\n".join([text for _, text in recent][-(WINDOW_MESSAGES - 1) :] + [body])
            recent.append((now, body))
            while len(recent) > WINDOW_MESSAGES:
                recent.popleft()
            flood = len(arrivals) > RATE_PER_MINUTE
        reasons: list[str] = []
        if fields.get("NumMedia", "0") not in ("", "0"):
            reasons.append("mms media is not scanned; review it in Twilio")
        if flood:
            reasons.append("sender exceeded the rate limit")
        data = body.encode("utf-8")
        single = scan_bytes(data, name="sms.txt", policy="agent-ingest", rules_dir=self.rules_dir)
        joined = window.encode("utf-8")
        combined = scan_bytes(
            joined, name="sms.txt", policy="agent-ingest", rules_dir=self.rules_dir
        )
        for label, result, scanned in (("message", single, data), ("window", combined, joined)):
            if not readable(result, scanned):
                rules = sorted({finding.rule_id for finding in result.findings})
                reasons.append(
                    f"{label}: {result.verdict.value}"
                    + (f" ({result.incomplete_reason})" if result.incomplete_reason else "")
                    + (f" {rules}" if rules else "")
                )
        entry["sha256"] = single.sha256
        if reasons:
            entry["held_because"] = reasons
            self._append("held.jsonl", entry)
            return "held"
        self._append("allowed.jsonl", entry)
        return "allowed"


class Handler(BaseHTTPRequestHandler):
    server: Bridge
    timeout = 10  # A client that stops sending mid-body loses its thread after this many seconds.

    def log_message(self, format: str, *args: Any) -> None:
        return  # The request line carries no body; skip it anyway so no message text is logged.

    def do_POST(self) -> None:
        if urlsplit(self.path).path != urlsplit(self.server.public_url).path:
            self._reply(404, b"")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._reply(411, b"")
            return
        if length < 0 or length > MAX_BODY:
            self._reply(413, b"")
            return
        try:
            raw = self.rfile.read(length).decode("utf-8")
            pairs = parse_qsl(raw, keep_blank_values=True, strict_parsing=bool(raw))
        except (OSError, UnicodeDecodeError, ValueError):
            self._reply(400, b"")
            return
        expected = twilio_signature(self.server.auth_token, self.server.public_url, pairs)
        if not hmac.compare_digest(expected, self.headers.get("X-Twilio-Signature", "")):
            self._reply(403, b"")
            return
        fields = dict(pairs)
        if len(fields) != len(pairs):
            self._reply(400, b"")  # A repeated field is not something Twilio sends.
            return
        outcome = self.server.gate.decide(fields)
        print(f"{fields.get('MessageSid', '?')}: {outcome}", flush=True)
        self._reply(200, EMPTY_TWIML, "text/xml")

    def _reply(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Bridge(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port: int, public_url: str, auth_token: str, gate: Gate) -> None:
        self.public_url = public_url
        self.auth_token = auth_token
        self.gate = gate
        super().__init__(("127.0.0.1", port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--public-url", required=True, help="the exact HTTPS URL Twilio calls")
    parser.add_argument("--queue", type=Path, required=True, help="owner-only queue directory")
    parser.add_argument("--rules", type=Path, help="rules root (default: yara-gate's own)")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    token = os.environ.get("TWILIO_AUTH_TOKEN", "")
    if not token:
        raise SystemExit("refusing: set TWILIO_AUTH_TOKEN in the environment")
    if urlsplit(args.public_url).scheme != "https":
        raise SystemExit("refusing: --public-url must be the https URL Twilio signs")
    bridge = Bridge(args.port, args.public_url, token, Gate(args.queue.expanduser(), args.rules))
    print(f"listening on 127.0.0.1:{bridge.server_address[1]} for {args.public_url}", flush=True)
    bridge.serve_forever()


if __name__ == "__main__":
    main()
