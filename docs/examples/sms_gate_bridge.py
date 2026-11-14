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
   for these exact bytes, and everything else to ``held.jsonl`` with the rule IDs for review;
5. records each ``MessageSid`` and its pending JSONL write together in ``processed.sqlite3``.
   A restart or retry finishes a pending write at its recorded offset before acknowledging
   the delivery. A committed duplicate is acknowledged without scanning. An overlapping
   delivery or a storage failure gets HTTP 503. A message without a ``MessageSid`` is held.

The agent should still skip a ``message_sid`` it has already consumed when it restarts or
replays a queue. Do not rotate or edit a queue while the bridge has a pending write.

It answers Twilio with an empty TwiML response: no automatic reply, nothing echoed back. The
agent side reads ``allowed.jsonl`` and must still fence each body as untrusted data and keep
its own approval checks on any action. A held message reaches the agent only after a person
reviews it; this example has no release command (see docs/integrations.md).

Run it on loopback behind the HTTPS reverse proxy or tunnel whose URL Twilio calls:

    TWILIO_AUTH_TOKEN=... uv run python docs/examples/sms_gate_bridge.py \\
        --public-url https://sms.example.com/twilio/sms --queue ~/sms-gate --port 8787

The token is read from the environment, never from argv or a file in the repository. The
queue directory must belong to the user running the bridge; an existing directory is narrowed
to 0700 and its queue files to 0600, with macOS extended ACLs removed. A link, another user's
path, or a failure to make it private stops the bridge at startup. It needs Linux or macOS.
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import sys
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
QUEUE_FILES = ("allowed.jsonl", "held.jsonl")
PROCESSED = "processed.sqlite3"


def _require_mine(info: os.stat_result, path: Path) -> None:
    if info.st_uid != os.getuid():
        raise PermissionError(f"{path} belongs to another user")


def _make_private(fd: int, mode: int) -> None:
    os.fchmod(fd, mode)
    if sys.platform == "darwin":
        # macOS ACL grants survive chmod; clear them on the validated descriptor.
        libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        libc.acl_init.argtypes = [ctypes.c_int]
        libc.acl_init.restype = ctypes.c_void_p
        libc.acl_set_fd.argtypes = [ctypes.c_int, ctypes.c_void_p]
        libc.acl_set_fd.restype = ctypes.c_int
        libc.acl_free.argtypes = [ctypes.c_void_p]
        libc.acl_free.restype = ctypes.c_int
        acl = libc.acl_init(0)
        if not acl:
            raise OSError(ctypes.get_errno(), "cannot allocate a private queue ACL")
        try:
            if libc.acl_set_fd(fd, acl) != 0:
                raise OSError(ctypes.get_errno(), "cannot clear the queue ACL")
        finally:
            libc.acl_free(acl)


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
        # Creation modes do not apply to a path that already exists, so an existing queue is
        # checked and narrowed here. Queue files are opened relative to this descriptor, so
        # renaming the path afterwards cannot redirect them.
        queue.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.dir_fd = os.open(queue, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            _require_mine(os.fstat(self.dir_fd), queue)
            _make_private(self.dir_fd, 0o700)
            for name in (*QUEUE_FILES, PROCESSED):
                os.close(self._open(name))
            # The checked file, by path: sqlite3 cannot open relative to a descriptor. The queue
            # directory is ours and 0700, so its journal files are private too.
            self.db = sqlite3.connect(
                queue / PROCESSED, isolation_level=None, check_same_thread=False
            )
            self.db.execute("PRAGMA secure_delete = ON")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS processed"
                " (message_sid TEXT PRIMARY KEY, outcome TEXT NOT NULL, received_at INTEGER)"
            )
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS pending ("
                "id INTEGER PRIMARY KEY CHECK (id = 1), queue TEXT NOT NULL,"
                " device INTEGER NOT NULL, inode INTEGER NOT NULL,"
                " offset INTEGER NOT NULL, payload BLOB NOT NULL)"
            )
            self.db_lock = threading.Lock()
            self._commit()
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            os.close(self.dir_fd)
            raise
        self.in_flight: set[str] = set()

    def _open(self, name: str) -> int:
        """Open an owner-only regular file with one link without following a link."""
        path = self.queue / name
        # O_NONBLOCK keeps a FIFO left in the queue from blocking the open.
        flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK
        fd = os.open(name, flags, 0o600, dir_fd=self.dir_fd)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise PermissionError(f"{path} must be a regular file with one link")
            _require_mine(info, path)
            _make_private(fd, 0o600)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _seen(self, sid: str) -> bool:
        with self.db_lock:
            row = self.db.execute("SELECT 1 FROM processed WHERE message_sid = ?", (sid,))
            return row.fetchone() is not None

    def _commit(self, name: str | None = None, entry: dict[str, Any] | None = None) -> bool:
        """Replay a queued write, then optionally commit the next delivery and its bytes."""
        with self.db_lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                pending = self.db.execute(
                    "SELECT queue, device, inode, offset, payload FROM pending"
                ).fetchone()
                if pending is not None:
                    self._finish_write(*pending)
                    self.db.execute("DELETE FROM pending")
                accepted = True
                if name is not None and entry is not None:
                    sid = entry["message_sid"]
                    if sid:
                        cursor = self.db.execute(
                            "INSERT OR IGNORE INTO processed VALUES (?, ?, ?)",
                            (sid, name, entry["received_at"]),
                        )
                        accepted = cursor.rowcount == 1
                    if accepted:
                        fd = self._open(name)
                        try:
                            info = os.fstat(fd)
                        finally:
                            os.close(fd)
                        payload = (json.dumps(entry, ensure_ascii=False) + "\n").encode("utf-8")
                        self.db.execute(
                            "INSERT INTO pending VALUES (1, ?, ?, ?, ?, ?)",
                            (name, info.st_dev, info.st_ino, info.st_size, payload),
                        )
                self.db.execute("COMMIT")
            except BaseException:
                if self.db.in_transaction:
                    self.db.execute("ROLLBACK")
                raise
            return accepted

    def _finish_write(
        self, name: str, device: int, inode: int, offset: int, payload: bytes
    ) -> None:
        if name not in QUEUE_FILES:
            raise ValueError("invalid pending queue name")
        with os.fdopen(self._open(name), "r+b") as handle:
            info = os.fstat(handle.fileno())
            if (info.st_dev, info.st_ino) != (device, inode):
                raise OSError("queue file changed during a pending write")
            end = handle.seek(0, os.SEEK_END)
            if not offset <= end <= offset + len(payload):
                raise OSError("queue size changed during a pending write")
            handle.seek(offset)
            written = handle.read(end - offset)
            if not payload.startswith(written):
                raise OSError("queue bytes changed during a pending write")
            handle.write(payload[len(written) :])
            handle.flush()
            os.fsync(handle.fileno())

    def decide(self, fields: dict[str, str]) -> str:
        self._commit()
        sid = fields.get("MessageSid", "")
        if sid:
            with self.lock:
                if sid in self.in_flight:
                    return "retry"
                if self._seen(sid):
                    return "duplicate"
                self.in_flight.add(sid)
        try:
            return self._decide(fields, sid)
        finally:
            with self.lock:
                self.in_flight.discard(sid)

    def _decide(self, fields: dict[str, str], sid: str) -> str:
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
        if not sid:
            reasons.append("no MessageSid, so a replay could not be told apart")
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
        outcome = "held" if reasons else "allowed"
        if reasons:
            entry["held_because"] = reasons
        accepted = self._commit(f"{outcome}.jsonl", entry)
        self._commit()
        return outcome if accepted else "duplicate"


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
        try:
            outcome = self.server.gate.decide(fields)
        except (OSError, sqlite3.Error):
            outcome = "retry"
        print(f"{fields.get('MessageSid', '?')}: {outcome}", flush=True)
        if outcome == "retry":
            self._reply(503, b"")
        else:
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
    try:
        gate = Gate(args.queue.expanduser(), args.rules)
    except (OSError, sqlite3.Error) as exc:
        raise SystemExit(f"refusing to use the queue: {exc}") from None
    bridge = Bridge(args.port, args.public_url, token, gate)
    print(f"listening on 127.0.0.1:{bridge.server_address[1]} for {args.public_url}", flush=True)
    bridge.serve_forever()


if __name__ == "__main__":
    main()
