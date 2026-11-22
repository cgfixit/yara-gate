# The SMS bridge example and connections that send nothing

Date: 2026-11-22. Base: `main` at `bed66d4`. Engine: YARA-X 1.23.0, Python 3.12.3, x86_64
Linux container running as root (descriptor limit 20,000). Rules: a disposable copy of the
shipped `rules/local` (89 rules), no vendor packs; the queue directory was disposable and
under the session scratchpad. The bridge listened on loopback with a made-up auth token and
URL, and nothing left the machine. Every run below is a direct run on this container; nothing
here is hosted CI.

## The lead

[#322](https://github.com/cgfixit/yara-gate/issues/322), item 4.
`docs/examples/sms_gate_bridge.py` serves with `ThreadingHTTPServer`: one thread per
connection, no limit. A request is refused only after its body is read and its signature
fails, and a connection that sends headers and no body keeps its thread until the handler's
10-second timeout. Whoever can reach the proxy in front of the bridge needs no token to hold
as many threads and descriptors as they open connections.

## Reproduced on the base

400 connections, each sending a request line and `Content-Length: 10` and then nothing; then
one signed message; then another after the idle connections have timed out.

| Observation | Base `bed66d4` | Change |
| --- | --- | --- |
| Handler threads at 50, 200, 400 idle connections | 50, 200, 350 (the first 50 had timed out) | 50, 64, 64 |
| Idle connections answered at once | 0 | 336 answered `503` unread |
| Time to open the 400 | 10.3 s | 5.1 s |
| Signed message while the idle connections are open | `200`, written to `allowed.jsonl` | **`503`, not written** |
| Signed message after they time out | `200`, written | `200`, written |

The third row from the bottom is the cost, stated plainly: under this flood the base still
took a real message, and the change turns it away for up to ten seconds at a time. What the
change buys is a bound. On the base the count is limited only by the process's descriptor
limit (20,000 in this container; the usual defaults elsewhere are far lower and were not
measured here), and the queue files and `processed.sqlite3` need descriptors from the same
pool. That exhaustion was not run.

## The change

`Bridge` holds a `BoundedSemaphore(MAX_CONNECTIONS)`, 64. `process_request` takes a slot
before it starts a handler thread; when none is free it writes a fixed `503` with a
one-second send timeout and closes the connection without reading it.
`process_request_thread` gives the slot back when the handler ends. Signature checking, the
scan, and the queue writes are unchanged.

## Checks

- `tests/test_sms_gate_bridge.py::test_connections_past_the_cap_are_answered_503_unread`
  sets the cap to 2, holds both slots, and checks that eight more connections and a signed
  message get `503`, that the thread count stays at 2, and that the next signed message is
  `200` and the only one written. The file gives 7 passed and 4 skipped (the macOS ACL
  cases) on the change. On the base example the test stops at the missing `MAX_CONNECTIONS`;
  the table above is the base observation.
- `ruff check`, `ruff format --check .`, `mypy --strict src scripts`,
  `docs/verification/check_doc_links.py`, and `docs/verification/check_text_controls.py`
  pass.

## What this does not cover

- **Availability.** 64 idle connections, renewed every ten seconds, keep real deliveries at
  `503`. Twilio's retry behaviour for a `503` was not tested and depends on the number's
  configuration. Connection limits, rate limits, and source filtering belong on the proxy.
- **Authentication before the read.** A request is still read, up to 64 KiB, before its
  signature is checked. There is nothing to check before the body arrives, since the
  signature covers the form fields.
- **The number 64.** It was chosen to sit under a small descriptor limit with room left for
  the queue files. It was not tuned against a real burst of deliveries.
- **A hosted run on macOS**, where the ACL tests of the same file run.
