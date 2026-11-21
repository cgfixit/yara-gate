# Demo request bounds: deep JSON and a stalled request

Date: 2026-11-21. Base: `main` at `78e26bb`. Python 3.12.3, YARA-X 1.23.0, x86_64 Linux
container. The server was `yara-gate demo --rules <disposable copy of rules/local>` on
loopback; requests were sent with Python's `http.client` and raw sockets. Browser: headless
Chromium through the preinstalled Playwright. Nothing here is hosted CI.

The leads came from a read-only sweep of `demo.py`. The same sweep found no request that
gets past the loopback bind, the Host and Origin checks, the content-type check, the size
bound, or the CSP, and no response that carries an exception message.

## Reproduced on the base

| Request | Base | Changed |
| --- | --- | --- |
| `POST /api/scan`, 50 or 5,000 `[` | 400 `bad json` | 400 `bad json` |
| 60,000 `[` (under the 128 KiB bound) | no response: the connection closed, and a `RecursionError` traceback on the server's stderr | 400 `bad json`, nothing on stderr |
| 131,000 `[` | no response, the same traceback | 400 `bad json` |
| Headers with `Content-Length: 1000`, ten body bytes, connection left open | still waiting after 75 s; the thread holds until the client leaves | `408 Request Timeout` after 10.0 s, `{"error": "request timeout"}` |
| A request line and one header, then nothing | still waiting after 30 s | connection closed after 10.0 s, nothing on stderr |
| `{"sample": "note", "policy": "agent-ingest"}` | 200, block | 200, block, `agent_prompt_injection_phrases` |

## The change

- `json.loads` raises `RecursionError` for a body nested past the interpreter's limit; the
  handler now answers it as `bad json`, as it does a syntax error.
- `DemoHandler.timeout` is 10 seconds (`_IO_SECONDS`), so the standard library sets it on
  each connection's socket. A body read that times out is answered with 408. A stall in
  the request line or headers is closed by `BaseHTTPRequestHandler`, which logs through the
  handler's silenced `log_message`.

`jsonbounds.check_json_structure` was not reused: it reads a `str`, so the body would have
to be decoded before `json.loads`, which today also detects UTF-16 and UTF-32. The size
bound already limits what the decoder can allocate.

## Checks

| Check | Result |
| --- | --- |
| The rows above, base then changed | as shown |
| `test_demo_rejects_invalid_json_encoding[deep]` and `test_demo_times_out_a_body_that_stops_short` | fail on the base `demo.py`, pass on the change |
| `pytest tests/test_demo.py` | 14 passed |
| Live workbench in Chromium, **Run every pair** under `agent-ingest` | 44 / 44 attacks held, 44 / 44 twins clean, 0 findings on twins, 2 / 2 incomplete, 90 of 90 results match; no console error |
| `ruff check`, `ruff format --check`, `mypy --strict src scripts`, `check_doc_links.py`, `check_text_controls.py` | pass |

Not run here: the full pytest suite, selftest, and the Windows job, which hosted CI runs.

## Left as it is

- The number of server threads has no limit, so many stalled connections each hold a
  thread for up to 10 seconds. The server is loopback-only, and a local process that can
  open connections can already use the machine's resources directly.
- Requests the standard library refuses itself (`HEAD`, `PUT`, a malformed request line, a
  header line over 64 KiB) get its own HTML error page, without the demo's CSP header. It
  carries no path or traceback. Reasoned from the code, not run.
- A negative `Content-Length` gets 413 rather than 400. It is still refused.
