# Demo timeout test reads the whole reply (2026-11-23)

Source: `main` at `bdd0fa4`, branch `claude/fix-demo-timeout-test-read`. Linux x86_64,
Python 3.12. Test-only change; no source under `src/` moves.

`tests/test_demo.py::test_demo_times_out_a_body_that_stops_short` sends a request whose body
stops short, then read one `recv(4096)` and asserted that it ends with the JSON error body.
`DemoHandler._send` (`src/yara_gate/demo.py`) writes the response in two sends: `end_headers()`
flushes the status line and headers, then `wfile.write(body)` sends the body. A single `recv`
can return the headers alone.

**Observed.** During the runtime dependency refresh the test failed once in seven runs of
`tests/test_demo.py` (the reply ended before the body) and passed in seven runs on the base
packages, which is timing noise rather than a package effect.

**Reproduced on the base revision.** A pytest plugin in the session scratchpad wrapped
`DemoHandler.end_headers` to flush and sleep 0.2 s before the body is written. With it, the
unchanged test failed every time (`1 failed`).

**The change.** The test reads until the server closes the connection (the 408 reply is
HTTP/1.0) and then asserts on the whole reply. The assertions are unchanged.

| Run | Before | After |
| --- | --- | --- |
| The node with the 0.2 s plugin | failed | passed |
| `tests/test_demo.py`, five runs | | 14 passed each |
| `ruff check`, `ruff format --check` on the file | | passed |

The two `recv(64)` reads in `tests/test_sms_gate_bridge.py` assert only the status line, which
is in the first send, so they are left as they are.
