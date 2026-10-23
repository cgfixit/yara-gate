# Demo: JSON encoding — October 19, 2026

Baseline `d72efc1566513ff40fc407d79db0404416cba0bc` drops the HTTP connection
when `json.loads` receives malformed UTF-8 or truncated UTF-16. Its handler catches
JSON syntax errors, but not `UnicodeDecodeError`. Both real HTTP regression
cases failed on that baseline with `RemoteDisconnected`.

The candidate catches that decoding error at the existing request-validation
boundary and returns HTTP 400 with `{"error":"bad json"}`. It does not scan the
rejected body. Valid JSON with an invalid schema still uses the existing response.
Body-size, Host/Origin checks, loopback binding and nonce CSP are unchanged.

## Verification

Python 3.12.12, YARA-X 1.21.0, macOS 27.0.1 ARM64; copied local rules and
disposable cache. `tests/test_demo.py -k 'not install_agent'` passed all eight
cases, including both malformed encodings and successful subsequent plain scans.
Ruff lint/format, strict mypy and diff checks passed. The owned CLI demo separately
returned 400/bad json for both raw invalid bodies, then 200/clean for a valid sample.

Computer Use exercised that candidate through the in-app browser: plain note
returned clean/exit 0; an empty paste displayed `empty text` and cleared the prior
verdict. The browser form produces valid UTF-8, so malformed transport-byte
acceptance is established by the HTTP calls, not by this screenshot.

![Browser clears the previous result after rejection](../../screenshots/yara-gate-demo-rejection.jpg)

Original viewport capture, October 19, 2026 EDT, macOS in-app browser, no editing
or re-encoding. Source was the baseline plus the one-line exception handler and
its two-case regression. `src/yara_gate/demo.py` SHA-256:
`f8fc91aec64372e0ab711e6dc78ea9e543b929fccb0db88aa48444ece7b10c72`.
Image SHA-256:
`956127e174b8bf939d1f2f19f20a0ca3335f947a95f3487f17869229c0251771`.

Broad regression suites were not run locally. Hosted jobs currently cannot start
because GitHub reports an account billing/spending-limit issue. No claim of
native UI, production-corpus coverage or complete HTTP-server hardening is made.
