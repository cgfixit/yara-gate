# Public recorded demo

The [Pages demo guide](../docs/pages-demo.md) explains the build, privacy, and deployment gates. This static site replays curated scanner recordings; it does not accept arbitrary scans or connect to the loopback workbench.

- [`index.html`](index.html) defines the public replay page and its content security policy.
- [`style.css`](style.css) styles its layouts and controls.
- [`app.mjs`](app.mjs) implements navigation and renders the recorded results in the browser.
- [`recordings.json`](recordings.json) contains the reviewed, allowlisted results generated from inert examples by the real scanner.
