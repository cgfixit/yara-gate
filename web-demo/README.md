# Public recorded demo

The [Pages demo guide](../docs/pages-demo.md) explains the build, privacy, and deployment gates. This static site replays curated scanner recordings; it does not accept arbitrary scans or connect to the loopback workbench.

- [`index.html`](index.html) defines the public replay page and its content security policy.
- [`style.css`](style.css) styles its layouts and controls.
- [`app.mjs`](app.mjs) implements navigation and renders the recorded results in the browser: the scoreboard, the buttons of the panel that sets what three files hold beside what a reader shows (its text is fixed in `index.html`), the per-policy strip of every pair, a card for each way an attack was caught (its attacks held, its twins clean, and the views that read it), and the filters by channel and by how each attack was caught, all computed from the recordings.
- [`recordings.json`](recordings.json) contains the reviewed, allowlisted results generated from inert examples by the real scanner.
