# Demo build and deployment scripts

Run these from the repository root. See [Pages demo](../docs/pages-demo.md) for the recording, review, and deployment workflow; the published site replays results and does not scan files.

- [`build_pages.py`](build_pages.py) validates the curated inputs and recordings, then builds a fresh artifact containing only the public allowlisted files.
- [`record_pages_demo.py`](record_pages_demo.py) scans fixed inert examples with disposable bundled rules and records selected results; its comparison mode protects the reviewed outcomes.
- [`pages_deploy_gate.py`](pages_deploy_gate.py) checks that the target is the latest `main` commit and that other checks are green before the workflow deploys. API errors and unresolved or failing checks prevent deployment.
