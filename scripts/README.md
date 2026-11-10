# Scripts

Run these from the repository root.

## Rule files

- [`generate_rules.py`](generate_rules.py) renders the three generated rule files in `rules/local/` from [`rules/templates/`](../rules/templates/): a template per file and one `fragments.toml` of word lists and the word separator. `--check` writes nothing and exits 1 when a generated file is stale; [`lint_rules.py`](../docs/verification/lint_rules.py) runs the same check in CI. See [generated rule files](../rules/README.md#generated-rule-files).

## Demo build and deployment

See [Pages demo](../docs/pages-demo.md) for the recording, review, and deployment workflow; the published site replays results and does not scan files.

- [`build_pages.py`](build_pages.py) validates the curated inputs and recordings, then builds a fresh artifact containing only the public allowlisted files.
- [`record_pages_demo.py`](record_pages_demo.py) scans the fixed inert examples of the shared catalog ([`showcase.py`](../src/yara_gate/showcase.py), which the local workbench also scans) with disposable bundled rules and records selected results; its comparison mode protects the reviewed outcomes.
- [`pages_deploy_gate.py`](pages_deploy_gate.py) checks that the target is the latest `main` commit and that other checks are green before the workflow deploys. API errors and unresolved or failing checks prevent deployment.
