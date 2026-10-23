# Vendor pack review

Reviewed 2026-10-23 on this Mac, offline. No pack was downloaded. No vendor rule body is added to git.

The lock pins are unchanged.

| Pack | Pin already in `rules.lock` | What was read | Decision |
| --- | --- | --- | --- |
| yara-forge core | `20261004` | Local `rules/vendor/yara-forge/yara-rules-core.yar` header. At least one rule meta says `license = "NO LICENSE SET"` and `license_url = "N/A"`. | Do not commit the body. |
| signature-base | `94a1c48d7ab499879287ff611dfe7f9c56376030` | One local rule meta cites Detection Rule License 1.1. The license text was not fetched. | Do not commit the body. |
| elastic | `83e227669df8a13a2a2fee52c14b742c0d5f17cc` | This repo's README already says Elastic License 2.0 and that those rules are not packaged for redistribution. | Do not commit the body. |

FACT. The local vendor tree on the canonical checkout has the downloaded bodies. They stay gitignored.

FACT. A per-rule false-positive census of those bodies against the 246-file benign corpus was not run. Compiling about 1,800 vendor files was not part of this pass.

The 13 compile skips already listed in `rules/vendor/SKIPPED.md` stay. `rules install` rewrites that file, so the pack decision below is also in this document.

No rule from these packs is newly vendored.
