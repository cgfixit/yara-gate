"""Check rules.lock shape and the committed sha256 of the file itself.

This does not download packs. The per-pack sha256 is the pin checked at install.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "rules/rules.lock"
PIN = REPO / "docs/verification/rules.lock.sha256"
ALLOWED = {
    "github.com",
    "api.github.com",
    "codeload.github.com",
    "release-assets.githubusercontent.com",
}


def main() -> None:
    raw = LOCK.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    pinned = PIN.read_text(encoding="utf-8").split()[0]
    if digest != pinned:
        raise SystemExit(f"rules.lock sha256 {digest} != {pinned}")
    payload = json.loads(raw)
    packs = payload.get("packs")
    if not isinstance(packs, list) or not packs:
        raise SystemExit("rules.lock has no packs")
    for pack in packs:
        if not isinstance(pack, dict):
            raise SystemExit("pack is not an object")
        url = str(pack.get("url", ""))
        host = urlparse(url).hostname or ""
        sha = str(pack.get("sha256", ""))
        if host not in ALLOWED:
            raise SystemExit(f"pack host {host} is not allowed")
        if len(sha) != 64 or any(char not in "0123456789abcdef" for char in sha):
            raise SystemExit(f"pack sha256 is not 64 hex: {pack.get('name')}")
    print(f"rules.lock hash ok ({len(packs)} packs)")


if __name__ == "__main__":
    main()
