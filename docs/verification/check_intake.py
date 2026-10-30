"""Inbox intake that must behave the same on Linux, macOS, and Windows.

CI runs this on Windows, where Python has no O_NOFOLLOW and intake checks the entry with
lstat before the open and by identity after it. The Ubuntu and macOS jobs cover the same
contract in tests/test_quarantine.py. Inputs are inert and are not executed. The gate home
and the rules tree are disposable copies.

A cloud-file placeholder (Dropbox, OneDrive) cannot be made on a hosted runner, so its
refusal is checked only from the attribute bits, not on a real placeholder.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from yara_gate import quarantine
from yara_gate.quarantine import GatePaths, process_inbox_file

REPO = Path(__file__).resolve().parents[2]
# CRLF and Ctrl-Z change under a Windows text-mode read; the hash must cover these bytes.
PAYLOAD = b"line one\r\nline two\x1a after ctrl-z\r\n"


def _cli() -> str:
    found = shutil.which("yara-gate", path=str(Path(sys.executable).parent))
    if found is None:
        raise SystemExit("yara-gate console script is not next to this interpreter")
    return found


def _scan(home: Path, rules: Path, target: Path) -> tuple[int, list[dict[str, object]]]:
    args = [_cli(), "scan", str(target), "--home", str(home), "--rules", str(rules), "--json"]
    proc = subprocess.run(args, capture_output=True, text=True, check=False)  # noqa: S603
    return proc.returncode, [json.loads(line) for line in proc.stdout.splitlines() if line]


def _settled(path: Path) -> None:
    """Age the file so intake does not wait for a writer."""
    os.utime(path, (1, 1))


def main() -> None:
    failures: list[str] = []

    def check(label: str, ok: bool) -> None:
        print(f"{'ok ' if ok else 'BAD'} {label}")
        if not ok:
            failures.append(label)

    with tempfile.TemporaryDirectory(prefix="yara-gate-intake-") as directory:
        root = Path(directory)
        rules = root / "rules"
        shutil.copytree(REPO / "rules/local", rules / "local")
        shutil.copy2(REPO / "rules/rules.lock", rules / "rules.lock")
        home = root / "home"
        gate = GatePaths(home)
        gate.ensure()
        digest = hashlib.sha256(PAYLOAD).hexdigest()

        entry = gate.inbox / "note.txt"
        entry.write_bytes(PAYLOAD)
        _settled(entry)
        code, records = _scan(home, rules, entry)
        check(f"regular file exits 0 (got {code})", code == 0)
        check("record hashes the original bytes", [r["sha256"] for r in records] == [digest])
        check("inbox entry consumed", not entry.exists())
        slot = gate.clean / digest / "note.txt"
        check("clean slot holds the exact bytes", slot.is_file() and slot.read_bytes() == PAYLOAD)

        entry.write_bytes(PAYLOAD)
        _settled(entry)
        code, _ = _scan(home, rules, entry)
        check(f"identical-byte resubmission exits 0 (got {code})", code == 0)
        check("resubmission consumed, one slot", not entry.exists() and slot.is_file())

        outside = root / "outside"
        outside.mkdir()
        secret = outside / "secret.txt"
        secret.write_bytes(b"outside the inbox\n")

        first = outside / "first.txt"
        first.write_bytes(b"two names\n")
        hardlink = gate.inbox / "hard.txt"
        os.link(first, hardlink)
        _settled(hardlink)
        code, records = _scan(home, rules, hardlink)
        reasons = [r["incomplete_reason"] for r in records]
        check(
            f"hardlink exits 2 as hardlink rejected (got {code} {reasons})",
            code == 2 and reasons == ["hardlink rejected"],
        )
        check("other name of the hardlink left in place", first.read_bytes() == b"two names\n")

        link = gate.inbox / "link.txt"
        try:
            link.symlink_to(secret)
        except OSError as exc:
            # Windows needs Developer Mode or an elevated token; hosted runners have one.
            failures.append(f"could not create a symlink: {exc}")
        else:
            opened: list[str] = []
            real_open = os.open

            def spy(path: object, *args: object, **kwargs: object) -> int:
                opened.append(os.fspath(path))  # type: ignore[arg-type]
                return real_open(path, *args, **kwargs)  # type: ignore[arg-type]

            os.open = spy  # type: ignore[assignment]
            try:
                result = process_inbox_file(gate, link, rules_dir=rules)
            finally:
                os.open = real_open
            check(
                f"symlink is incomplete as symlink rejected ({result.incomplete_reason})",
                result.incomplete_reason == "symlink rejected",
            )
            check("symlink target never opened", str(secret) not in opened)
            if quarantine._NOFOLLOW is None:
                check("symlink itself never opened", str(link) not in opened)
            check("symlink moved out of the inbox", not os.path.lexists(link))

        if sys.platform == "win32":
            import _winapi

            junction = gate.inbox / "junction"
            _winapi.CreateJunction(str(outside), str(junction))
            code, records = _scan(home, rules, gate.inbox)
            paths = [str(r["path"]) for r in records]
            check(f"junction in the inbox exits 2 (got {code})", code == 2)
            check(
                f"no record names a file behind the junction {paths}",
                not any("secret.txt" in p for p in paths),
            )
            check("junction moved out of the inbox", not os.path.lexists(junction))
            check("junction target left in place", secret.read_bytes() == b"outside the inbox\n")

        child = subprocess.Popen(  # noqa: S603
            [sys.executable, "-c", "import time; time.sleep(30)"]
        )
        try:
            check("a running process reads as alive", quarantine._alive(child.pid))
            check("the liveness probe did not stop it", child.poll() is None)
        finally:
            child.kill()
            child.wait()
        check("an exited process reads as not alive", not quarantine._alive(child.pid))

    if failures:
        raise SystemExit("intake check failed: " + "; ".join(failures))
    print("intake check passed")


if __name__ == "__main__":
    main()
