"""One-command fixture matrix. Exits 0 only when every expected verdict matches."""

import shutil
import tempfile
from pathlib import Path

from yara_gate import scanner
from yara_gate.models import Verdict, exit_code
from yara_gate.quarantine import GatePaths, process_inbox_file
from yara_gate.rules import shipped_local_dir
from yara_gate.samples import (
    EICAR,
    bidi_markdown,
    clean_text,
    docm_with_autoopen,
    eicar_bytes,
    injection_markdown,
    risky_pdf,
    tag_smuggled_markdown,
    zip_named_pdf,
)
from yara_gate.scanner import MAX_FILE_BYTES, ScanTimeout, scan_file


def run_selftest() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="yara-gate-") as tmp:
        root = Path(tmp)
        home = GatePaths(root / "home")
        home.ensure()
        rules = root / "rules"
        shutil.copytree(shipped_local_dir(), rules / "local")
        (rules / "vendor").mkdir()
        cases: list[tuple[str, str, bytes, Verdict]] = [
            ("eicar", "eicar.com", eicar_bytes(), Verdict.block),
            ("docm", "macro.docm", docm_with_autoopen(), Verdict.block),
            ("pdf", "open.pdf", risky_pdf(), Verdict.block),
            ("mismatch", "not-a.pdf", zip_named_pdf(), Verdict.advisory),
            ("hidden-tags", "hidden.md", tag_smuggled_markdown(), Verdict.block),
            # A lone zero-width or bidi control is a note: recorded, verdict advisory.
            ("bidi", "names.md", bidi_markdown(), Verdict.advisory),
            ("injection", "note.md", injection_markdown(), Verdict.advisory),
            ("clean", "notes.txt", clean_text(), Verdict.clean),
        ]
        for name, filename, payload, expected in cases:
            if not _drop(home, rules, name, filename, payload, expected):
                failures += 1
        if not _oversize(home, rules):
            failures += 1
        if not _broken_rules(root):
            failures += 1
        if not _reports_hide_eicar(home):
            failures += 1
        if not _hunt(home, rules, root):
            failures += 1
        if not _forced_timeout(root, rules):
            failures += 1
    if failures:
        print(f"SELFTEST FAIL {failures}")
        return 1
    print("SELFTEST PASS")
    return 0


def _drop(
    home: GatePaths,
    rules: Path,
    name: str,
    filename: str,
    payload: bytes,
    expected: Verdict,
) -> bool:
    inbox_file = home.inbox / filename
    inbox_file.write_bytes(payload)
    result = process_inbox_file(home, inbox_file, rules_dir=rules)
    ok = result.verdict is expected
    place = (
        "quarantine"
        if result.verdict is Verdict.incomplete
        else ("blocked" if result.verdict is Verdict.block else "clean")
    )
    slot = getattr(home, place) / result.sha256
    reports = home.reports
    ok = ok and slot.is_dir()
    ok = ok and (reports / f"{result.sha256}.sarif").is_file()
    ok = ok and (reports / f"{result.sha256}.json").is_file()
    print(f"{'PASS' if ok else 'FAIL'} {name} verdict={result.verdict} exit={exit_code(result)}")
    return ok


def _oversize(home: GatePaths, rules: Path) -> bool:
    path = home.inbox / "big.bin"
    path.touch()
    os_truncate(path, MAX_FILE_BYTES + 1)
    result = process_inbox_file(home, path, rules_dir=rules)
    stayed = (home.quarantine / result.sha256).is_dir()
    ok = result.verdict is Verdict.incomplete and exit_code(result) == 2 and stayed
    print(f"{'PASS' if ok else 'FAIL'} oversize verdict={result.verdict} stayed={stayed}")
    return ok


def os_truncate(path: Path, size: int) -> None:
    with path.open("wb") as handle:
        handle.truncate(size)


def _broken_rules(root: Path) -> bool:
    rules = root / "broken"
    rules.mkdir()
    (rules / "bad.yar").write_text(
        "rule nope { condition: not_a_real_identifier }\n", encoding="utf-8"
    )
    target = root / "plain.txt"
    target.write_text("hello\n", encoding="utf-8")
    result = scan_file(target, rules_dir=rules)
    ok = (
        result.verdict is Verdict.incomplete
        and exit_code(result) == 2
        and result.incomplete_reason == "no rules compiled"
    )
    print(f"{'PASS' if ok else 'FAIL'} broken-rules verdict={result.verdict}")
    return ok


def _reports_hide_eicar(home: GatePaths) -> bool:
    ok = True
    for report in home.reports.iterdir():
        text = report.read_text(encoding="utf-8", errors="replace")
        if EICAR.decode() in text:
            ok = False
    print(f"{'PASS' if ok else 'FAIL'} reports-omit-eicar")
    return ok


def _hunt(home: GatePaths, rules: Path, root: Path) -> bool:
    from yara_gate.hunt import hunt

    sample = eicar_bytes()
    digest = hash_file_bytes(sample)
    slot = home.blocked / digest
    if not slot.is_dir():
        print("FAIL hunt missing-blocked-sample")
        return False
    scope = root / "scope"
    scope.mkdir()
    (scope / "copy.com").write_bytes(sample)
    (scope / "ok.txt").write_text("ordinary notes\n", encoding="utf-8")
    try:
        rule_path, hits = hunt(
            home,
            digest,
            reason="selftest confirmed eicar",
            scope=scope,
            rules_dir=rules,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"FAIL hunt {exc.__class__.__name__}")
        return False
    text = rule_path.read_text(encoding="utf-8")
    ok = 'status = "candidate"' in text and any(path.name == "copy.com" for path in hits)
    print(f"{'PASS' if ok else 'FAIL'} hunt hits={len(hits)}")
    return ok


def hash_file_bytes(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def _forced_timeout(root: Path, rules: Path) -> bool:
    target = root / "timeout.txt"
    target.write_text("hello\n", encoding="utf-8")
    original = scanner._invoke_scan

    def boom(
        rules: object, data: bytes, timeout_s: int, ext: str, *, samples: bool = False
    ) -> object:
        raise ScanTimeout

    scanner._invoke_scan = boom
    try:
        result = scan_file(target, rules_dir=rules)
    finally:
        scanner._invoke_scan = original
    ok = (
        result.verdict is Verdict.incomplete
        and exit_code(result) == 2
        and result.incomplete_reason == "timeout"
    )
    print(f"{'PASS' if ok else 'FAIL'} timeout verdict={result.verdict}")
    return ok
