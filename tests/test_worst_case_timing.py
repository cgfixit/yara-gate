"""The tripwire must reject slow scans and stop a worker that never returns in time."""

import runpy
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "docs/verification/check_worst_case_timing.py"


def test_tripwire_rejects_scan_over_ceiling(
    rules_copy: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = runpy.run_path(str(SCRIPT))
    scan = module["scan_case"]
    monkeypatch.setitem(scan.__globals__, "SCAN_SECONDS", 0)
    with pytest.raises(RuntimeError, match="exceeds 0s"):
        scan("html-comments.html", rules_copy)


def test_tripwire_stops_worker(monkeypatch: pytest.MonkeyPatch) -> None:
    module = runpy.run_path(str(SCRIPT))
    main = module["main"]
    monkeypatch.setitem(main.__globals__, "PROCESS_SECONDS", 0.001)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)])
    with pytest.raises(SystemExit, match="process exceeded 0.001s"):
        main()
