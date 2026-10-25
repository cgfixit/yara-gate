"""Quarantine untrusted files until a scan finishes."""

from typing import TYPE_CHECKING, Any

__version__ = "0.2.0"

__all__ = ["ScanResult", "__version__", "scan_bytes", "scan_file"]

if TYPE_CHECKING:
    from yara_gate.models import ScanResult
    from yara_gate.scanner import scan_bytes, scan_file


def __getattr__(name: str) -> Any:
    # The scanner and its rule loader are imported on first use, so `yara-gate --version`,
    # `rules install`, and `demo` do not pay for them (PEP 562).
    if name == "ScanResult":
        from yara_gate.models import ScanResult

        return ScanResult
    if name in ("scan_bytes", "scan_file"):
        from yara_gate import scanner

        return getattr(scanner, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
