"""Quarantine untrusted files until a scan finishes."""

from yara_gate.models import ScanResult
from yara_gate.scanner import scan_bytes, scan_file

__version__ = "0.2.0"

__all__ = ["ScanResult", "__version__", "scan_bytes", "scan_file"]
