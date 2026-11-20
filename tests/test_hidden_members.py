"""Archive members a streaming unpacker reads and a directory reader does not, and the
LibreOffice printer setup that is not a base64 payload."""

import base64
import io
import struct
import tarfile
import zipfile
import zlib

from yara_gate.heuristics import base64_run_signals
from yara_gate.models import Verdict
from yara_gate.samples import injection_markdown, mini_pe, printer_setup_settings
from yara_gate.scanner import scan_bytes

_PHRASE = "agent_prompt_injection_phrases"


def _local(name: bytes, data: bytes, flags: int = 0, sizes: bool = True) -> bytes:
    deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
    body = deflate.compress(data) + deflate.flush()
    crc, packed, size = (zlib.crc32(data), len(body), len(data)) if sizes else (0, 0, 0)
    header = struct.pack(
        "<4sHHHHHIIIHH", b"PK\x03\x04", 20, flags, 8, 0, 0, crc, packed, size, len(name), 0
    )
    tail = b"" if sizes else struct.pack("<4sIII", b"PK\x07\x08", zlib.crc32(data), len(body), size)
    return header + name + body + tail


def _zip(entries: list[tuple[str, bytes]]) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return out.getvalue()


def _rules(result: object) -> set[tuple[str, str]]:
    return {(f.rule_id, "/".join(f.member_path)) for f in getattr(result, "findings", [])}


def test_entry_before_a_valid_archive_is_read() -> None:
    data = _local(b"notes.md", injection_markdown()) + _zip([("readme.txt", b"notes\n")])
    assert zipfile.ZipFile(io.BytesIO(data)).namelist() == ["readme.txt"]
    result = scan_bytes(data, name="bundle.zip")
    assert (_PHRASE, "zip:1") in _rules(result)


def test_entry_with_a_data_descriptor_is_read() -> None:
    data = _local(b"notes.md", injection_markdown(), flags=8, sizes=False) + _zip(
        [("readme.txt", b"notes\n")]
    )
    assert (_PHRASE, "zip:1") in _rules(scan_bytes(data, name="bundle.zip"))


def test_unlisted_entry_keeps_the_member_checks() -> None:
    benign = _zip([("readme.txt", b"notes\n")])
    encrypted = scan_bytes(_local(b"notes.md", b"x", flags=1) + benign, name="bundle.zip")
    assert encrypted.incomplete_reason == "archive unreadable or encrypted"
    escaping = scan_bytes(_local(b"../notes.md", b"x") + benign, name="bundle.zip")
    assert escaping.incomplete_reason == "archive member escapes the archive"


def test_bytes_that_only_look_like_a_header_are_ignored() -> None:
    fake = (b"PK\x03\x04" + b"\x14\x00\x00\x00\x08\x00" + bytes(20)) * 1000
    result = scan_bytes(fake + _zip([("readme.txt", b"notes\n")]), name="bundle.zip")
    assert result.verdict is Verdict.clean
    assert result.units_scanned == 2


def _v7(archive: bytes) -> bytes:
    """The ustar archive with its magic, version, and owner names blanked, checksums redone."""
    data = bytearray(archive)
    position = 0
    while position + 512 <= len(data) and any(data[position : position + 512]):
        header = data[position : position + 512]
        size = int(header[124:136].rstrip(b"\0 ") or b"0", 8)
        header[257:345] = bytes(88)
        header[148:156] = b" " * 8
        header[148:156] = b"%06o\0 " % sum(header)
        data[position : position + 512] = header
        position += 512 + (size + 511) // 512 * 512
    return bytes(data)


def test_tar_without_ustar_magic_is_opened() -> None:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in (
            ("bundle.zip", _zip([("notes.md", injection_markdown())])),
            ("build.log", b"Ordinary build log line.\n" * 8000),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    v7 = _v7(out.getvalue())
    assert v7[257:262] != b"ustar"
    assert tarfile.open(fileobj=io.BytesIO(v7)).getnames() == ["bundle.zip", "build.log"]
    assert (_PHRASE, "tar:0/zip:0") in _rules(scan_bytes(v7, name="logs.tar"))


def test_printer_setup_is_not_a_base64_blob() -> None:
    blob, exe = base64_run_signals(printer_setup_settings())
    assert (blob, exe) == (False, False)


def test_printer_setup_holding_a_payload_stays_a_blob() -> None:
    assert base64_run_signals(printer_setup_settings(bytes(8) + mini_pe()))[0]
    inner = base64.b64encode(b"ordinary words " * 40)
    assert base64_run_signals(printer_setup_settings(inner))[0]
    renamed = printer_setup_settings().replace(b"PrinterSetup", b"PrinterSetupX")
    assert base64_run_signals(renamed)[0]
    # The total no longer matches the bytes: not what LibreOffice writes.
    item = printer_setup_settings()
    start = item.index(b">") + 1
    stop = item.index(b"</")
    decoded = bytearray(base64.b64decode(item[start:stop]))
    struct.pack_into("<H", decoded, 0, len(decoded) + 1)
    broken = item[:start] + base64.b64encode(bytes(decoded)) + item[stop:]
    assert base64_run_signals(broken)[0]
