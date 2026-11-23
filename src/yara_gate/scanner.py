"""Scan raw bytes, archive members and derived text without moving files."""

import functools
import hashlib
import importlib.metadata
import math
import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from itertools import chain
from pathlib import Path, PurePosixPath
from typing import Any

from yara_gate.content import (
    FOLDED_SUFFIX,
    MAX_TEXT_PIECES,
    Budget,
    ContentLimit,
    ContentUnit,
    PdfObjects,
    PdfStream,
    _derived,
    comment_texts,
    config_unescaped_texts,
    content_units,
    decoded_text,
    feed_texts,
    folded_text,
    html_text_blocks,
    markdown_texts,
    notebook_texts,
    ooxml_cell_texts,
    ooxml_comment_texts,
    ooxml_header_texts,
    ooxml_hidden_texts,
    ooxml_text_views,
    pdf_streams,
    pdf_views,
    svg_scope_proven,
    text_views,
    xml_texts,
)
from yara_gate.content import (
    MAX_ARCHIVE_DEPTH as MAX_ARCHIVE_DEPTH,
)
from yara_gate.content import (
    MAX_EXTRACT_BYTES as MAX_EXTRACT_BYTES,
)
from yara_gate.content import (
    MAX_FILE_BYTES as MAX_FILE_BYTES,
)
from yara_gate.filetype import (
    double_extension,
    is_document_name,
    is_executable_kind,
    mismatch,
    name_has_controls,
    raster_image,
    sniff,
)
from yara_gate.heuristics import (
    CONTROL_BYTES_RULES,
    base64_run_signals,
    control_conjunction,
    control_in_text,
    heuristic_findings,
    joiner_findings,
    pdf_token_findings,
    tag_findings,
    variation_findings,
)
from yara_gate.htmlhidden import html_also_shown, html_hidden_texts
from yara_gate.models import (
    DOCUMENT_HOLD,
    DOCUMENT_NOTES,
    INGEST_HOLD,
    UNKNOWN_SHA256,
    Finding,
    FindingSource,
    ScanPolicy,
    ScanResult,
    Severity,
    Verdict,
    result_from_findings,
)
from yara_gate.odftext import odf_text_views
from yara_gate.pdfannotations import PdfStrings, pdf_string_texts, shown_string
from yara_gate.pdftext import pdf_text
from yara_gate.rtftext import rtf_texts
from yara_gate.rules import (
    GUARD_LOG_PREFIX,
    MATCH_LIMIT,
    RESCAN_LIMIT,
    GuardedRules,
    compile_ruleset,
    compile_source,
    default_rules_dir,
    guarded_rules,
    locating_source,
    placed_rule_sources,
    vendor_namespace_dirs,
    vendor_overrides,
    yara_x_version,
)


class ScanTimeout(Exception):
    pass


# A view whose first scan fills at most this many counted lists is read again at
# ``RESCAN_LIMIT``. Four full lists of matching public rules peaked at 2.3 GB (2,171 MiB); a
# string read only for presence logs nothing and grows on the rescan too, so this bounds the
# counted lists, not the memory (docs/verification/2026-11-19-rescan-memory.md).
RESCAN_MAX_FULL = 4
# The rescan runs only when the time left is this many times what the first scan took.
RESCAN_TIME_FACTOR = 1.25
MATCH_CAP_REASON = "match cap reached"


@dataclass(slots=True)
class MatchCap:
    """What the match-cap guards saw across one scan's views."""

    # The limit of the rescan, when any view needed one.
    rescan_limit: int | None = None
    # A list was full on a view's final scan: the scan is incomplete.
    full: bool = False


def scan_file(
    path: Path | str,
    *,
    timeout_s: int = 30,
    rules_dir: Path | None = None,
    policy: ScanPolicy | str = ScanPolicy.default,
) -> ScanResult:
    file_path = Path(path)
    try:
        return _scan_file(
            file_path, timeout_s=timeout_s, rules_dir=rules_dir, policy=ScanPolicy(policy)
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        return result_from_findings(
            sha256=UNKNOWN_SHA256, path=str(file_path), findings=[], incomplete_reason="scan failed"
        )


# Third-party parsers whose behavior reaches a verdict; YARA-X is also reported on its own.
_DETECTOR_PACKAGES = ("olefile", "oletools", "pyyaml", "yara-x")


@functools.cache
def detector_digest() -> str | None:
    """SHA-256 over this package's Python sources and the parser versions a verdict depends on.

    ``ruleset_sha256`` names the rules and ``tool_version`` the release, but a reader or
    heuristic change can alter verdicts under both unchanged; this digest changes with it. It
    identifies the code that produced a record, so a consumer that caches admissions can rescan
    when it changes. None when the sources cannot be read.
    """
    root = Path(__file__).resolve().parent
    hasher = hashlib.sha256()
    try:
        for path in sorted(root.rglob("*.py")):
            name = path.relative_to(root).as_posix().encode()
            body = path.read_bytes()
            hasher.update(b"%d:%s%d:" % (len(name), name, len(body)))
            hasher.update(body)
    except OSError:
        return None
    for package in _DETECTOR_PACKAGES:
        try:
            version = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            version = ""
        hasher.update(b"%s=%s;" % (package.encode(), version.encode()))
    return hasher.hexdigest()


def scan_bytes(
    data: bytes,
    *,
    name: str = "input",
    timeout_s: int = 30,
    rules_dir: Path | None = None,
    policy: ScanPolicy | str = ScanPolicy.default,
) -> ScanResult:
    """Scan bytes the caller already holds, such as a chat or SMS message body.

    Nothing is written to disk and nothing is moved. ``name`` supplies the suffix that the
    extension-sensitive checks read (the YARA ``yara_gate_ext`` global, type mismatch, double
    extension, MCP JSON and model headers); only its final component is kept, and it becomes
    the report ``path``. The verdict describes these bytes: consume the same buffer, not a
    later reread.
    """
    # Either separator ends a directory, so a Windows-style name keeps only its last component
    # on POSIX too.
    label = PurePosixPath(str(name).replace("\\", "/")).name or "input"
    # bytes(5) would build five NUL bytes; anything not bytes-like is a failed scan.
    payload = bytes(data) if isinstance(data, bytes | bytearray | memoryview) else None
    try:
        if payload is None:
            raise TypeError("scan_bytes needs bytes")
        return _scan_file(
            Path(label),
            timeout_s=timeout_s,
            rules_dir=rules_dir,
            policy=ScanPolicy(policy),
            data=payload,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        digest = hashlib.sha256(payload).hexdigest() if payload is not None else UNKNOWN_SHA256
        return result_from_findings(
            sha256=digest, path=label, findings=[], incomplete_reason="scan failed"
        )


def _scan_file(
    file_path: Path,
    *,
    timeout_s: int,
    rules_dir: Path | None,
    policy: ScanPolicy,
    data: bytes | None = None,
) -> ScanResult:
    started = time.monotonic()
    budget = Budget(started + timeout_s)
    digest = UNKNOWN_SHA256
    findings: list[Finding] = []
    fingerprint: str | None = None
    engine_version: str | None = None
    skip_count = 0
    compiled = 0
    units = 0
    views: dict[str, int] = {}
    # Page-content streams of every PDF unit left unread, by the filter that kept them unread.
    unread: dict[str, int] = {}
    scanned_bytes = 0
    yara_time = 0.0
    cap = MatchCap()
    guard: GuardedRules | None = None

    def yara(
        rules: object,
        payload: bytes,
        ext: str,
        view: str | None,
        *,
        samples: bool = False,
        name: str = "",
    ) -> list[Finding]:
        nonlocal scanned_bytes, yara_time
        if view is not None:
            views[view] = views.get(view, 0) + 1
        # Only a view this long can fill a match list, so only it needs the guarded ruleset,
        # which is read from the cache here the first time (before the time left is taken).
        guarded = guard.rules() if guard is not None and len(payload) >= MATCH_LIMIT else None
        seconds = max(1, math.ceil(budget.deadline - time.monotonic()))
        begun = time.monotonic()
        try:
            # Decoded PDF streams can be image samples, whose flat areas read as base64; a
            # validated raster's views say so through ``samples``.
            samples = samples or view == "pdf-flate"
            return _yara_findings(
                rules,
                payload,
                ext,
                seconds,
                samples=samples,
                overrides=overrides,
                vendor_dirs=vendor_dirs,
                name=name,
                placed=placed,
                digest=ruleset,
                guarded=guarded,
                cap=cap,
            )
        finally:
            scanned_bytes += len(payload)
            yara_time += time.monotonic() - begun

    def finish(reason: str | None = None) -> ScanResult:
        from yara_gate import __version__

        if reason is None and cap.full:
            # A string's list was full on the final scan: a match past it was never read.
            reason = MATCH_CAP_REASON
        result = result_from_findings(
            sha256=digest, path=str(file_path), findings=findings, incomplete_reason=reason
        )
        result.ruleset_sha256 = fingerprint
        result.engine_version = engine_version
        result.skipped_rule_files = skip_count
        result.compiled_rules = compiled
        result.tool_version = __version__
        result.detector_sha256 = detector_digest()
        result.scan_seconds = round(time.monotonic() - started, 3)
        result.units_scanned = units
        result.views_scanned = dict(sorted(views.items()))
        result.pdf_content_unread = dict(sorted(unread.items()))
        result.match_rescan_limit = cap.rescan_limit
        result.unguarded_rule_files = len(guard.unguarded) if guard is not None else 0
        result.bytes_scanned = scanned_bytes
        result.yara_seconds = round(yara_time, 3) if units else None
        result.policy = policy
        if result.verdict is Verdict.advisory:
            if policy is ScanPolicy.agent_ingest:
                result.verdict = Verdict.block
                result.policy_reason = INGEST_HOLD
            elif policy is ScanPolicy.agent_document and result.advisory:
                result.verdict = Verdict.block
                result.policy_reason = DOCUMENT_HOLD
            elif policy is ScanPolicy.agent_document:
                result.policy_reason = DOCUMENT_NOTES
        return result

    if data is None:
        if not file_path.is_file():
            return finish("unreadable file")
        try:
            if file_path.stat().st_size > MAX_FILE_BYTES:
                return finish("file exceeds 100MB")
            with file_path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        except OSError:
            return finish("unreadable file")
    if len(data) > MAX_FILE_BYTES:
        return finish("file exceeds 100MB")
    digest = hashlib.sha256(data).hexdigest()
    root = rules_dir or default_rules_dir()
    rules, _skipped, error, compiled, skip_count, ruleset = compile_ruleset(root)
    if error or rules is None:
        return finish(error or "yara-x missing")
    fingerprint = ruleset
    engine_version = yara_x_version()
    try:
        overrides = vendor_overrides()
    except (OSError, ValueError):
        return finish("invalid vendor-overrides.json")
    # An override applies only to a match from the pack directory its entry names.
    vendor_dirs = vendor_namespace_dirs(ruleset)
    placed = placed_rule_sources(ruleset)
    guard = guarded_rules(ruleset)
    # Only the submitted name: the directories above it belong to the operator.
    findings.extend(_name_findings([file_path.name]))
    read_paths: set[tuple[str, ...]] = set()
    reread: list[list[str]] = []
    try:
        for unit in content_units(ContentUnit(file_path.name, data), budget):
            budget.check()
            units += 1
            unit_start = len(findings)
            path = Path(unit.name)
            kind = sniff(unit.data)
            extra: list[Finding] = []
            if unit.member_path:
                # Every component: an Invoice.pdf.app bundle hides behind its inner file names.
                extra.extend(_name_findings(path.parts))
            if is_executable_kind(kind) and unit.member_path and is_document_name(file_path):
                extra.append(
                    Finding(
                        rule_id="heuristic_document_executable",
                        severity=Severity.block,
                        source=FindingSource.heuristic,
                    )
                )
            if is_executable_kind(kind) and len(unit.member_path) >= 2:
                extra.append(
                    Finding(
                        rule_id="heuristic_nested_executable",
                        severity=Severity.block,
                        source=FindingSource.heuristic,
                    )
                )
            if mismatch(path, kind):
                if unit.data:
                    extra.append(
                        Finding(
                            rule_id=f"filetype_mismatch_{kind}",
                            severity=Severity.block
                            if kind in {"pe", "elf", "macho"}
                            else Severity.advisory,
                            source=FindingSource.filetype,
                        )
                    )
                else:
                    # Zero bytes sniff as text; a cloud placeholder is not a disguised type.
                    extra.append(
                        Finding(
                            rule_id="heuristic_empty_file",
                            severity=Severity.advisory,
                            source=FindingSource.heuristic,
                        )
                    )
            ext = path.suffix.lower().removeprefix(".")
            # The final name component, for rules about files known by name (.envrc,
            # devcontainer.json) that have no telling suffix. An archive member named with
            # backslashes is a directory path on Windows, wherever the scan runs, and Windows
            # drops trailing dots and spaces from a name it creates.
            base = PurePosixPath(unit.name.replace("\\", "/")).name.rstrip(". ").lower()
            # A .bmp, .tif, .emf, or .wmf whose header validates holds image samples. Its raw
            # bytes and every text view are still scanned, in the same samples mode as the
            # pdf-flate view: a base64 run must hold data beyond repeats and grain, and a
            # Unicode control must sit in UTF-8 text. Text a reader or interpreter would see
            # (a script, a phrase, a real payload) is checked as in any other unit.
            image = raster_image(path.suffix, unit.data)
            extra.extend(yara(rules, unit.data, ext, None, samples=image, name=base))
            # Object streams are indexed on first use, for an /OpenAction reference only.
            pdf_objects = PdfObjects(unit.data, budget)
            heuristic, office_error = heuristic_findings(path, unit.data, pdf_objects, budget.check)
            extra.extend(heuristic)
            decoded = _decoded_text(unit.name, unit.data, budget)
            readings = _readings(unit.data, decoded)
            for text, view in readings:
                for finding in [
                    *joiner_findings(text, budget.check),
                    *tag_findings(text),
                    *variation_findings(text),
                ]:
                    finding.view = view
                    extra.append(finding)
            for finding in extra:
                finding.member_path = list(unit.member_path)
            findings.extend(extra)
            if office_error:
                return finish(office_error)
            # A rule a later reading finds in a view an earlier reading already reported it in
            # is the same finding.
            earlier: set[tuple[str, str | None, str]] = set()
            current: set[tuple[str, str | None, str]] = set()
            knowns: list[tuple[str, str] | None] = [*readings] or [None]
            for marked, derived in chain.from_iterable(
                _marked(text_views(unit.data, budget, name=unit.name, known=known))
                for known in knowns
            ):
                if marked is None:
                    earlier |= current
                    continue
                view = marked
                budget.check()
                view_findings = yara(rules, derived, ext, view, samples=image, name=base)
                if _raw_only(view):
                    # Folding rewrites digits inside base64 (0 to o), which breaks the media
                    # exemptions; the raw bytes already carry the base64 verdict, and folding
                    # cannot create a real encoded payload that the raw view missed. The
                    # decoded views are the text a base64 or percent run spells, judged by
                    # the lexical rules; the run itself was judged in the raw view.
                    view_findings = [f for f in view_findings if f.rule_id not in _RAW_ONLY_RULES]
                if view == "base64-decoded":
                    view_findings.extend(_encoded_phrase_findings(derived, view_findings))
                if view == "html-unescaped":
                    # An entity such as &zwnj; hides a joiner that the raw check cannot see.
                    view_findings.extend(joiner_findings(derived.decode("utf-8"), budget.check))
                if view in {"html-unescaped", "json-unescaped"}:
                    # &#xE0049; or \udb40\udc49 spells a tag character the raw bytes do not hold,
                    # and an escaped run of variation selectors is hidden the same way.
                    view_text = derived.decode("utf-8")
                    view_findings.extend(tag_findings(view_text))
                    view_findings.extend(variation_findings(view_text))
                for finding in view_findings:
                    key = (finding.rule_id, finding.namespace, view)
                    if key in earlier:
                        continue
                    current.add(key)
                    finding.member_path = list(unit.member_path)
                    finding.view = view
                    findings.append(finding)
            streams = pdf_streams(unit.data, budget, pdf_objects.decoded)
            findings.extend(_pdf_unread_findings(unit, streams, unread))
            for view, derived in pdf_views(unit.data, budget, pdf_objects.decoded, streams):
                budget.check()
                view_findings = yara(rules, derived, ext, view, name=base)
                if view in _RAW_ONLY_VIEWS:
                    view_findings = [f for f in view_findings if f.rule_id not in _RAW_ONLY_RULES]
                    view_findings.extend(_encoded_phrase_findings(derived, view_findings))
                else:
                    # An action dictionary inside an object stream is invisible to the raw check.
                    view_findings.extend(pdf_token_findings(derived, pdf_objects, budget.check))
                for finding in view_findings:
                    finding.member_path = list(unit.member_path)
                    finding.view = view
                    findings.append(finding)
            text_findings, strings = _pdf_text_findings(
                rules, unit, streams, pdf_objects, budget, yara, ext, base
            )
            findings.extend(text_findings)
            findings.extend(
                _hidden_text_findings(
                    rules,
                    unit,
                    "ooxml-hidden-text",
                    ooxml_hidden_texts(unit.name, unit.data, budget),
                    budget,
                    yara,
                    ext,
                    base,
                )
            )
            # An Office part that readers take differently gives one view for each reading;
            # a rule is reported once for the unit and view, whichever readings held it.
            joined: set[tuple[str, str | None, str]] = set()
            for view, derived in chain(
                ooxml_text_views(unit.name, unit.data, budget),
                odf_text_views(unit.data, budget),
            ):
                budget.check()
                # A sentence split across Word runs or an OpenDocument span is one sentence
                # to the reader.
                found = yara(rules, derived, ext, view, name=base)
                if _raw_only(view):
                    found = [f for f in found if f.rule_id not in _RAW_ONLY_RULES]
                for finding in found:
                    if (finding.rule_id, finding.namespace, view) in joined:
                        continue
                    joined.add((finding.rule_id, finding.namespace, view))
                    finding.member_path = list(unit.member_path)
                    finding.view = view
                    findings.append(finding)

            # A worksheet cell split across rich-text runs, an HTML paragraph split by bold, a
            # link, or a comment, a Markdown paragraph split by emphasis or a code span, a
            # sentence wrapped over two comment lines, and a notebook cell stored as a list of
            # lines are each one piece of text to the reader.
            _piece_findings(
                rules,
                unit,
                _reader_pieces(unit, strings, readings, budget),
                budget,
                yara,
                ext,
                base,
                output=findings,
            )
            hidden_seen: set[tuple[str, str | None, str]] = set()
            for reading, _ in readings:
                for finding in _html_hidden_findings(
                    rules, unit, reading, findings[unit_start:], budget, yara, ext, base
                ):
                    key = (finding.rule_id, finding.namespace, finding.view)
                    if key not in hidden_seen:
                        hidden_seen.add(key)
                        findings.append(finding)
            conjunction = control_conjunction(findings[unit_start:])
            if conjunction is not None:
                conjunction.member_path = list(unit.member_path)
                findings.append(conjunction)
            # A mail part with a padded transfer encoding is read twice, decoded and as
            # written, under its one member path. A match both readings share is one finding.
            member_path = list(unit.member_path)
            if unit.member_path in read_paths:
                same_path = [f for f in findings[:unit_start] if f.member_path == member_path]
                findings[unit_start:] = [f for f in findings[unit_start:] if f not in same_path]
            read_paths.add(unit.member_path)
            # The one body of a message opened for that body is this unit's text read again,
            # and it was scanned first. What it found is kept under its member path only when
            # this unit did not find the same rule at the same severity, in whichever view.
            if unit.reread:
                reread.append(member_path)
            elif any(path[:-1] == member_path for path in reread):
                own = {(f.rule_id, f.severity) for f in findings[unit_start:]}
                findings[:] = [
                    f
                    for f in findings
                    if not (
                        f.member_path in reread
                        and f.member_path[:-1] == member_path
                        and (f.rule_id, f.severity) in own
                    )
                ]
                reread = [path for path in reread if path[:-1] != member_path]
            budget.check()
    except ContentLimit as exc:
        return finish(str(exc))
    except ScanTimeout:
        return finish("timeout")
    except Exception:
        return finish("content scan failed")
    return finish()


def _pdf_unread_findings(
    unit: ContentUnit, streams: list[PdfStream], unread: dict[str, int]
) -> list[Finding]:
    """``heuristic_pdf_content_unread`` when page content in this unit was not decoded.

    A stream a ``/Contents`` entry names, or a form XObject, whose filter chain the PDF views
    cannot decode (a filter with no decoder here, or LZW or RunLength past its size cap) holds
    text a reader with that decoder shows and no view read. It is a note, as unmapped glyphs
    are: ``agent-ingest`` holds it, ``agent-document`` records it. Each such stream is counted
    in ``unread`` under its filter. Images, fonts, and other resources are never counted.
    """
    labels = [stream.unread for stream in streams if stream.unread is not None]
    for label in labels:
        unread[label] = unread.get(label, 0) + 1
    if not labels:
        return []
    return [
        Finding(
            rule_id="heuristic_pdf_content_unread",
            severity=Severity.note,
            source=FindingSource.heuristic,
            member_path=list(unit.member_path),
            view="pdf-text",
        )
    ]


def _pdf_text_findings(
    rules: object,
    unit: ContentUnit,
    streams: list[PdfStream],
    objects: PdfObjects,
    budget: Budget,
    yara: Callable[..., list[Finding]],
    ext: str,
    name: str,
) -> tuple[list[Finding], PdfStrings]:
    """Scan the text a reader sees: each text block (``pdf-text``), then each paragraph that
    spans blocks (``pdf-paragraph``), including each piece's folded spelling when different.
    Marked content's /ActualText (``pdf-actual-text``) is read from the content streams and
    from property lists written as objects, as one view. The file's other text strings are
    returned for the caller to scan.

    A block is one text object's strings, cut at a paragraph break, so a phrase cannot be
    assembled from two paragraphs. A paragraph view exists only when a word in bold or a
    wrapped line split it across blocks. One finding per rule is kept for each view. A
    composite font whose strings could not be decoded, or a font name that means more fonts
    than are decoded, leaves text unread, which is reported as the note
    ``heuristic_pdf_text_unmapped``.
    """
    text = pdf_text(unit.data, streams, objects, budget)
    strings = pdf_string_texts(unit.data, objects, budget)
    extra: list[Finding] = []
    if text.unmapped:
        extra.append(
            Finding(
                rule_id="heuristic_pdf_text_unmapped",
                severity=Severity.note,
                source=FindingSource.heuristic,
                view="pdf-text",
            )
        )
    pieces = [
        ("pdf-text", text.blocks),
        ("pdf-text" + FOLDED_SUFFIX, _fold_pdf_pieces(text.blocks, budget)),
        ("pdf-paragraph", text.paragraphs),
        ("pdf-paragraph" + FOLDED_SUFFIX, _fold_pdf_pieces(text.paragraphs, budget)),
    ]
    # Marked content's /ActualText, which poppler and PDFium show in place of its glyphs.
    actual: list[str] = []
    for raw in text.actual_texts:
        budget.check()
        if (value := shown_string(raw)).strip():
            actual.append(value)
    # A property list a page names from its /Properties (``/Span /MC0 BDC``) is an object.
    actual = list(dict.fromkeys([*actual, *strings.actual]))
    if actual:
        pieces += [
            ("pdf-actual-text", actual),
            ("pdf-actual-text" + FOLDED_SUFFIX, _fold_pdf_pieces(actual, budget)),
        ]
    found = _piece_findings(rules, unit, pieces, budget, yara, ext, name, extra)
    hidden = _hidden_text_findings(
        rules, unit, "pdf-hidden-text", text.hidden, budget, yara, ext, name
    )
    return found + hidden, strings


# Rules that match invisible characters by their UTF-8 bytes: the Unicode-control notes and the
# zero-width run, which is advisory and so not one of the notes the conjunction reads. In a
# decoded PDF stream their bytes can be image samples, so a match needs UTF-8 text beside it.
_CONTROL_BYTES_RULES = CONTROL_BYTES_RULES

# Rules whose match is not an instruction to the reader: the invisible-character rules (the
# notes' own conjunction covers them) and the base64 rules, which are left to the raw bytes.
_NOT_INSTRUCTIONS = _CONTROL_BYTES_RULES | {"agent_base64_blob", "agent_base64_executable"}


def _hidden_text_findings(
    rules: object,
    unit: ContentUnit,
    view: str,
    texts: Sequence[str],
    budget: Budget,
    yara: Callable[..., list[Finding]],
    ext: str,
    name: str,
) -> list[Finding]:
    """``heuristic_hidden_text`` when an instruction rule matches text a reader does not show.

    ``texts`` are the hidden pieces of one unit (``ooxml-hidden-text``, ``pdf-hidden-text``),
    each scanned on its own, then folded as ``<view>+text-folded`` if the plain spelling held
    nothing. A note or advisory match from an ``agent_`` rule there is the conjunction, reported
    once per unit as an advisory with the view label; the rule's own finding already comes from
    the views that read every run. Hidden text with no instruction reports nothing: templates,
    watermarks, and OCR layers hide text all the time.
    """
    if not texts:
        return []
    for label, pieces in _with_folded_pieces(view, texts, budget):
        for found in _piece_findings(rules, unit, [(label, pieces)], budget, yara, ext, name):
            if _is_instruction(found):
                return [_hidden_text(unit, label)]
    return []


def _is_instruction(found: Finding) -> bool:
    """A note or advisory match of an ``agent_`` rule that reads as an instruction."""
    return (
        found.rule_id.startswith("agent_")
        and found.rule_id not in _NOT_INSTRUCTIONS
        and found.severity in (Severity.note, Severity.advisory)
    )


def _hidden_text(unit: ContentUnit, view: str) -> Finding:
    return Finding(
        rule_id="heuristic_hidden_text",
        severity=Severity.advisory,
        source=FindingSource.heuristic,
        member_path=list(unit.member_path),
        view=view,
    )


# The also-shown test reads the page's shown text once for each hidden piece that holds an
# instruction. Past this many bytes of it in one member, a piece counts as hidden untested.
_ALSO_SHOWN_BYTES = 256 * 1024 * 1024


def _html_hidden_findings(
    rules: object,
    unit: ContentUnit,
    text: str,
    found: Sequence[Finding],
    budget: Budget,
    yara: Callable[..., list[Finding]],
    ext: str,
    name: str,
) -> list[Finding]:
    """``heuristic_hidden_text`` when an instruction rule matches HTML text a browser hides.

    ``found`` are the member's findings so far. The lexical rule ``agent_hidden_html`` keeps
    reporting what it already reports: when it matched this member, nothing is added, so a
    file it holds today gives the same findings. Otherwise each hidden piece
    (``htmlhidden.html_hidden_texts``) is scanned on its own as ``html-hidden-text``, then folded
    as ``html-hidden-text+text-folded`` when that spelling differs. The first piece that holds
    an instruction and whose text the page does not also show is the finding, once per member,
    labeled with the view. A piece the page also shows (a share widget's copy of the title, a
    mail preheader that repeats the first line) is not hidden from the reader and is skipped.
    Hidden text with no instruction reports nothing: menus, dialogs, templates, and tracking
    attributes hide text on every page.
    """
    if any(item.rule_id == "agent_hidden_html" for item in found):
        return []
    hidden = html_hidden_texts(unit.name, text, budget)
    if not hidden.pieces:
        return []
    view = "html-hidden-text"
    read = 0
    _SCANNERS.reuse = True
    try:
        for piece in hidden.pieces:
            budget.check()
            folded = folded_text(piece)
            spellings = [(view, piece)]
            if folded != piece:
                spellings.append((view + FOLDED_SUFFIX, folded))
            for label, spelling in spellings:
                hits = yara(rules, _derived(spelling, budget), ext, label, name=name)
                if not any(_is_instruction(hit) for hit in hits):
                    continue
                if read <= _ALSO_SHOWN_BYTES:
                    read += len(hidden.shown)
                    if html_also_shown(hidden, piece):
                        break
                return [_hidden_text(unit, label)]
    finally:
        _SCANNERS.reuse = False
        _SCANNERS.pair = None
    return []


def _reader_pieces(
    unit: ContentUnit, strings: PdfStrings, readings: Sequence[tuple[str, str]], budget: Budget
) -> Iterator[tuple[str, Iterable[str]]]:
    """Produce groups lazily so each reader's pieces can be scanned and released."""
    yield from _with_folded_pieces(
        "ooxml-cell", ooxml_cell_texts(unit.name, unit.data, budget), budget
    )
    yield from _with_folded_pieces(
        "ooxml-comment", ooxml_comment_texts(unit.name, unit.data, budget), budget
    )
    # A worksheet's page header or footer, one section at a time.
    yield from _with_folded_pieces(
        "ooxml-header", ooxml_header_texts(unit.name, unit.data, budget), budget
    )
    yield from _with_folded_pieces("rtf-text", rtf_texts(unit.data, budget), budget)
    yield from _with_folded_pieces("pdf-annotation", strings.annotations, budget)
    # A form field's value, a document information string, and an outline title.
    yield from _with_folded_pieces("pdf-string", strings.shown, budget)
    # Both readings' pieces share their views, so a rule is reported once per view.
    for reading, _ in readings:
        yield from _with_folded_pieces(
            "html-text", html_text_blocks(unit.name, reading, budget), budget
        )
        yield from _with_folded_pieces(
            "markdown-text", markdown_texts(unit.name, reading, budget), budget
        )
        yield from _with_folded_pieces("feed-text", feed_texts(reading, budget), budget)
        yield from _with_folded_pieces("xml-text", xml_texts(unit.name, reading, budget), budget)
        yield from _with_folded_pieces(
            "config-unescaped",
            config_unescaped_texts(unit.name, reading, budget),
            budget,
        )
        cells = notebook_texts(unit.name, reading, budget)
        yield from _with_folded_pieces(
            "notebook-text",
            [text for text, lines, _ in cells if lines >= 2],
            budget,
        )
        # A comment inside a code cell is inside a JSON string in the raw text.
        comments = comment_texts(reading, budget)
        for text, _, code in cells:
            if code:
                comments += comment_texts(text, budget)
                if len(comments) > MAX_TEXT_PIECES:
                    raise ContentLimit("text pieces exceed 100000")
        yield from _with_folded_pieces("comment-text", comments, budget)


def _piece_findings(
    rules: object,
    unit: ContentUnit,
    pieces: Iterable[tuple[str, Iterable[str]]],
    budget: Budget,
    yara: Callable[..., list[Finding]],
    ext: str,
    name: str,
    extra: Sequence[Finding] = (),
    *,
    output: list[Finding] | None = None,
) -> list[Finding]:
    """One YARA pass per piece of text, keeping one finding per rule and namespace per view.

    A piece is text a reader sees as one unit (a PDF text block, a worksheet cell, an HTML
    paragraph), scanned on its own so two pieces never form one phrase. The base64 rules are
    left to the raw bytes, where image samples and media are told apart. ``extra`` findings
    (already labeled with their view) are kept in their view's order.
    """
    # Keyed by namespace and rule: two rule files may share an id with different severities.
    views: dict[str, dict[tuple[str, str], Finding]] = {}
    ordered = [] if output is None else output
    _SCANNERS.reuse = True
    try:
        for view, texts in pieces:
            matches = views.setdefault(view, {})
            for piece in texts:
                budget.check()
                for finding in yara(rules, _derived(piece, budget), ext, view, name=name):
                    if finding.rule_id in _RAW_ONLY_RULES:
                        continue
                    matches.setdefault((finding.rule_id, finding.namespace or ""), finding)
    finally:
        _SCANNERS.reuse = False
        _SCANNERS.pair = None
        # A later reader can hit a limit. Preserve matches from pieces already scanned.
        for finding in extra:
            views.setdefault(finding.view, {})[(finding.rule_id, finding.namespace or "")] = finding
        for view, found in views.items():
            for key in sorted(found):
                finding = found[key]
                finding.member_path = list(unit.member_path)
                finding.view = view
                ordered.append(finding)
    return ordered


def _fold_pdf_pieces(texts: Sequence[str], budget: Budget) -> Iterator[str]:
    for piece in texts:
        budget.check()
        folded = folded_text(piece)
        if folded != piece:
            yield folded


def _with_folded_pieces(
    view: str, texts: Iterable[str], budget: Budget
) -> Iterator[tuple[str, Iterable[str]]]:
    """Scan original pieces as they arrive, then their changed folded spellings."""
    folded: list[str] = []

    def originals() -> Iterator[str]:
        for piece in texts:
            budget.check()
            yield piece
            result = folded_text(piece)
            if result != piece:
                folded.append(result)

    yield view, originals()
    if folded:
        yield view + FOLDED_SUFFIX, folded


_SCANNERS = threading.local()


# The phrases the retired YARA rule agent_encoded_instruction matched in base64 (its id and
# note severity are kept). It matched raw substrings, so a phrase run into the word before it
# was still found; the lexical rules need a word boundary. Encoded text keeps that stricter
# reading on purpose: plain text with the same glued phrase is not reported.
_ENCODED_PHRASES = (b"ignore previous instructions", b"ignore all previous instructions")


def _encoded_phrase_findings(derived: bytes, found: Sequence[Finding]) -> list[Finding]:
    """The retired encoded-instruction note, when a decoded run holds a phrase as a substring
    and the lexical rules did not already report one there."""
    if any(f.rule_id == "agent_prompt_injection_phrases" for f in found):
        return []
    lowered = derived.lower()
    if not any(phrase in lowered for phrase in _ENCODED_PHRASES):
        return []
    return [
        Finding(
            rule_id="agent_encoded_instruction",
            severity=Severity.note,
            source=FindingSource.heuristic,
        )
    ]


_RAW_ONLY_RULES = frozenset({"agent_base64_blob", "agent_base64_executable"})
_RAW_ONLY_VIEWS = frozenset(
    {"text-folded", "base64-decoded", "percent-decoded", "mime-headers-decoded"}
)


def _raw_only(view: str) -> bool:
    """True for a view in which the base64 rules are left to the raw bytes: a decoded view,
    and every folded view, whose look-alike folding rewrites digits inside base64."""
    return view in _RAW_ONLY_VIEWS or view.endswith(FOLDED_SUFFIX)


def _name_findings(parts: Sequence[str]) -> list[Finding]:
    found: list[Finding] = []
    if any(double_extension(Path(part)) for part in parts):
        found.append(
            Finding(
                rule_id="heuristic_double_extension",
                severity=Severity.block,
                source=FindingSource.heuristic,
            )
        )
    if any(name_has_controls(part) for part in parts):
        found.append(
            Finding(
                rule_id="heuristic_filename_control",
                severity=Severity.block,
                source=FindingSource.heuristic,
            )
        )
    return found


def _marked(views: Iterator[tuple[str, bytes]]) -> Iterator[tuple[str | None, bytes]]:
    """``views``, then a ``None`` marker where the next reading's views begin."""
    yield from views
    yield None, b""


def _readings(data: bytes, decoded: tuple[str, str] | None) -> list[tuple[str, str]]:
    """The reading ``decoded_text`` chose, and for a declared charset also the UTF-8 one.

    A consumer that ignores the declaration decodes the bytes as UTF-8. A meta and one stray
    byte must not hide what that reading shows (tag characters, a phrase written in UTF-8),
    so both are scanned and a rule both find in a view is one finding.
    """
    if decoded is None:
        return []
    if decoded[1] != "decoded-charset":
        return [decoded]
    try:
        utf8 = (data.decode("utf-8"), "raw")
    except UnicodeError:
        utf8 = (data.decode("utf-8", errors="replace"), "utf8-replaced")
    return [decoded, utf8]


def _decoded_text(name: str, data: bytes, budget: Budget) -> tuple[str, str] | None:
    if sniff(data) != "text":
        return None
    try:
        return decoded_text(name, data, budget)
    except UnicodeError:
        # UTF-16 that does not decode; ``text_views`` reports it as incomplete.
        return None


def archive_limit(data: bytes, *, depth: int = 0) -> str | None:
    """Inspect archive coverage with the same bounded reader used by scans."""
    try:
        for _unit in content_units(ContentUnit("archive", data), Budget(float("inf")), depth):
            pass
    except ContentLimit as exc:
        return str(exc)
    return None


def _yara_findings(
    rules: object,
    data: bytes,
    ext: str,
    timeout_s: int,
    *,
    samples: bool = False,
    overrides: Mapping[tuple[str, str], str] | None = None,
    vendor_dirs: Mapping[str, str] | None = None,
    name: str = "",
    placed: Mapping[str, tuple[str, frozenset[str]]] | None = None,
    digest: str | None = None,
    guarded: object | None = None,
    cap: MatchCap | None = None,
) -> list[Finding]:
    if guarded is not None and len(data) >= MATCH_LIMIT:
        # A list holds one match per start offset, so none can fill in a shorter view.
        logs: list[str] = []
        begun = time.monotonic()
        result = _invoke_scan(guarded, data, timeout_s, ext, samples=samples, name=name, log=logs)
        took = time.monotonic() - begun
        # A rescan reads more matches than the first scan; one that cannot finish in the time
        # left would only end as a timeout, so the full list is reported instead.
        left = timeout_s - took
        if logs and len(logs) <= RESCAN_MAX_FULL and left > took * RESCAN_TIME_FACTOR:
            logs = []
            # The first result holds a Python object for every match of every matching public
            # rule; kept alive through the rescan it added 11 to 14 percent to the peak.
            result = None
            result = _invoke_scan(
                guarded,
                data,
                max(1, math.ceil(left)),
                ext,
                samples=samples,
                name=name,
                limit=RESCAN_LIMIT,
                log=logs,
            )
            if cap is not None:
                cap.rescan_limit = RESCAN_LIMIT
        if logs and cap is not None:
            cap.full = True
    else:
        result = _invoke_scan(rules, data, timeout_s, ext, samples=samples, name=name)
    findings: list[Finding] = []
    scan_globals: list[tuple[str, object]] | None = None
    for rule in getattr(result, "matching_rules", ()):
        meta = {str(key): value for key, value in getattr(rule, "metadata", ())}
        rule_id = str(getattr(rule, "identifier", "rule"))
        mode = meta.get("verdict_on_match")
        namespace = str(getattr(rule, "namespace", "")) or None
        if mode is None:
            # A rule without verdict_on_match is a vendor rule. Its severity comes from the
            # reviewed rules/vendor-overrides.json entry for its pack and name, and it blocks
            # when the list has none; a rule outside vendor/ has no pack and always blocks.
            pack = (vendor_dirs or {}).get(namespace or "")
            mode = (overrides or {}).get((pack, rule_id), "block") if pack else "block"
            if mode == "skip":
                continue
        if mode not in ("note", "advisory", "block"):
            mode = "block"
        located = _first_match(rule, data, text_only=samples and rule_id in _CONTROL_BYTES_RULES)
        if located is None:
            # Every match of a control rule sits in bytes that are not UTF-8 text.
            continue
        source, placed_ids = (placed or {}).get(namespace or "", ("", frozenset()))
        if located == (None, None) and rule_id in placed_ids:
            # The guarded ruleset keeps this rule's strings in a private rule, so the result
            # holds no match for it.
            if scan_globals is None:
                scan_globals = _scan_globals(data, ext, name, samples)
            shown = _located_rule(
                rule_id, data, digest, namespace or "", source, scan_globals, timeout_s
            )
            if shown is not None:
                rule = shown
                located = _first_match(rule, data, text_only=False) or (None, None)
        if (
            rule_id in placed_ids
            and rule_id not in _CONTROL_BYTES_RULES
            and len(data) <= WITNESS_MAX_BYTES
        ):
            if scan_globals is None:
                scan_globals = _scan_globals(data, ext, name, samples)
            located = _deciding_match(
                rule,
                rule_id,
                data,
                located,
                _witness_rules(digest, namespace or "", source),
                scan_globals,
                timeout_s,
            )
        offset, length = located
        findings.append(
            Finding(
                rule_id=rule_id,
                offset=offset,
                length=length,
                severity=Severity(str(mode)),
                source=FindingSource.yara,
                namespace=namespace,
            )
        )
    return findings


def _first_match(
    rule: object, data: bytes, *, text_only: bool
) -> tuple[int | None, int | None] | None:
    """The first match's offset and length, or (None, None) when the rule has no match data.

    With ``text_only``, the first match whose surroundings read as UTF-8 text, and None when
    there are matches and none does: decoded PDF streams can hold image samples whose bytes
    spell a control character.
    """
    matched = False
    for pattern in getattr(rule, "patterns", ()):
        for match in getattr(pattern, "matches", ()):
            offset, length = int(match.offset), int(match.length)
            if not text_only or control_in_text(data, offset, length):
                return offset, length
            matched = True
    return None if matched else (None, None)


# A view larger than this reports a placed rule's first match: the deciding match is found by
# scanning prefixes of the view again, about twenty times at most (#284).
WITNESS_MAX_BYTES = 1 << 20
# Placed rule files compiled one at a time, for the prefix scans: (ruleset digest, namespace).
_WITNESS_RULES: dict[tuple[str, str], Any] = {}


def _witness_rules(digest: str | None, namespace: str, source: str) -> Any:
    key = (digest or "", namespace)
    rules = _WITNESS_RULES.get(key)
    if rules is None:
        if any(cached != key[0] for cached, _ in list(_WITNESS_RULES)):
            _WITNESS_RULES.clear()
        rules = _WITNESS_RULES[key] = compile_source(source)
    return rules


def _deciding_match(
    rule: object,
    rule_id: str,
    data: bytes,
    located: tuple[int | None, int | None],
    rules: Any,
    scan_globals: list[tuple[str, object]],
    timeout_s: int,
) -> tuple[int | None, int | None]:
    """The match that made a placed rule fire, where its first match did not.

    A rule that reads where its matches lie can fire on a match its first one is not: a
    quotation exempts the order it names and a later order fires; a refusal covers its
    request and a separate request fires. The first match stays the answer when the rule
    no longer fires with that match's first byte blanked out, so a rule that needs it reports it as
    before. Otherwise the answer is the match that ends where the rule first fires on a
    prefix of ``data``, found by bisecting the ends of its matches. YARA-X reads the same
    rule file alone, with the globals of the whole view. Any timeout keeps the first match.
    """
    import yara_x

    offset, length = located
    if offset is None or length is None:
        return located
    ends = sorted(
        {
            int(match.offset) + int(match.length)
            for pattern in getattr(rule, "patterns", ())
            for match in getattr(pattern, "matches", ())
        }
    )
    try:
        # One byte: a later match that overlaps this one keeps its bytes.
        blanked = data[:offset] + b" " + data[offset + 1 :]
        if not ends or not _fires(rules, rule_id, blanked, scan_globals, timeout_s):
            return located
        if not _fires(rules, rule_id, data[: ends[-1]], scan_globals, timeout_s):
            return located
        low, high = 0, len(ends) - 1
        while low < high:
            middle = (low + high) // 2
            if _fires(rules, rule_id, data[: ends[middle]], scan_globals, timeout_s):
                high = middle
            else:
                low = middle + 1
    except yara_x.TimeoutError:
        return located
    # The first match is not needed, so another match ending at the same byte is the answer.
    for pattern in getattr(rule, "patterns", ()):
        for match in getattr(pattern, "matches", ()):
            found = int(match.offset), int(match.length)
            if found[0] + found[1] == ends[low] and found != (offset, length):
                return found
    return located


# The most matches of one string the locating scan keeps: the first match is all it reads.
LOCATE_LIMIT = 1024
# Rule files compiled for the locating scan: (ruleset digest, namespace).
_LOCATE_RULES: dict[tuple[str, str], Any] = {}


def _located_rule(
    rule_id: str,
    data: bytes,
    digest: str | None,
    namespace: str,
    source: str,
    scan_globals: list[tuple[str, object]],
    timeout_s: int,
) -> object | None:
    """The matches of a rule the guarded ruleset reports without its strings.

    The rule's file is scanned alone with every condition replaced by ``any of them``. A view
    the deciding match is looked for in gets every match, as the rule's own list held; a
    larger one keeps each string to its first ``LOCATE_LIMIT`` matches, since only the first
    match is read there, so the cost does not grow with a flood. None when the file cannot be
    rewritten or the scan times out.
    """
    import yara_x

    key = (digest or "", namespace)
    try:
        rules = _LOCATE_RULES.get(key)
        if rules is None:
            text = locating_source(source)
            if text is None:
                return None
            if any(cached != key[0] for cached, _ in list(_LOCATE_RULES)):
                _LOCATE_RULES.clear()
            rules = _LOCATE_RULES[key] = compile_source(text)
        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(timeout_s)
        scanner.max_matches_per_pattern(
            MATCH_LIMIT if len(data) <= WITNESS_MAX_BYTES else LOCATE_LIMIT
        )
        for global_name, value in scan_globals:
            try:
                scanner.set_global(global_name, value)
            except (TypeError, ValueError):
                pass
        result = scanner.scan(data)
    except (yara_x.CompileError, yara_x.TimeoutError):
        return None
    for rule in result.matching_rules:
        if str(rule.identifier) == rule_id:
            return rule
    return None


def _fires(
    rules: Any, rule_id: str, data: bytes, scan_globals: list[tuple[str, object]], timeout_s: int
) -> bool:
    import yara_x

    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(timeout_s)
    for global_name, value in scan_globals:
        try:
            scanner.set_global(global_name, value)
        except (TypeError, ValueError):
            pass
    result = scanner.scan(data)
    return any(str(rule.identifier) == rule_id for rule in result.matching_rules)


def _guard_sink(log: list[str] | None) -> Callable[[str], None]:
    """A console callback that keeps the match-cap guards' lines; a rule's own logs are dropped."""

    def sink(line: str) -> None:
        if log is not None and line.startswith(GUARD_LOG_PREFIX):
            log.append(line)

    return sink


def _scan_globals(data: bytes, ext: str, name: str, samples: bool) -> list[tuple[str, object]]:
    """The values the scanner gives each global for one buffer."""
    blob, exe = base64_run_signals(data, samples=samples)
    return [
        ("yara_gate_ext", ext),
        ("yara_gate_name", name),
        ("yara_gate_text", sniff(data) == "text"),
        ("yara_gate_b64_blob", blob),
        ("yara_gate_b64_exe", exe),
        ("yara_gate_svg_scope_proven", svg_scope_proven(data)),
    ]


def _invoke_scan(
    rules: Any,
    data: bytes,
    timeout_s: int,
    ext: str,
    *,
    samples: bool = False,
    name: str = "",
    limit: int = MATCH_LIMIT,
    log: list[str] | None = None,
) -> object:
    """Scan ``data``. With ``log``, each list a match-cap guard found full is appended to it."""
    import yara_x

    # A Scanner costs about 0.6 ms to build, more than scanning a PDF paragraph, so the
    # pdf-text loop reuses one per compiled ruleset and thread. Every other call builds its
    # own: a reused Scanner reports matching rules in another order, and report order is
    # part of the recorded output. Every call sets the timeout and every global again.
    cached = getattr(_SCANNERS, "pair", None) if getattr(_SCANNERS, "reuse", False) else None
    if cached is not None and cached[0] is rules:
        scanner = cached[1]
    else:
        scanner = yara_x.Scanner(rules)
        if getattr(_SCANNERS, "reuse", False):
            _SCANNERS.pair = (rules, scanner)
    scanner.set_timeout(timeout_s)
    # A reused Scanner keeps its limit and log callback, so both are set on every call.
    scanner.max_matches_per_pattern(limit)
    scanner.console_log(_guard_sink(log))
    for global_name, value in [
        *_scan_globals(data, ext, name, samples),
        ("yara_gate_match_limit", limit),
    ]:
        try:
            scanner.set_global(global_name, value)
        except (TypeError, ValueError):
            pass
    try:
        return scanner.scan(data)
    except yara_x.TimeoutError as exc:
        raise ScanTimeout from exc
