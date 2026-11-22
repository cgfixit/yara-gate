"""Compile rules written for classic YARA the way the gate compiles a rule file.

YARA-X reads most rules written for YARA 4.x unchanged. This probe shows the rest, for
someone who brings rules from the older engine, such as a rule set kept for a backup
product's YARA scan. It runs the differences the YARA-X project documents, and a few it
does not, on the locked engine with the gate's own compiler settings, and it compiles a
folder of rule files one at a time and says which fail and why:

    uv run python docs/research/probe_yara_compat.py
    uv run python docs/research/probe_yara_compat.py RULES_DIR [--json]
    uv run --with yara-python python docs/research/probe_yara_compat.py --classic
    uv run --with yara-python python docs/research/probe_yara_compat.py RULES_DIR \
        --samples SAMPLES_DIR

The first form exits 1 when the engine no longer answers a case as the table below records,
which is what a YARA-X upgrade has to show. The second exits 1 when a file does not compile.
The third puts classic YARA beside each case. The fourth scans every file under
SAMPLES_DIR with each rule file on both engines and exits 1 when the two name different
rules for a sample. The last two need a package the locked environment does not hold.

Nothing is installed into a rules root and no rule is loaded into a gate. A case scans only
the few bytes it carries. A compiler message names the rule line it rejects, so the output
shows rule source and never scanned content; a sample is named by its path.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yara_x

from yara_gate import rules as gate_rules

FAILS = "does not compile under YARA-X"
DIFFERS = "compiles on both and answers differently"
RELAXED = "compiles here because the gate uses relaxed regular expressions"
REFUSED = "refused by the gate's compiler settings or this build"
SAME = "same answer on both"

_SHIFTED = base64.b64encode(b"xDhis program cannow")


@dataclass(frozen=True)
class Case:
    name: str
    group: str
    source: str
    data: bytes
    # What the gate's compiler and a scan of ``data`` give: "match", "no match", or an error code.
    gate: str
    # What yara-python 4.5.4 gave on November 22, 2026: "match", "no match", or "error".
    classic: str
    note: str
    # The rule whose match is the answer.
    rule: str = "r"


CASES = (
    Case(
        "base64-two-bytes",
        FAILS,
        'rule r { strings: $a = "ab" base64 condition: $a }',
        base64.b64encode(b"ab ab ab"),
        "E024",
        "match",
        "base64 needs a string of three bytes or more",
    ),
    Case(
        "of-rule-name-wildcard",
        FAILS,
        "rule fam_a { condition: true } rule r { condition: 1 of (fam_*) }",
        b"x",
        "E001",
        "match",
        "`of` takes rule names, no longer a wildcard over them",
    ),
    Case(
        "negative-match-index",
        FAILS,
        'rule r { strings: $a = "abc" condition: $a or @a[-1] > 0 }',
        b"abc abc",
        "E007",
        "match",
        "@a[-1] was always undefined in YARA 4.x; here it is an error",
    ),
    Case(
        "duplicate-modifier",
        FAILS,
        "private private rule p { condition: true } rule r { condition: p }",
        b"x",
        "E001",
        "match",
        "a modifier may appear once",
    ),
    Case(
        "entrypoint-keyword",
        FAILS,
        "rule r { strings: $a = { 90 90 } condition: $a at entrypoint }",
        b"\x90\x90",
        "E017",
        "no match",
        "use pe.entry_point or elf.entry_point",
    ),
    Case(
        "regex-unicode-class",
        FAILS,
        "rule r { strings: $a = /\\p{L}+/ condition: $a }",
        b"abc",
        "E014",
        "no match",
        "YARA 4.x read \\p as the letter p; relaxed mode does not",
    ),
    Case(
        "regex-empty-alternative",
        FAILS,
        "rule r { strings: $a = /BADD|Bad Error Happened|/ condition: $a }",
        b"xx BADD yy",
        "E014",
        "match",
        "a pattern that can match nothing at all is an error, relaxed or not",
    ),
    Case(
        "boolean-in-bitwise",
        FAILS,
        'import "pe"\nrule r { condition: pe.exports("Crash") & pe.characteristics }',
        b"MZ" + bytes(64),
        "E002",
        "no match",
        "YARA 4.x read a boolean as 0 or 1 beside `&`",
    ),
    Case(
        "xor-fullword",
        DIFFERS,
        'rule r { strings: $a = "mississippi" xor(1) fullword condition: $a }',
        b"{lhrrhrrhqqh}",
        "no match",
        "match",
        "the bytes around the string are now read after the XOR, not before",
    ),
    Case(
        "base64-shifted-neighbour",
        DIFFERS,
        'rule r { strings: $a = "This program cannot" base64 condition: $a }',
        _SHIFTED,
        "no match",
        "match",
        'YARA 4.x also matched the base64 of "Dhis program cannow" at one alignment',
    ),
    Case(
        "regex-literal-brace",
        RELAXED,
        "rule r { strings: $a = /abc{/ condition: $a }",
        b"xx abc{ yy",
        "match",
        "match",
        "strict YARA-X wants /abc\\{/",
    ),
    Case(
        "regex-mistyped-repeat",
        RELAXED,
        "rule r { strings: $a = /[0-9]{1:5}x/ condition: $a }",
        b"7{1:5}x",
        "match",
        "match",
        "{1:5} is not a repeat, so both read it as text: the rule's own mistake survives",
    ),
    Case(
        "regex-unknown-escape",
        RELAXED,
        "rule r { strings: $a = /x64\\Release\\\\create\\.pdb/ condition: $a }",
        b"C:\\x64Release\\create.pdb",
        "match",
        "match",
        "\\R is read as R, as YARA 4.x reads it",
    ),
    Case(
        "include",
        REFUSED,
        'include "other.yar"\nrule r { condition: true }',
        b"x",
        "E044",
        "error",
        "the gate loads every file itself so the ruleset digest covers every rule",
    ),
    Case(
        "external-filename",
        REFUSED,
        'rule r { strings: $a = "abc" condition: $a and filename matches /\\.txt$/ }',
        b"abc",
        "E009",
        "error",
        "the caller defines externals; the gate defines only its yara_gate_* globals",
    ),
    Case(
        "module-magic",
        REFUSED,
        'import "magic"\nrule r { condition: magic.mime_type() == "text/plain" }',
        b"hello",
        "E010",
        "error",
        "not in the YARA-X wheel, and not in the yara-python wheel either",
    ),
    Case(
        "module-hash-with-tag",
        SAME,
        'import "hash"\nrule SearchFileHash : SuppressMalwareDetectionNotification '
        '{ condition: hash.sha256(0, filesize) == "2cf24dba5fb0a30e26e83b2ac5b9e29e'
        '1b161e5c1fa7425e73043362938b9824" }',
        b"hello",
        "match",
        "match",
        "a tag compiles and is not read by the gate",
        "SearchFileHash",
    ),
    Case(
        "module-pe",
        SAME,
        'import "pe"\nrule r { condition: not pe.is_pe and uint16(0) == 0x5A4D '
        "and filesize < 5MB }",
        b"MZ" + bytes(100),
        "match",
        "match",
        "",
    ),
    Case(
        "wide-nocase-fullword",
        SAME,
        'rule r { strings: $a = "Invoke-Mimikatz" ascii wide nocase fullword condition: $a }',
        "x invoke-mimikatz y".encode("utf-16-le"),
        "match",
        "match",
        "",
    ),
    Case(
        "loop-over-offsets",
        SAME,
        'rule r { strings: $a = "ab" condition: for all i in (1..#a) : (@a[i] < 100) }',
        b"ab ab ab",
        "match",
        "match",
        "",
    ),
    Case(
        "hex-jump-and-alternative",
        SAME,
        "rule r { strings: $a = { 4D 5A [2-4] ( 50 45 | 4E 45 ) ?? 00 } condition: $a }",
        b"MZ\x00\x00\x00PE\x01\x00",
        "match",
        "match",
        "",
    ),
    Case(
        "global-rule",
        SAME,
        "global rule g { condition: filesize < 100 } rule r { condition: true }",
        bytes(200),
        "no match",
        "no match",
        "",
    ),
)

_CODE = re.compile(r"error\[(E\d+)\]: ([^\n]*)")
_PLACE = re.compile(r"--> [^\n:]*:(\d+):(\d+)")
_IMPORT = re.compile(r'(?m)^[ \t]*import[ \t]+"([^"]+)"')
_INCLUDE = re.compile(r'(?m)^[ \t]*include[ \t]+"')
_TAGS = re.compile(
    r"(?m)^[ \t]*(?:(?:private|global)[ \t]+)*rule[ \t]+\w+[ \t]*:[ \t]*([\w \t]+?)[ \t]*(?:\{|$)"
)
_VERDICT = re.compile(r"\bverdict_on_match\s*=")
_XOR_FULLWORD = re.compile(
    r"(?m)^[^\n/]*=\s*\"[^\n]*\"[^\n]*\b(?:xor\b[^\n]*\bfullword|fullword\b[^\n]*\bxor)\b"
)
_BASE64 = re.compile(r"(?m)^[^\n/]*=\s*\"[^\n]*\"[^\n]*\bbase64(?:wide)?\b")
# Externals a scanner front end commonly defines for classic rules; the gate defines none.
_EXTERNALS = frozenset({"filename", "filepath", "extension", "filetype", "owner"})
HINTS = {
    "E001": "a syntax YARA-X dropped (a wildcard over rule names in `of`, a repeated modifier) "
    "or never had",
    "E002": "an operand of the wrong type, such as a boolean beside `&`",
    "E007": "a negative index such as @a[-1]",
    "E010": "a module this build does not carry",
    "E014": "a regular expression YARA-X does not read even in relaxed mode",
    "E017": "the `entrypoint` keyword: use pe.entry_point or elf.entry_point",
    "E022": "a string no condition reads",
    "E024": "a string too short for its modifier (base64 needs three bytes)",
    "E044": "an include: put the rules in files of their own, the gate loads each one",
}


def _compile(source: str, origin: str = "rule.yar") -> Any:
    """One rule file under the gate's settings: relaxed regex, includes off, scan globals."""
    compiler = gate_rules._rule_compiler(yara_x)
    compiler.add_source(source, origin=origin)
    return compiler.build()


def _matched(rules: Any, data: bytes, name: str) -> bool:
    found = yara_x.Scanner(rules).scan(data).matching_rules
    return any(str(rule.identifier) == name for rule in found)


def _error(exc: Exception) -> tuple[str, str, int | None]:
    text = str(exc)
    code = _CODE.search(text)
    place = _PLACE.search(text)
    return (
        code.group(1) if code else exc.__class__.__name__,
        code.group(2) if code else text.strip().splitlines()[0],
        int(place.group(1)) if place else None,
    )


def gate_answer(case: Case) -> str:
    try:
        rules = _compile(case.source)
    except yara_x.CompileError as exc:
        return _error(exc)[0]
    return "match" if _matched(rules, case.data, case.rule) else "no match"


def strict_compiles(case: Case) -> bool:
    try:
        yara_x.compile(case.source)
    except yara_x.CompileError:
        return False
    return True


def classic_answer(case: Case, yara: Any) -> str:
    try:
        rules = yara.compile(source=case.source)
    except yara.Error:
        return "error"
    hits = rules.match(data=case.data)
    return "match" if any(hit.rule == case.rule for hit in hits) else "no match"


def run_cases(classic: bool) -> int:
    yara: Any = None
    if classic:
        try:
            import yara
        except ImportError:
            print("needs yara-python: uv run --with yara-python python ...", file=sys.stderr)
            return 2
    title = f"YARA-X {gate_rules.yara_x_version()}, compiled as the gate compiles a rule file"
    if yara is not None:
        title += f", beside classic YARA {yara.YARA_VERSION}"
    print(title)
    moved = 0
    group = ""
    for case in CASES:
        if case.group != group:
            group = case.group
            print(f"\n{group}")
        seen = gate_answer(case)
        line = f"  {case.name:26s} gate: {seen:9s}"
        if seen != case.gate:
            moved += 1
            line += f" (recorded: {case.gate})"
        if yara is not None:
            now = classic_answer(case, yara)
            line += f" classic: {now:9s}"
            if now != case.classic:
                line += f" (4.5.4 gave: {case.classic})"
        else:
            line += f" classic 4.5.4: {case.classic:9s}"
        if case.group == RELAXED and strict_compiles(case):
            moved += 1
            line += " (strict YARA-X now compiles it)"
        print(line + (f"  {case.note}" if case.note else ""))
    print(f"\nmodules in this build: {', '.join(yara_x.module_names())}")
    if moved:
        print(f"\n{moved} case(s) no longer answer as recorded: update CASES and the record")
        return 1
    return 0


def check_file(path: Path, root: Path, elsewhere: dict[str, str] | None = None) -> dict[str, Any]:
    """One rule file, compiled alone as the loader validates it. No file is scanned.

    ``elsewhere`` maps a rule name to the file that defines it, for the hint on a rule one
    file reads from another.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    names = gate_rules._RULE_NAME.findall(text)
    record: dict[str, Any] = {
        "file": path.relative_to(root).as_posix(),
        "rules": len(names),
        "imports": sorted(set(_IMPORT.findall(text))),
        "tags": sorted({tag for found in _TAGS.findall(text) for tag in found.split()}),
        "notes": [],
    }
    try:
        _compile(text, path.name)
    except yara_x.CompileError as exc:
        code, message, line = _error(exc)
        record.update(compiles=False, code=code, message=message, line=line)
        named = re.search(r"unknown identifier `(\w+)`", message)
        if named and named.group(1) in (elsewhere or {}):
            record["hint"] = (
                f"`{named.group(1)}` is a rule in {(elsewhere or {})[named.group(1)]}; the gate "
                "compiles each file in a namespace of its own, so keep the two in one file"
            )
        elif named and named.group(1) in _EXTERNALS:
            record["hint"] = (
                f"`{named.group(1)}` is an external variable the old scanner defined; the gate "
                "sets yara_gate_name and yara_gate_ext instead"
            )
        elif code in HINTS:
            record["hint"] = HINTS[code]
        return record
    record["compiles"] = True
    if _INCLUDE.search(text):
        record["notes"].append("has an include line inside a comment or string")
    if not _VERDICT.search(text):
        record["notes"].append("no verdict_on_match: a match blocks")
    elif len(_VERDICT.findall(text)) < len(names):
        record["notes"].append("some rules have no verdict_on_match: a match of one blocks")
    if _XOR_FULLWORD.search(text):
        record["notes"].append("xor with fullword: matches differently than under YARA 4.x")
    if _BASE64.search(text):
        record["notes"].append("base64: YARA 4.x false positives at a shifted alignment are gone")
    if record["tags"]:
        record["notes"].append("tags are not read by the gate")
    return record


def run_folder(root: Path, as_json: bool) -> int:
    if not root.is_dir():
        print(f"not a directory: {root}", file=sys.stderr)
        return 2
    found: list[Path] = []
    gate_rules._collect_rules(root, found)
    if not found:
        print("no .yar or .yara file found", file=sys.stderr)
        return 2
    files = sorted(set(found))
    elsewhere: dict[str, str] = {}
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for name in gate_rules._RULE_NAME.findall(text):
            elsewhere.setdefault(name, path.relative_to(root).as_posix())
    records = [check_file(path, root, elsewhere) for path in files]
    failed = [record for record in records if not record["compiles"]]
    if as_json:
        for record in records:
            print(json.dumps(record, ensure_ascii=True))
    else:
        for record in records:
            if record["compiles"]:
                notes = "; ".join(record["notes"])
                print(
                    f"ok    {record['file']}: {record['rules']} rule(s)"
                    + (f"; {notes}" if notes else "")
                )
                continue
            place = f" line {record['line']}" if record["line"] else ""
            print(f"FAIL  {record['file']}{place}: {record['code']} {record['message']}")
            if "hint" in record:
                print(f"      {record['hint']}")
    summary = {
        "record": "summary",
        "engine_version": gate_rules.yara_x_version(),
        "files": len(records),
        "compile": len(records) - len(failed),
        "fail": len(failed),
        "by_code": {
            code: sum(1 for record in failed if record["code"] == code)
            for code in sorted({record["code"] for record in failed})
        },
    }
    if as_json:
        print(json.dumps(summary, ensure_ascii=True))
    else:
        print(
            f"\n{summary['files']} file(s): {summary['compile']} compile, {summary['fail']} fail"
            f" under YARA-X {summary['engine_version']}"
        )
        if failed:
            print(
                "In <rules root>/local/ one failing file makes every scan incomplete "
                "(`local rule compile failed`)."
            )
    return 1 if failed else 0


SAMPLE_BYTES = 4 * 1024 * 1024
SCAN_SECONDS = 30


def _classic_names(rules: Any, data: bytes) -> set[str]:
    return {hit.rule for hit in rules.match(data=data, timeout=SCAN_SECONDS)}


def _gate_names(rules: Any, data: bytes) -> set[str]:
    scanner = yara_x.Scanner(rules)
    scanner.set_timeout(SCAN_SECONDS)
    return {str(rule.identifier) for rule in scanner.scan(data).matching_rules}


def run_samples(root: Path, samples: Path) -> int:
    """Each rule file on both engines over the same sample files: the rules each one names."""
    try:
        import yara
    except ImportError:
        print("needs yara-python: uv run --with yara-python python ...", file=sys.stderr)
        return 2
    if not root.is_dir() or not samples.is_dir():
        print("RULES_DIR and --samples must be directories", file=sys.stderr)
        return 2
    found: list[Path] = []
    gate_rules._collect_rules(root, found)
    pairs: list[tuple[str, Any, Any]] = []
    for path in sorted(set(found)):
        text = path.read_text(encoding="utf-8", errors="replace")
        name = path.relative_to(root).as_posix()
        try:
            pairs.append((name, _compile(text, path.name), yara.compile(source=text)))
        except yara_x.CompileError as exc:
            print(f"skip  {name}: YARA-X {_error(exc)[0]}")
        except yara.Error:
            print(f"skip  {name}: classic YARA does not compile it")
    scanned = matched = differ = 0
    for item in sorted(item for item in samples.rglob("*") if item.is_file()):
        if item.stat().st_size > SAMPLE_BYTES:
            continue
        data = item.read_bytes()
        sample = item.relative_to(samples).as_posix()
        scanned += 1
        hit = False
        for name, new, old in pairs:
            try:
                here, there = _gate_names(new, data), _classic_names(old, data)
            except (yara_x.ScanError, yara_x.TimeoutError, yara.Error) as exc:
                print(f"error {sample} with {name}: {type(exc).__name__}")
                differ += 1
                continue
            hit = hit or bool(here or there)
            if here != there:
                differ += 1
                print(
                    f"DIFF  {sample} with {name}: only YARA-X {sorted(here - there)}, "
                    f"only classic {sorted(there - here)}"
                )
        matched += hit
    print(
        f"\n{len(pairs)} rule file(s) on YARA-X {gate_rules.yara_x_version()} and classic YARA "
        f"{yara.YARA_VERSION}: {scanned} sample(s), {matched} with a match, "
        f"{differ} disagreement(s)"
    )
    return 1 if differ else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("rules_dir", nargs="?", type=Path, help="a folder of .yar and .yara files")
    parser.add_argument(
        "--json", action="store_true", help="one JSON line per file, then a summary"
    )
    parser.add_argument(
        "--classic", action="store_true", help="run the cases under yara-python too"
    )
    parser.add_argument("--samples", type=Path, help="files to scan on both engines")
    args = parser.parse_args()
    if args.samples is not None:
        if args.rules_dir is None:
            parser.error("--samples needs RULES_DIR")
        return run_samples(args.rules_dir, args.samples)
    if args.rules_dir is not None:
        return run_folder(args.rules_dir, args.json)
    return run_cases(args.classic)


if __name__ == "__main__":
    raise SystemExit(main())
