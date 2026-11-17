"""Check that the phrase rule's documentary exemption agrees with the counting it replaced.

The exemption lets a quotation ("the phrase 'ignore all previous instructions'") cover the
one order it ends with. It used to find each order's nearest quotation by counting quotations
from the start of the unit, which is quadratic (#274). It now looks for an order in the gaps
between quotations, which gives the same answer while no listed verb can begin inside an order
and the quotation's skip stays lazy (docs/verification/2026-11-17-phrase-doc-exemption.md).

This probe compiles the shipped exemption beside the counting condition with the original
`ascii wide` strings, each alone, scans random inert messages, and fails on any message where
the two disagree. Messages mix ASCII and UTF-16LE parts, nest quotations, put a quotation's
order past its 64-character skip, and split words with tabs and line breaks. Run it after
changing the rule's order strings, its quotation string, or the word lists they read.

    uv run python docs/research/probe_phrase_doc_exemption.py [--seed N] [--messages N]
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import yara_x

RULE = (
    Path(__file__).resolve().parents[2] / "rules" / "local" / "agent_prompt_injection_phrases.yar"
)
COUNTING = """        for any of ($a, $b, $c) : (
            for any i in (1..#) : (
                with quote_index = #doc_phrase in (0..@[i]) : (
                    not defined @doc_phrase[quote_index] or
                    @doc_phrase[quote_index] + !doc_phrase[quote_index] != @[i] + ![i]
                )
            )
        )
"""
VERBS = ["ignore", "disregard", "forget", "IGNORE", "Forget"]
SEPS = [" ", " ", " ", "  ", "\t", "\n", " \r\n ", "\n\n"]
ORDERS = [
    "{v}{s}all{s}previous{s}instructions",
    "{v}{s}previous{s}instructions",
    "{v}{s}all{s}of{s}your{s}prior{s}rules",
    "{v}{s}the{s}earlier{s}prompts",
    "{v}{s}any{s}original{s}directions",
    "{v}{s}the{s}above",
    "{v}{s}all{s}the{s}above",
    "{v}{s}everything{s}you{s}were{s}told",
    "{v}{s}all{s}said{s}above",
    "{v}{s}everything{s}you{s}have{s}been{s}told",
]
NEAR = [
    "ignored all previous instructions",
    "ignore all previous instructionsX",
    "ignore all prior",
    "do not ignore",
    "ignore",
    "the above",
    "previous instructions",
]
FILLERS = ["", " ", '"', "'", " “", ": ", " quoted as ", " x" * 20, " " * 40, "\n", "\0", "phrase "]
WORDS = ["Hi.", "The paper says", "ok", "see", "Thanks!", "the", "phrase", "the phrase"]
SEPARATORS = [" ", ". ", "\n", ", ", "\n\n", "", "\0"]


def exemption_rules(source: str) -> str:
    """Two rules holding only the exemption: the shipped one, and the counting one with the
    original `ascii wide` strings. The rule's other strings would fire alike in both and hide
    a difference, so they are left out."""
    strings = {
        name: line
        for line in source.splitlines()
        if (name := line.strip().split(" = ")[0]) in {"$a", "$b", "$c", "$doc_phrase"}
        or name.endswith("_wide")
    }
    shipped = source[source.index("        for any of ($a, $b, $c) : (\n            $ and (") :]
    shipped = shipped[: shipped.rindex("}")]
    both = [strings[f"${x}"] + " wide" for x in "abc"] + [strings["$doc_phrase"]]
    return (
        "rule shipped {\n    strings:\n"
        + "\n".join(line for name, line in strings.items())
        + "\n    condition:\n"
        + shipped
        + "}\nrule counting {\n    strings:\n"
        + "\n".join(both)
        + "\n    condition:\n"
        + COUNTING
        + "}\n"
    )


def order(rng: random.Random) -> str:
    sep = rng.choice(SEPS)
    return rng.choice(ORDERS).format(v=rng.choice(VERBS), s=sep)


def part(rng: random.Random) -> str:
    draw = rng.random()
    if draw < 0.4:
        lead = rng.choice(["the phrase", "The phrase", "THE PHRASE", "the phrase the phrase"])
        gap = "".join(rng.choice(FILLERS) for _ in range(rng.randint(0, 3)))
        tail = rng.choice(["", '"', ".", "s", " is quoted", " and " + order(rng)])
        inner = order(rng) if rng.random() < 0.9 else rng.choice(NEAR)
        return lead + gap + inner + tail
    if draw < 0.65:
        return order(rng)
    if draw < 0.8:
        return rng.choice(NEAR)
    return rng.choice(WORDS)


def cross(rng: random.Random) -> bytes:
    """A quotation in one encoding whose skip holds a short order in the other, at either byte
    alignment, then an order in the quotation's own encoding: the order the skip holds is not
    the one quoted."""
    short = rng.choice(["{v} the above", "{v}{s}all said above", "{v} previous rules"])
    other = short.format(v=rng.choice(VERBS), s=rng.choice([" ", "\t"]))
    lead, gap = rng.choice(["the phrase", "The phrase"]), rng.choice(["", " ", "\0", " \0", ": "])
    if rng.random() < 0.5:
        inner = other.encode("utf-16-le")
        return (
            lead.encode()
            + gap.encode()
            + inner
            + rng.choice([b"", b" ", b"\0"])
            + order(rng).encode()
        )
    inner = other.encode()
    return (
        (lead + gap).encode("utf-16-le")
        + rng.choice([b"", b"\0"])
        + inner
        + (" " + order(rng)).encode("utf-16-le")
    )


def encode(text: str, rng: random.Random, mode: str) -> bytes:
    if mode == "wide" or (mode == "mixed" and rng.random() < 0.5):
        return text.encode("utf-16-le")
    return text.encode("utf-8")


def message(rng: random.Random) -> bytes:
    mode = rng.choice(["ascii", "ascii", "wide", "mixed", "mixed", "cross"])
    if mode == "cross":
        # Alone, or another order would fire in both rules and hide a difference.
        # A quoted order after it puts the cross part between two quotations.
        words = [rng.choice(WORDS + ["the phrase"]) for _ in range(rng.randint(0, 2))]
        if rng.random() < 0.5:
            words.append("the phrase " + order(rng))
        return cross(rng) + encode(" " + " ".join(words), rng, "mixed")
    out = b""
    for _ in range(rng.randint(1, 6)):
        if mode == "mixed" and rng.random() < 0.25:
            out += cross(rng)
        out += encode(part(rng) + rng.choice(SEPARATORS), rng, mode)
        if mode == "mixed" and rng.random() < 0.2:
            out += b"\0"  # shift the parity of what follows
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--messages", type=int, default=50000)
    args = parser.parse_args()
    rules = yara_x.compile(exemption_rules(RULE.read_text(encoding="utf-8")))
    rng = random.Random(args.seed)  # noqa: S311 - a repeatable fuzzing seed, not a secret
    fire = quoted = 0
    differ: list[bytes] = []
    for _ in range(args.messages):
        data = message(rng)
        fired = {rule.identifier for rule in rules.scan(data).matching_rules}
        fire += "counting" in fired
        quoted += "counting" not in fired and b"hrase" in data.replace(b"\0", b"")
        if ("counting" in fired) != ("shipped" in fired):
            differ.append(data)
    print(
        f"{args.messages} messages: {fire} fire, {quoted} quote an order and stay clean, "
        f"{len(differ)} differ"
    )
    if differ:
        raise SystemExit("\n".join(repr(data) for data in differ[:10]))


if __name__ == "__main__":
    main()
