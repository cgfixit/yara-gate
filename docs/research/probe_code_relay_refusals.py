"""Check that agent_message_code_relay's refusal lookup agrees with the pairing it replaced.

#270 replaced a condition that paired every request with every refusal (quadratic) with a
search of the gaps between refusals. The two agree only while the refusal alternatives keep
nondecreasing ends in start order (docs/verification/2026-11-16-code-relay-timing.md). This
probe compiles the shipped rule and a copy with the old pairing condition, scans random inert
messages built from requests, nested and repeated refusals, and fillers, and fails on any
message where the two disagree. Run it after changing the rule's refusal or request strings.

    uv run python docs/research/probe_code_relay_refusals.py [--seed N] [--messages N]
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

import yara_x

RULE = Path(__file__).resolve().parents[2] / "rules" / "local" / "agent_message_code_relay.yar"
PAIRING = (
    "        for any of ($relay, $received_me, $received_to, $reply, $link) : (\n"
    "            for any i in (1..#) : (\n"
    "                not for any j in (1..#negated) : "
    "(@negated[j] <= @[i] and @[i] < @negated[j] + !negated[j])\n"
    "            )\n"
    "        )\n"
)
REFUSALS = [
    "do not",
    "don't",
    "dont",
    "never",
    "not to",
    "won't",
    "will never",
    "should not",
    "shouldn't",
    "cannot",
    "can't",
    "never ever",
    "will never ask you to",
    "do not ever tell you to",
    "never request to",
    "Do NOT",
    "we will never ever require you to",
]
REQUESTS = [
    "forward the verification code to me",
    "send me the 2FA code right away",
    "text us the 6-digit code to +1 404 555 0100",
    "give me the code you just got",
    "forward the code you received to me",
    "reply with your one-time code",
    "respond with the verification code",
    "forward the password reset link to me",
    "send the PIN to this number",
    "read me the sign-in code asap",
    "share your passcode in this chat",
    "tell me the login code immediately",
]
FILLERS = [
    "Hi.",
    "ok",
    "Thanks!",
    "see you",
    "Your verification code is 482913.",
    "the code",
    "never",
]
SEPARATORS = [" ", ". ", "\n", ", ", "  ", "; "]


def pairing_source(source: str) -> str:
    """The shipped rule with the condition #270 replaced."""
    start = source.index("        for any of ($relay")
    return source[:start] + PAIRING + source[source.rindex("}") :]


def message(rng: random.Random) -> bytes:
    parts = []
    for _ in range(rng.randint(1, 8)):
        draw = rng.random()
        if draw < 0.45:
            gap = rng.choice([" ", "  ", " ever "])
            parts.append(rng.choice(REFUSALS) + gap + rng.choice(REQUESTS))
        elif draw < 0.7:
            parts.append(rng.choice(REQUESTS))
        else:
            parts.append(rng.choice(FILLERS))
    return "".join(part + rng.choice(SEPARATORS) for part in parts).encode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--messages", type=int, default=50000)
    args = parser.parse_args()
    source = RULE.read_text(encoding="utf-8")
    shipped, pairing = yara_x.compile(source), yara_x.compile(pairing_source(source))
    rng = random.Random(args.seed)  # noqa: S311 - a repeatable fuzzing seed, not a secret
    held = exempt = 0
    differ: list[bytes] = []
    for _ in range(args.messages):
        text = message(rng)
        old = bool(pairing.scan(text).matching_rules)
        held += old
        exempt += not old and any(request.encode() in text for request in REQUESTS)
        if old != bool(shipped.scan(text).matching_rules):
            differ.append(text)
    print(
        f"{args.messages} messages: {held} fire, {exempt} carry a request that every refusal "
        f"exempts, {len(differ)} differ"
    )
    if differ:
        raise SystemExit("\n".join(repr(text) for text in differ[:10]))


if __name__ == "__main__":
    main()
