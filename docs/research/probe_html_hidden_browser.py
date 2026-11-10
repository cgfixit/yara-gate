"""Compare the HTML hidden-text reader with what a browser draws, text by text.

``yara_gate.htmlhidden`` claims that a piece of text is hidden without rendering anything.
This probe checks that claim against a renderer. It writes inert HTML documents in which
every text is ``MARKn lorem ipsum``; ``html_hidden_oracle.js`` loads each in headless Chromium
and records whether each marker is drawn; ``compare`` then reads the same documents with the
reader. A marker the reader calls hidden and the browser draws is *unsound*, and one is a
failure. A marker the browser hides and the reader does not is expected: the reader claims
only what the markup settles.

    python docs/research/probe_html_hidden_browser.py directed cases.json
    python docs/research/probe_html_hidden_browser.py generate cases.json --count 10000 --seed 1
    python docs/research/probe_html_hidden_browser.py real cases.json FILE.html [FILE.html ...]
    ORACLE_JS=1 node docs/research/html_hidden_oracle.js cases.json drawn.json
    python docs/research/probe_html_hidden_browser.py compare cases.json drawn.json

``directed`` writes one document per parser or CSS rule; ``generate`` writes random documents
(``--dynamic`` adds a stylesheet, a script, or a colour scheme; ``--quirks`` drops the
doctype); ``real`` puts markers into HTML files that are already on the machine, with a
hidden element of ours around some of them. Not run by CI: it needs Node, Playwright, and a
Chromium build. Run ``real`` with ``ORACLE_JS`` unset, so nothing in those files is executed;
the generated documents hold no script that does anything, and the oracle aborts every
request either way.

See docs/verification/2026-11-10-hidden-html-text.md for what was measured with it.
"""

import argparse
import json
import random
import re
import time
from collections import Counter
from pathlib import Path

from yara_gate.content import Budget
from yara_gate.htmlhidden import html_hidden_texts

DATA = json.loads(Path(__file__).with_name("html-hidden-probes.json").read_text("utf-8"))
MARK = re.compile(r"MARK\d+(?= lorem)")
HEAD = "<!doctype html><html><head><title>t</title></head><body>"
SR_ONLY = (
    "<style>.sr-only,.visually-hidden{position:absolute;width:1px;height:1px;padding:0;"
    "overflow:hidden;clip:rect(0,0,0,0)}</style>"
)
DYNAMIC_HEADS = (
    "<style>.note{background:#222;color:#eee}.card{font-size:15px}</style>",
    '<link rel="stylesheet" href="https://example.invalid/site.css">',
    "<style>@keyframes in{to{opacity:1}}.x{animation:in 1s forwards}</style>",
    '<script src="https://example.invalid/app.js"></script>',
    '<meta name="color-scheme" content="dark">',
    "<style>h1{-webkit-background-clip:text}</style>",
    "<style>code{color:#c7254e}p{font-size:16px}section{display:block}</style>",
)
PLACEHOLDER = re.compile(r"\{(m|breaker|a:([a-z0-9-]+))\}")
# For ``real``: stretches of a file that are not text a marker can go in.
NOT_TEXT = re.compile(
    r"(?is)<(script|style|textarea|title|xmp|iframe|noembed|noframes|select|svg|math)\b.*?"
    r"(?:</\1\s*>|\Z)|<!--.*?(?:-->|\Z)|<[^<>]*>"
)
OUR_HIDING = (
    'style="display:none"',
    "hidden",
    'style="visibility:hidden"',
    'style="font-size:0"',
    'style="color:#fff;background:#fff"',
    'style="color:transparent"',
    'style="opacity:0"',
    'style="display:none ! important"',
    'style="color:#ffffff;background-color:#ffffff"',
)
OUR_TWINS = (
    'style="display:block"',
    'style="visibility:visible"',
    'style="font-size:0 px"',
    'style="color:#fff;background:#333"',
    'style="x:(;display:none"',
    'style="display:none\\9"',
    'style="opacity:0.9"',
    "",
    'style="color:#000"',
)


class Generator:
    """One random document. The same seed gives the same document."""

    def __init__(self, seed: int, dynamic: bool, quirks: bool) -> None:
        self.r = random.Random(seed)  # noqa: S311 - test data, not a secret
        self.count = 0
        self.dynamic = dynamic
        self.quirks = quirks
        # A screen-reader-only class is used only where a stylesheet defines it.
        self.sr_only = dynamic and self.r.random() < 0.3

    def mark(self) -> str:
        self.count += 1
        return f"MARK{self.count} lorem ipsum"

    def style(self) -> str:
        r = self.r
        parts = []
        roll = r.random()
        if roll < 0.45:
            parts.append(r.choice(DATA["hiding"]))
        if roll > 0.3 and r.random() < 0.5:
            parts.append(r.choice(DATA["ordinary"]))
        if r.random() < 0.08:
            parts.append(r.choice(DATA["hiding"]))
        if r.random() < 0.3:
            parts.append(r.choice(DATA["odd"]))
        r.shuffle(parts)
        text = ";".join(parts)
        if text and r.random() < 0.1:
            text = text.replace(":", " : ").replace(";", " ; ")
        if text and r.random() < 0.06:
            # Character references, as an attribute value decodes them or leaves them.
            pick = r.randrange(7)
            if pick < 3:
                text = text.replace(":", ("&colon;", "&#58;", "&#x3a")[pick], 1)
            elif pick < 6:
                text = ("x:&quot=;", "x:&quotx;", "x:&quot ;")[pick - 3] + text
            else:
                text = text.replace(";", "&semi;", 1)
        return text

    def attrs(self, tag: str) -> str:
        r = self.r
        out = []
        style = self.style()
        if style:
            if "'" in style and '"' in style:
                style = style.replace('"', "&#34;")
            quote = "'" if '"' in style else '"' if "'" in style else r.choice(['"', "'"])
            out.append(f"style={quote}{style}{quote}")
        if r.random() < 0.04:
            out.append(r.choice(["hidden", 'hidden=""', 'hidden="hidden"', "HIDDEN"]))
        if r.random() < 0.05:
            out.append(f'class="{r.choice(["note", "card lead", "x"])}"')
        elif self.sr_only and r.random() < 0.06:
            names = ["sr-only", "x visually-hidden", "SR-ONLY", "sr-only x"]
            out.append(f'class="{r.choice(names)}"')
        if r.random() < 0.03:
            out.append(f'id="n{self.count}"')
        if tag in ("td", "table", "tr", "div", "span", "p") and r.random() < 0.2:
            out.append(f'bgcolor="{r.choice(["#ffffff", "#000000", "white", "#333"])}"')
        if r.random() < 0.04:
            extras = ['align="right"', 'dir="rtl"', "open", 'hidden="until-found"']
            extras += ['color="#ffffff"', 'text="#ffffff"', 'size="7"', 'background="x.png"']
            out.append(r.choice(extras))
        if tag == "font" and r.random() < 0.7:
            out.append(f'color="{r.choice(["#ffffff", "white", "#000000", "red"])}"')
        if tag == "a" and r.random() < 0.7:
            out.append('href="#x"')
        if r.random() < 0.05:
            out.append(f'data-note="{self.mark()} in an attribute"')
        if r.random() < 0.03:
            out.append('title="a > b"')
        if r.random() < 0.02:
            out.append("it's")
        r.shuffle(out)
        return (" " + " ".join(out)) if out else ""

    def fill(self, template: str) -> str:
        def one(match: re.Match[str]) -> str:
            if match.group(1) == "m":
                return self.mark()
            if match.group(1) == "breaker":
                return str(self.r.choice(DATA["select_breakers"]))
            return self.attrs(match.group(2))

        return PLACEHOLDER.sub(one, template)

    def node(self, depth: int, inline: bool) -> str:
        r = self.r
        roll = r.random()
        if depth > 5 or roll < 0.34:
            return self.mark() + r.choice([" ", ". ", ""])
        if roll < 0.38:
            return f"<!-- {self.mark()} in a comment -->"
        if roll < 0.40:
            return f"<{r.choice(DATA['voids'])}>"
        if roll < 0.42 and not inline:
            return f"<template><p>{self.mark()}</p></template>"
        if roll < 0.44 and not inline:
            return f"<textarea{self.attrs('textarea')}>{self.mark()} <b>bold</b></textarea>"
        if roll < 0.45:
            return f"</{r.choice(['span', 'div', 'b', 'p'])}>"
        if roll < 0.475 and not inline:
            return self.fill(r.choice(DATA["older"]))
        if roll < 0.56 and not inline:
            return self.fill(r.choice(DATA["rare"]))
        if roll < 0.575:
            return r.choice([" ", "\n  ", " ", "&#32;", "&nbsp;"])
        tag = r.choice(DATA["inlines"] if inline or r.random() < 0.4 else DATA["blocks"])
        if tag == "tr":
            body = "".join(self.wrap("td", depth + 1) for _ in range(r.randint(1, 2)))
            return f"<table{self.attrs('table')}><tr{self.attrs('tr')}>{body}</tr></table>"
        if tag in ("ul", "ol"):
            body = "".join(self.wrap("li", depth + 1) for _ in range(r.randint(1, 3)))
            return f"<{tag}{self.attrs(tag)}>{body}</{tag}>"
        if tag == "dl":
            body = "".join(self.wrap(r.choice(["dt", "dd"]), depth + 1) for _ in range(2))
            return f"<dl{self.attrs('dl')}>{body}</dl>"
        if tag in ("li", "td", "dt", "dd", "table"):
            tag = "div"
        return self.wrap(tag, depth)

    def wrap(self, tag: str, depth: int) -> str:
        r = self.r
        child_inline = tag in DATA["inlines"] or tag in ("p", "h2", "dt")
        body = "".join(self.node(depth + 1, child_inline) for _ in range(r.randint(1, 3)))
        end = "" if tag in DATA["omit_end"] and r.random() < 0.35 else f"</{tag}>"
        return f"<{tag}{self.attrs(tag)}>{body}{end}"

    def document(self) -> str:
        r = self.r
        head = "<title>Page title</title>"
        body_attrs = ""
        if r.random() < 0.08:
            choices = [' bgcolor="#000000" text="#ffffff"', ' style="background:#111"']
            body_attrs = r.choice([*choices, ' bgcolor="#ffffff"', ' style="color:#fff"'])
        if self.sr_only:
            head += SR_ONLY
        if r.random() < 0.08:
            head += "<noscript><img src='x.png'></noscript>"
        if self.dynamic:
            head += r.choice(DYNAMIC_HEADS)
        body = "".join(self.node(0, False) for _ in range(r.randint(2, 5)))
        doctype = "" if self.quirks else "<!doctype html>"
        shape = r.random()
        if shape < 0.05:
            # Content before any body tag, and a body tag that comes late with attributes.
            late = self.attrs("body") or r.choice([' bgcolor="#000000"', " hidden"])
            return f"{doctype}{self.node(0, False)}<body{late}>{body}"
        whole = f"{doctype}<html><head>{head}</head><body{body_attrs}>{body}</body></html>"
        if shape < 0.08:
            return whole + self.node(0, False)
        if shape < 0.11:
            again = f"<body{self.attrs('body')}>{self.node(0, False)}</body></html>"
            return whole.removesuffix("</body></html>") + again
        return whole


def built_in() -> list[dict[str, str]]:
    """Directed documents made here because they are long or regular."""
    cases = []
    for depth in (50, 400, 495, 505, 512, 600, 5000):
        for tag in ("div", "span"):
            hidden = f'<{tag} style="display:none">MARK1 lorem ipsum</{tag}>'
            html = HEAD + f"<{tag}>" * depth + hidden + f"</{tag}>" * depth + "MARK2 lorem ipsum"
            cases.append({"id": f"depth {depth}: {tag}", "html": html})
    plain = "a abbr address article aside b bdo blockquote button center cite code details div"
    plain += " dl em fieldset figure font footer form h1 header i label main mark marquee nav"
    plain += " ol p pre q s section small span strong sub summary u ul x-custom"
    for doctype in ("<!doctype html>", ""):
        for tag in plain.split():
            html = f"{doctype}<html><head><title>t</title></head><body>"
            html += f"<{tag} hidden>MARK1 lorem ipsum</{tag}>MARK2 lorem ipsum"
            mode = "standards" if doctype else "quirks"
            cases.append({"id": f"hidden attribute, {mode}: {tag}", "html": html})
    return cases


def with_markers(paths: list[str], seed: int) -> list[dict[str, str]]:
    """Two documents for each file: markers alone, and markers with hiding of our own."""
    r = random.Random(seed)  # noqa: S311 - test data, not a secret
    cases = []
    for index, path in enumerate(paths):
        source = Path(path).read_bytes().decode("utf-8", "replace")
        if re.search(r"(?i)<noscript|<frameset|<plaintext", source):
            # Scripting decides how a noscript body is parsed, and these are rendered
            # with it off.
            continue
        runs, at = [], 0
        for match in NOT_TEXT.finditer(source):
            if match.start() > at and re.search(r"[A-Za-z]", source[at : match.start()]):
                runs.append(at)
            at = match.end()
        runs = sorted(r.sample(runs, 150)) if len(runs) > 150 else runs
        for variant in ("plain", "ours"):
            out, at = [], 0
            for number, start in enumerate(runs, 1):
                out.append(source[at:start])
                at = start
                text = f"MARK{number} lorem ipsum"
                if variant == "ours" and r.random() < 0.5:
                    pool = OUR_HIDING if r.random() < 0.6 else OUR_TWINS
                    tag = r.choice(["span", "div", "p", "b", "font", "section"])
                    out.append(f"<{tag} {r.choice(pool)}>{text}</{tag}> ")
                else:
                    out.append(text + " ")
            out.append(source[at:])
            cases.append({"id": f"r{index}-{variant}", "path": path, "html": "".join(out)})
    return cases


def compare(cases: list[dict[str, str]], drawn: dict[str, dict[str, str]], show: int) -> int:
    budget = Budget(time.monotonic() + 3600)
    agree_hidden = agree_shown = errors = 0
    unsound: list[tuple[str, str, str, str]] = []
    cautious: Counter[str] = Counter()
    for case in cases:
        seen = drawn.get(case["id"], {"__error": "not rendered"})
        if "__error" in seen:
            errors += 1
            continue
        pieces = html_hidden_texts("a.html", case["html"], budget).pieces
        hidden = set(MARK.findall("\n".join(pieces)))
        for marker in set(MARK.findall(case["html"])):
            verdict = seen.get(marker, "absent")
            if verdict == "not-text":
                continue
            is_drawn = verdict.startswith(("shown", "title"))
            if marker in hidden and is_drawn:
                unsound.append((case["id"], marker, verdict, case["html"]))
            elif marker in hidden:
                agree_hidden += 1
            elif is_drawn:
                agree_shown += 1
            else:
                cautious[verdict.split(":")[0]] += 1
    total = agree_hidden + agree_shown + len(unsound) + sum(cautious.values())
    print(f"documents {len(cases)} (not rendered {errors}); marked texts {total}")
    print(f"  hidden to both {agree_hidden}; shown to both {agree_shown}")
    print(f"  reader shown, browser hides it {sum(cautious.values())}: {dict(cautious)}")
    print(f"  UNSOUND, reader hidden and browser draws it: {len(unsound)}")
    for name, marker, verdict, html in unsound[:show]:
        at = html.index(marker + " ")
        context = html[max(0, at - 240) : at + 40].replace("\n", " ")
        print(f"--- {name} {marker} browser={verdict}\n    ...{context}")
    return len(unsound)


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    directed = commands.add_parser("directed", help="write the single-rule documents")
    directed.add_argument("out")
    generate = commands.add_parser("generate", help="write random documents")
    generate.add_argument("out")
    generate.add_argument("--count", type=int, default=3000)
    generate.add_argument("--seed", type=int, default=1)
    generate.add_argument("--dynamic", action="store_true")
    generate.add_argument("--quirks", action="store_true")
    real = commands.add_parser("real", help="put markers into HTML files on this machine")
    real.add_argument("out")
    real.add_argument("files", nargs="+")
    real.add_argument("--seed", type=int, default=1)
    check = commands.add_parser("compare", help="read the documents and compare")
    check.add_argument("cases")
    check.add_argument("drawn")
    check.add_argument("--show", type=int, default=10)
    args = parser.parse_args()
    if args.command == "compare":
        cases = json.loads(Path(args.cases).read_text("utf-8"))
        drawn = json.loads(Path(args.drawn).read_text("utf-8"))
        raise SystemExit(1 if compare(cases, drawn, args.show) else 0)
    if args.command == "directed":
        cases = [*DATA["directed"], *built_in()]
    elif args.command == "real":
        cases = with_markers(args.files, args.seed)
    else:
        cases = []
        for index in range(args.count):
            made = Generator(args.seed * 1_000_003 + index, args.dynamic, args.quirks)
            cases.append({"id": f"d{index}", "html": made.document()})
    Path(args.out).write_text(json.dumps(cases), "utf-8")
    print(f"{len(cases)} documents")


if __name__ == "__main__":
    main()
