"""Command line for yara-gate. Unhandled errors exit 2."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

import typer

from yara_gate import __version__
from yara_gate.models import ScanPolicy, ScanResult, Verdict, exit_code

if TYPE_CHECKING:
    from yara_gate.quarantine import GatePaths
    from yara_gate.rules import RulesLock

# The scanner, rule loader, reports, and selftest are imported inside the command that needs
# them, so --version, rules, demo, and install-agent start without compiling anything. The
# three wrappers keep the names tests patch on this module.


def run_selftest() -> int:
    from yara_gate import selftest

    return selftest.run_selftest()


def install_packs(root: Path) -> RulesLock:
    from yara_gate import rules

    return rules.install_packs(root)


def update_packs(root: Path) -> RulesLock:
    from yara_gate import rules

    return rules.update_packs(root)


app = typer.Typer(add_completion=False, no_args_is_help=True)
rules_app = typer.Typer(add_completion=False, no_args_is_help=True)
app.add_typer(rules_app, name="rules")


def _version(value: bool) -> None:
    if value:
        typer.echo(f"yara-gate {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version_flag: bool = typer.Option(
        False,
        "--version",
        callback=_version,
        is_eager=True,
        help="Print the version and exit.",
    ),
) -> None:
    """Pause on untrusted files, scan them, and fail closed."""


@app.command()
def scan(
    # Strings, not Paths: Path("./-") normalizes to "-" and would read stdin.
    paths: list[str] | None = typer.Argument(None, metavar="PATH..."),
    home: Path = typer.Option(Path.home() / "YaraGate", "--home", help="Gate root."),
    timeout_s: int = typer.Option(30, "--timeout", help="Seconds for one file."),
    rules: Path | None = typer.Option(None, "--rules", help="Rules directory."),
    policy: ScanPolicy = typer.Option(
        ScanPolicy.default, "--policy", help="agent-ingest blocks advisory findings."
    ),
    follow_symlinks: bool = typer.Option(
        False,
        "--follow-symlinks",
        help="Scan a symlink target outside the inbox. Inbox links are never followed.",
    ),
    json_output: bool = typer.Option(
        False, "--json", help="Emit one JSON report per file to stdout (JSON Lines)."
    ),
    name: str = typer.Option(
        "stdin",
        "--name",
        help="With PATH '-', the logical file name of stdin. Its suffix drives type checks.",
    ),
    paths_from: str | None = typer.Option(
        None,
        "--paths-from",
        metavar="FILE",
        help="Read more paths from FILE, one per line, or from stdin with '-'.",
    ),
    null: bool = typer.Option(
        False, "--null", help="With --paths-from, paths are NUL-separated, not line-separated."
    ),
) -> None:
    """Scan files or folders, or '-' for stdin. Inbox paths are quarantined. Others stay put.

    Several paths are scanned in order, each exactly as a single path is. The exit code is
    the worst one seen (incomplete 2, then block 1); a missing path does not stop the rest.
    """
    from yara_gate.quarantine import GatePaths

    try:
        targets = _targets(paths or [], paths_from, null)
        if targets == ["-"]:
            code = _scan_stdin(GatePaths(home), name, timeout_s, rules, policy, json_output)
        else:
            if "-" in targets:
                raise ValueError("'-' must be the only PATH")
            code = 0
            for target in targets:
                code = max(
                    code,
                    _scan_path(
                        Path(target),
                        GatePaths(home),
                        timeout_s,
                        rules,
                        policy,
                        follow_symlinks,
                        json_output,
                    ),
                )
    except typer.Exit:
        raise
    except ValueError as exc:
        typer.echo(f"incomplete: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=code)


def _targets(paths: list[str], paths_from: str | None, null: bool) -> list[str]:
    """The positional paths, then the listed ones, in order, with exact duplicates dropped."""
    found = list(paths)
    if paths_from is not None:
        raw = sys.stdin.buffer.read() if paths_from == "-" else Path(paths_from).read_bytes()
        separator = b"\0" if null else b"\n"
        for item in raw.split(separator):
            text = os.fsdecode(item if null else item.rstrip(b"\r"))
            if text:
                found.append(text)
    if not found and paths_from is None:
        raise ValueError("no paths given")
    # A listed "-" would scan whatever is left of stdin, possibly the list itself. Refuse it.
    if paths_from is not None and "-" in found:
        raise ValueError("'-' cannot appear in a path list")
    # An empty list scans nothing and exits 0, like an empty directory. A set keeps the
    # duplicate check linear for a long find -print0 list; the list keeps the order.
    seen: set[str] = set()
    distinct: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            distinct.append(item)
    return distinct


@app.command()
def watch_inbox(
    home: Path = typer.Option(Path.home() / "YaraGate", "--home", help="Gate root."),
    timeout_s: int = typer.Option(30, "--timeout"),
    rules: Path | None = typer.Option(None, "--rules"),
    policy: ScanPolicy = typer.Option(ScanPolicy.default, "--policy"),
) -> None:
    """Watch inbox/ and move each file to clean/ or blocked/."""
    from yara_gate.quarantine import GatePaths, watch

    try:
        watch(GatePaths(home), rules_dir=rules, timeout_s=timeout_s, policy=policy)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:
        typer.echo(f"incomplete: {_incomplete_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def demo(
    port: int = typer.Option(0, "--port", help="Loopback port. 0 picks a free port."),
    rules: Path | None = typer.Option(None, "--rules", help="Rules directory."),
) -> None:
    """Serve a loopback page that scans samples without moving them."""
    from yara_gate.demo import serve_demo

    try:
        serve_demo(port, rules)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc


@app.command("install-agent")
def install_agent(
    dest: Path = typer.Option(..., "--dest", help="Where to write the plist."),
    home: Path = typer.Option(Path.home() / "YaraGate", "--home", help="Gate root."),
) -> None:
    """Write a launchd plist for watch. This command does not load the agent."""
    from yara_gate.launchd import write_launch_agent

    try:
        path = write_launch_agent(dest, home=home)
    except Exception as exc:
        typer.echo(f"incomplete: {_incomplete_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(path)


@app.command()
def selftest() -> None:
    """Run the fixture matrix. Exit 0 only when every verdict matches."""
    try:
        code = run_selftest()
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=code)


@app.command()
def hunt(
    confirmed: str = typer.Option(..., "--confirmed", help="sha256 of a file in blocked/."),
    reason: str = typer.Option(..., "--reason", help="Why this file is confirmed bad."),
    scope: Path = typer.Option(..., "--scope", help="Directory to search for variants."),
    home: Path = typer.Option(Path.home() / "YaraGate", "--home"),
    rules: Path | None = typer.Option(None, "--rules"),
    confirmed_by: str = typer.Option(
        "operator",
        "--confirmed-by",
        help="Label stored on the candidate. Defaults to operator.",
    ),
) -> None:
    """Write a candidate rule from a confirmed file. Candidates do not block."""
    from yara_gate.hunt import hunt as build_hunt
    from yara_gate.quarantine import GatePaths

    try:
        rule_path, hits = build_hunt(
            GatePaths(home),
            confirmed,
            reason,
            scope,
            rules_dir=rules,
            confirmed_by=confirmed_by,
        )
    except Exception as exc:
        typer.echo(f"incomplete: {_incomplete_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"candidate {rule_path.name} hits={len(hits)}")
    for hit in hits:
        typer.echo(hit)


@rules_app.command("install")
def rules_install(
    allow_network: bool = typer.Option(False, "--allow-network", help="Permit this download."),
    rules: Path | None = typer.Option(None, "--rules"),
) -> None:
    """Install the packs named in rules.lock. Refuses to run without --allow-network."""
    from yara_gate.rules import compile_sources, default_rules_dir

    if not allow_network:
        typer.echo("refusing: pass --allow-network", err=True)
        raise typer.Exit(code=2)
    root = rules or default_rules_dir()
    try:
        lock = install_packs(root)
        _rules, skipped, error, compiled, skip_count = compile_sources(root)
    except Exception as exc:
        _echo_incomplete(exc)
    for pack in lock.packs:
        typer.echo(f"{pack.name} pin={pack.pin} sha256={pack.sha256}")
    _echo_shadows(skipped)
    typer.echo(f"compiled_rules={compiled} skipped_rules={skip_count}")
    if error:
        typer.echo(error, err=True)
        raise typer.Exit(code=2)


@rules_app.command("update")
def rules_update(
    allow_network: bool = typer.Option(False, "--allow-network", help="Permit this download."),
    rules: Path | None = typer.Option(None, "--rules"),
) -> None:
    """Download pinned vendor packs. Refuses to run without --allow-network."""
    from yara_gate.rules import compile_sources, default_rules_dir

    if not allow_network:
        typer.echo("refusing: pass --allow-network", err=True)
        raise typer.Exit(code=2)
    root = rules or default_rules_dir()
    try:
        lock = update_packs(root)
        _rules, skipped, error, compiled, skip_count = compile_sources(root)
    except Exception as exc:
        _echo_incomplete(exc)
    for pack in lock.packs:
        typer.echo(f"{pack.name} pin={pack.pin} sha256={pack.sha256}")
    _echo_shadows(skipped)
    typer.echo(f"compiled_rules={compiled} skipped_rules={skip_count}")
    if error:
        typer.echo(error, err=True)
        raise typer.Exit(code=2)


@rules_app.command("promote")
def rules_promote(
    rule_id: str = typer.Argument(..., help="Hunt id, with or without the hunt_ prefix."),
    rules: Path | None = typer.Option(None, "--rules"),
) -> None:
    """Let a candidate rule block on later scans."""
    from yara_gate.rules import promote

    try:
        path = promote(rule_id, rules)
    except Exception as exc:
        typer.echo(f"incomplete: {_incomplete_text(exc)}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"promoted {path.name}")


def _incomplete_text(exc: Exception) -> str:
    """The message for an error yara-gate raised on purpose; the class name for anything else.

    ``watch already running``, ``no distinctive strings``, and ``<id> is not a hunt rule`` tell the
    operator what to do. A missing candidate or confirmed file names what was not found. An
    unexpected exception keeps its class name, as ``scan``, ``selftest``, and ``demo`` print it.
    """
    if isinstance(exc, FileNotFoundError):
        return f"not found: {exc}"
    if isinstance(exc, ValueError | RuntimeError):
        return str(exc) or exc.__class__.__name__
    return exc.__class__.__name__


def _echo_incomplete(exc: Exception) -> NoReturn:
    from yara_gate.rules import RuleDownloadError

    if isinstance(exc, RuleDownloadError):
        typer.echo(f"incomplete: {exc}", err=True)
    else:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
    raise typer.Exit(code=2) from exc


def _echo_shadows(skipped: list[str]) -> None:
    for line in skipped:
        if line.endswith(": shadowed by bundled"):
            typer.echo(line)


def _scan_path(
    path: Path,
    home: GatePaths,
    timeout_s: int,
    rules: Path | None,
    policy: ScanPolicy = ScanPolicy.default,
    follow_symlinks: bool = False,
    json_output: bool = False,
) -> int:
    from yara_gate.quarantine import process_inbox_file, scan_in_place

    home.ensure()
    try:
        info = path.lstat()
    except FileNotFoundError:
        typer.echo("incomplete: missing path", err=True)
        return 2
    files, unreadable = _list_files(path) if stat.S_ISDIR(info.st_mode) else ([path], [])
    worst = 0
    pending = [(item, False) for item in files] + [(item, True) for item in unreadable]
    for item, failed in pending:
        if failed:
            result = _refuse_path(home, item, "directory not readable", policy)
        elif _is_under(item, home.inbox):
            result = process_inbox_file(
                home, item, rules_dir=rules, timeout_s=timeout_s, policy=policy
            )
        elif (item.is_symlink() or item.is_junction()) and (not follow_symlinks or item.is_dir()):
            result = _refuse_path(home, item, "symlink not followed", policy)
        else:
            result = scan_in_place(home, item, rules_dir=rules, timeout_s=timeout_s, policy=policy)
        _emit(result, json_output)
        worst = max(worst, exit_code(result))
    return worst


def _scan_stdin(
    home: GatePaths,
    name: str,
    timeout_s: int,
    rules: Path | None,
    policy: ScanPolicy,
    json_output: bool,
) -> int:
    """Scan stdin in memory. Over 100 MiB is incomplete; its sha256 covers what was read."""
    from yara_gate.report import write_reports
    from yara_gate.scanner import MAX_FILE_BYTES, scan_bytes

    home.ensure()
    data = sys.stdin.buffer.read(MAX_FILE_BYTES + 1)
    result = scan_bytes(data, name=name, timeout_s=timeout_s, rules_dir=rules, policy=policy)
    write_reports(home.reports, result)
    _emit(result, json_output)
    return exit_code(result)


def _emit(result: ScanResult, json_output: bool) -> None:
    from yara_gate.report import compact_report

    if json_output:
        typer.echo(json.dumps(compact_report(result), separators=(",", ":")))
        return
    reason = f" reason={result.incomplete_reason}" if result.incomplete_reason else ""
    typer.echo(
        f"{result.verdict} sha256={result.sha256} findings={len(result.findings)} "
        f"exit={exit_code(result)}{reason}"
    )


def _list_files(root: Path) -> tuple[list[Path], list[Path]]:
    """Walk a directory without following a symlinked file or directory.

    A symlinked directory or a Windows junction is listed as an entry so the caller
    reports it; os.walk does not treat a junction as a link. A directory that cannot be
    listed goes in the second list; skipping it would read as clean.
    """
    found: list[Path] = []
    unreadable: list[Path] = []

    def record(exc: OSError) -> None:
        unreadable.append(Path(exc.filename) if exc.filename else root)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False, onerror=record):
        base = Path(dirpath)
        links = [
            name for name in dirnames if (base / name).is_symlink() or (base / name).is_junction()
        ]
        dirnames[:] = [name for name in dirnames if name not in links]
        found.extend(base / name for name in [*filenames, *links])
    return sorted(found), sorted(unreadable)


def _refuse_path(
    home: GatePaths, path: Path, reason: str, policy: ScanPolicy = ScanPolicy.default
) -> ScanResult:
    """Report an outside path as incomplete without reading it."""
    from yara_gate.report import write_reports

    token = hashlib.sha256(str(path).encode()).hexdigest()
    result = ScanResult(
        sha256=token,
        verdict=Verdict.incomplete,
        incomplete_reason=reason,
        path=str(path),
        policy=policy,
    )
    write_reports(home.reports, result)
    return result


def _is_under(path: Path, root: Path) -> bool:
    """True when path is inside root. The final component is never resolved."""
    try:
        (path.parent.resolve() / path.name).relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


# The installed script name is `watch`. Typer uses the function name, so alias it.
app.command("watch")(watch_inbox)
