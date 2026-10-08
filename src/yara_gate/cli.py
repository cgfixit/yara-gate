"""Command line for yara-gate. Unhandled errors exit 2."""

from pathlib import Path

import typer

from yara_gate import __version__
from yara_gate.models import ScanPolicy, exit_code
from yara_gate.quarantine import GatePaths, process_inbox_file, scan_in_place, watch
from yara_gate.rules import compile_sources, default_rules_dir, promote, update_packs
from yara_gate.selftest import run_selftest

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
    path: Path,
    home: Path = typer.Option(Path.home() / "YaraGate", "--home", help="Gate root."),
    timeout_s: int = typer.Option(30, "--timeout", help="Seconds for one file."),
    rules: Path | None = typer.Option(None, "--rules", help="Rules directory."),
    policy: ScanPolicy = typer.Option(
        ScanPolicy.default, "--policy", help="agent-ingest blocks advisory findings."
    ),
) -> None:
    """Scan a file or folder. Inbox paths are quarantined. Other paths stay put."""
    try:
        code = _scan_path(path, GatePaths(home), timeout_s, rules, policy)
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    raise typer.Exit(code=code)


@app.command()
def watch_inbox(
    home: Path = typer.Option(Path.home() / "YaraGate", "--home", help="Gate root."),
    timeout_s: int = typer.Option(30, "--timeout"),
    rules: Path | None = typer.Option(None, "--rules"),
    policy: ScanPolicy = typer.Option(ScanPolicy.default, "--policy"),
) -> None:
    """Watch inbox/ and move each file to clean/ or blocked/."""
    try:
        watch(GatePaths(home), rules_dir=rules, timeout_s=timeout_s, policy=policy)
    except KeyboardInterrupt:
        raise typer.Exit(code=0) from None
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
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
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(path)


@app.command()
def selftest() -> None:
    """Run the fixture matrix. Exit 0 only when every verdict matches."""
    raise typer.Exit(code=run_selftest())


@app.command()
def hunt(
    confirmed: str = typer.Option(..., "--confirmed", help="sha256 of a file in blocked/."),
    reason: str = typer.Option(..., "--reason", help="Why this file is confirmed bad."),
    scope: Path = typer.Option(..., "--scope", help="Directory to search for variants."),
    home: Path = typer.Option(Path.home() / "YaraGate", "--home"),
    rules: Path | None = typer.Option(None, "--rules"),
) -> None:
    """Write a candidate rule from a confirmed file. Candidates do not block."""
    from yara_gate.hunt import hunt as build_hunt

    try:
        rule_path, hits = build_hunt(
            GatePaths(home),
            confirmed,
            reason,
            scope,
            rules_dir=rules,
        )
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"candidate {rule_path.name} hits={len(hits)}")
    for hit in hits:
        typer.echo(hit)


@rules_app.command("update")
def rules_update(
    allow_network: bool = typer.Option(False, "--allow-network", help="Permit this download."),
    rules: Path | None = typer.Option(None, "--rules"),
) -> None:
    """Download pinned vendor packs. Refuses to run without --allow-network."""
    if not allow_network:
        typer.echo("refusing: pass --allow-network", err=True)
        raise typer.Exit(code=2)
    root = rules or default_rules_dir()
    try:
        lock = update_packs(root)
        _rules, skipped, error, compiled, skip_count = compile_sources(root)
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    for pack in lock.packs:
        typer.echo(f"{pack.name} pin={pack.pin} sha256={pack.sha256}")
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
    try:
        path = promote(rule_id, rules)
    except Exception as exc:
        typer.echo(f"incomplete: {exc.__class__.__name__}", err=True)
        raise typer.Exit(code=2) from exc
    typer.echo(f"promoted {path.name}")


def _scan_path(
    path: Path,
    home: GatePaths,
    timeout_s: int,
    rules: Path | None,
    policy: ScanPolicy = ScanPolicy.default,
) -> int:
    home.ensure()
    if not path.exists():
        typer.echo("incomplete: missing path", err=True)
        return 2
    files = (
        [path] if path.is_file() else [item for item in sorted(path.rglob("*")) if item.is_file()]
    )
    worst = 0
    for item in files:
        if _is_under(item, home.inbox):
            result = process_inbox_file(
                home, item, rules_dir=rules, timeout_s=timeout_s, policy=policy
            )
        else:
            result = scan_in_place(home, item, rules_dir=rules, timeout_s=timeout_s, policy=policy)
        typer.echo(
            f"{result.verdict} sha256={result.sha256} findings={len(result.findings)} "
            f"exit={exit_code(result)}"
        )
        worst = max(worst, exit_code(result))
    return worst


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


# The installed script name is `watch`. Typer uses the function name, so alias it.
app.command("watch")(watch_inbox)
