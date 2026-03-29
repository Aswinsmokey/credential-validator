from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from credtest.config import load_config, validate_config
from credtest.engine import AttemptResult, run_all
from credtest.output import build_rich_table, print_result, write_csv, write_jsonl
from credtest.recon import recon as do_recon

app = typer.Typer(
    name="credtest",
    help="Automated credential validation framework for authorized security audits.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def recon(
    url: str = typer.Option(..., "--url", "-u", help="Login page URL to analyze"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Disable SSL verification"),
    debug: bool = typer.Option(False, "--debug", help="Print raw HTML snippet to help diagnose issues"),
    cookies: Optional[str] = typer.Option(
        None, "--cookies",
        help='Pre-existing cookies to send, e.g. "session=abc123;csrftoken=xyz"',
    ),
) -> None:
    """Analyze a login form using a real browser — works on JS-rendered pages."""
    console.print(f"[bold cyan]Recon:[/] {url}\n")

    cookie_dict: dict[str, str] = {}
    if cookies:
        for pair in cookies.split(";"):
            if "=" in pair:
                k, _, v = pair.strip().partition("=")
                cookie_dict[k.strip()] = v.strip()

    result = do_recon(url, verify_ssl=not no_verify, debug=debug, cookies=cookie_dict)

    if result.page_title:
        console.print(f"  [bold]Page title:[/] {result.page_title}")
    console.print(f"  [bold]Action URL:[/] {result.action}")
    console.print(f"  [bold]Method:[/]     {result.method}")

    if result.fields:
        console.print(f"  [bold]Fields:[/]")
        for f in result.fields:
            req = " [red](required)[/]" if f.required else ""
            val = f" = {f.value!r}" if f.value else ""
            console.print(f"    • [cyan]{f.name}[/] ({f.field_type}){val}{req}")
    else:
        console.print("  [bold]Fields:[/] [dim](none found)[/]")

    if result.csrf_fields:
        console.print(f"\n  [yellow]⚠ CSRF fields:[/] {', '.join(result.csrf_fields)}")

    if result.js_action_hints:
        console.print(f"\n  [bold]JS endpoint hints:[/]")
        for hint in result.js_action_hints:
            console.print(f"    • [cyan]{hint}[/]")

    for note in result.notes:
        console.print(f"\n  [dim]ℹ {note}[/]")


@app.command()
def validate(
    config: Path = typer.Option(..., "--config", "-c", help="Path to YAML config file"),
) -> None:
    """Validate a config file and report any errors."""
    try:
        cfg = load_config(config)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]YAML parse error:[/] {e}")
        raise typer.Exit(1)

    errors = validate_config(cfg)
    if errors:
        console.print(f"[red bold]Config invalid — {len(errors)} error(s):[/]")
        for err in errors:
            console.print(f"  [red]• {err}[/]")
        raise typer.Exit(1)

    console.print(f"[green]✅ Config valid.[/] {len(cfg.targets)} target(s) loaded.")


@app.command()
def run(
    config: Path = typer.Option(..., "--config", "-c", help="Path to YAML config file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for results"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all attempts including failures"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Run only this target name"),
) -> None:
    """Run credential tests against configured targets."""
    try:
        cfg = load_config(config)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/] {e}")
        raise typer.Exit(1)

    errors = validate_config(cfg)
    if errors:
        console.print(f"[red bold]{len(errors)} config error(s):[/]")
        for err in errors:
            console.print(f"  [red]• {err}[/]")
        raise typer.Exit(1)

    targets = cfg.targets
    if target:
        targets = [t for t in targets if t.name == target]
        if not targets:
            console.print(f"[red]No target named '{target}' in config.[/]")
            raise typer.Exit(1)

    if not cfg.global_config.verify_ssl:
        console.print("[yellow]⚠ SSL verification disabled[/]")

    results: list[AttemptResult] = []

    def on_result(r: AttemptResult) -> None:
        results.append(r)
        print_result(r, verbose=verbose)

    console.print(f"[bold]Running {len(targets)} target(s)…[/]\n")
    asyncio.run(run_all(targets, cfg.global_config, on_result))

    # Summary table (successes only)
    successes = [r for r in results if r.classification.auth_success]
    console.print()
    if successes:
        console.print(build_rich_table(successes))
        console.print(f"\n[green bold]{len(successes)} credential(s) succeeded.[/]")
    else:
        console.print("[dim]No successful authentications found.[/]")

    if output:
        output = Path(output)
        write_jsonl(results, output / "results.jsonl")
        write_csv(results, output / "results.csv")
        console.print(f"\n[dim]Results written to {output}/[/]")
