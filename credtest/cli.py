from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich import box

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


def _parse_cookies(cookies_str: Optional[str]) -> dict[str, str]:
    cookie_dict: dict[str, str] = {}
    if cookies_str:
        for pair in cookies_str.split(";"):
            if "=" in pair:
                k, _, v = pair.strip().partition("=")
                cookie_dict[k.strip()] = v.strip()
    return cookie_dict


def _print_recon_result(url: str, result) -> None:
    console.rule(f"[bold cyan]{url}[/]")
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
    console.print()


def _recon_status(result) -> tuple[str, str]:
    """Return (status_label, style) for summary table."""
    if result.fields and any(f.field_type == "password" for f in result.fields):
        return "✅ Ready", "green"
    if result.fields:
        return "⚠ Fields (no password)", "yellow"
    if "Playwright error" in " ".join(result.notes):
        return "❌ Error", "red"
    if "WAF" in " ".join(result.notes) or "bot" in " ".join(result.notes).lower():
        return "🛡 WAF/Bot block", "red"
    if "JavaScript-rendered" in " ".join(result.notes) or "JS render" in " ".join(result.notes):
        return "⚙ JS render", "yellow"
    if "CSRF" in " ".join(result.notes):
        return "⚠ CSRF detected", "yellow"
    if result.js_action_hints:
        return "🔍 JS hints only", "yellow"
    return "❌ No form", "red"


@app.command()
def recon(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Single login page URL to analyze"),
    url_file: Optional[Path] = typer.Option(None, "--url-file", "-f", help="File with one URL per line"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Disable SSL verification"),
    debug: bool = typer.Option(False, "--debug", help="Print raw HTML snippet to help diagnose issues"),
    cookies: Optional[str] = typer.Option(
        None, "--cookies",
        help='Pre-existing cookies to send, e.g. "session=abc123;csrftoken=xyz"',
    ),
) -> None:
    """Analyze login forms using a real browser — works on JS-rendered pages.

    Pass --url for a single target or --url-file for a list of URLs (one per line).
    """
    if not url and not url_file:
        console.print("[red]Provide --url or --url-file.[/]")
        raise typer.Exit(1)

    # Build URL list
    urls: list[str] = []
    if url:
        urls.append(url)
    if url_file:
        if not url_file.exists():
            console.print(f"[red]File not found: {url_file}[/]")
            raise typer.Exit(1)
        for line in url_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)

    cookie_dict = _parse_cookies(cookies)
    verify_ssl = not no_verify

    if len(urls) == 1:
        # Single URL — detailed output
        result = do_recon(urls[0], verify_ssl=verify_ssl, debug=debug, cookies=cookie_dict)
        _print_recon_result(urls[0], result)
        return

    # Multiple URLs — detailed output per URL + summary table
    from credtest.recon import ReconResult
    results: list[tuple[str, ReconResult]] = []

    console.print(f"[bold]Reconning {len(urls)} URL(s)…[/]\n")
    for u in urls:
        console.print(f"[dim]→ {u}[/]")
        r = do_recon(u, verify_ssl=verify_ssl, debug=debug, cookies=cookie_dict)
        results.append((u, r))
        _print_recon_result(u, r)

    # Summary table
    table = Table(title="Recon Summary", box=box.ROUNDED, header_style="bold magenta")
    table.add_column("#", justify="right", style="dim")
    table.add_column("URL", no_wrap=False)
    table.add_column("Title")
    table.add_column("Fields", justify="center")
    table.add_column("CSRF", justify="center")
    table.add_column("Status", justify="center")
    table.add_column("Action URL")

    for i, (u, r) in enumerate(results, 1):
        status, style = _recon_status(r)
        field_names = ", ".join(f.name for f in r.fields if f.field_type != "hidden") or "—"
        csrf = "⚠ Yes" if r.csrf_fields else "No"
        table.add_row(
            str(i),
            u,
            r.page_title or "—",
            field_names,
            csrf,
            f"[{style}]{status}[/]",
            r.action,
        )

    console.print(table)
    console.print(f"\n[dim]✅ Ready = form + password field found  "
                  f"⚠ = needs attention  ❌ = no form detected[/]")


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
