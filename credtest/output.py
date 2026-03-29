from __future__ import annotations

import csv
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

from credtest.engine import AttemptResult

console = Console()


def _confidence_style(confidence: str) -> str:
    return {
        "high": "bold green",
        "medium": "yellow",
        "low": "dim",
        "failure": "dim",
    }.get(confidence, "")


def print_result(result: AttemptResult, verbose: bool = False) -> None:
    c = result.classification
    if not verbose and not c.auth_success and c.action != "hold":
        return

    creds_str = " / ".join(f"{k}={v}" for k, v in result.credentials.items())
    signals_str = ", ".join(c.signals[:3]) + ("…" if len(c.signals) > 3 else "")

    if c.auth_success:
        icon = "[bold green]✅[/]"
        style = "green"
    elif c.action == "hold":
        icon = "[yellow]⏸[/]"
        style = "yellow"
    else:
        icon = "[dim]✗[/]"
        style = ""

    console.print(
        f"{icon} [{style}]{result.target}[/] | "
        f"[cyan]{creds_str}[/] | "
        f"[{_confidence_style(c.auth_confidence)}]{c.auth_confidence.upper()} ({c.auth_score})[/] | "
        f"[dim]{signals_str}[/]"
    )


def build_rich_table(results: list[AttemptResult]) -> Table:
    table = Table(
        title="CredTest Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
    )
    table.add_column("Target", style="cyan", no_wrap=True)
    table.add_column("Username")
    table.add_column("Password")
    table.add_column("Result", justify="center")
    table.add_column("Confidence", justify="center")
    table.add_column("Score", justify="right")
    table.add_column("Signals")

    for r in results:
        c = r.classification
        if not c.auth_success:
            continue
        username = r.credentials.get("username", r.credentials.get("user", ""))
        password = r.credentials.get("password", r.credentials.get("pass", ""))
        signals = "; ".join(c.signals[:2])
        table.add_row(
            r.target,
            username,
            password,
            "[green]✅ SUCCESS[/]",
            f"[{_confidence_style(c.auth_confidence)}]{c.auth_confidence.upper()}[/]",
            str(c.auth_score),
            signals,
        )

    return table


def write_jsonl(results: list[AttemptResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            c = r.classification
            record = {
                "timestamp": r.timestamp,
                "target": r.target,
                "url": r.url,
                "credentials": r.credentials,
                "attack_mode": r.attack_mode,
                "response": {
                    "status_code": r.response_status,
                    "content_length": r.response_length,
                    "redirect_location": r.redirect_location,
                    "latency_ms": r.latency_ms,
                },
                "classification": {
                    "auth_success": c.auth_success,
                    "auth_confidence": c.auth_confidence,
                    "auth_score": c.auth_score,
                    "rate_limited": c.rate_limited,
                    "captcha_detected": c.captcha_detected,
                    "csrf_detected": c.csrf_detected,
                    "csrf_fields": c.csrf_fields,
                    "signals": c.signals,
                },
                "action": c.action,
            }
            f.write(json.dumps(record) + "\n")


def write_csv(results: list[AttemptResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp", "target", "username", "password",
        "success", "confidence", "score",
        "rate_limited", "captcha", "csrf", "action",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            c = r.classification
            writer.writerow({
                "timestamp": r.timestamp,
                "target": r.target,
                "username": r.credentials.get("username", r.credentials.get("user", "")),
                "password": r.credentials.get("password", r.credentials.get("pass", "")),
                "success": c.auth_success,
                "confidence": c.auth_confidence,
                "score": c.auth_score,
                "rate_limited": c.rate_limited,
                "captcha": c.captcha_detected,
                "csrf": c.csrf_detected,
                "action": c.action,
            })
