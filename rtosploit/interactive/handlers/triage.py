"""Triage handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_triage(session: InteractiveSession, console: Console) -> None:
    """Run crash triage pipeline."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    crash_dir = questionary.path(
        "Crash directory:",
        only_directories=True,
    ).ask()

    if not crash_dir:
        return

    minimize = questionary.confirm("Minimize crash inputs?", default=True).ask()

    console.print(f"[dim]Triaging crashes in {crash_dir}...[/dim]")
    try:
        from rtosploit.triage.pipeline import TriagePipeline
        pipeline = TriagePipeline(
            firmware_path=str(fw.path),
            machine=fw.machine or "mps2-an385",
            minimize=minimize,
        )
        results = pipeline.run(crash_dir)

        if not results:
            console.print("[yellow]No crashes found to triage.[/yellow]")
            return

        table = Table(title="Triage Results", show_header=True, header_style="bold cyan")
        table.add_column("Crash ID", style="cyan")
        table.add_column("Classification", style="red")
        table.add_column("Original", justify="right")
        table.add_column("Minimized", justify="right")

        for crash in results:
            classification = getattr(crash.triage_result, "classification", "unknown")
            min_size = f"{crash.minimized_size:,}" if crash.minimized_size else "-"
            table.add_row(
                crash.crash_id,
                str(classification),
                f"{crash.original_size:,}",
                min_size,
            )

        console.print(table)
        console.print(f"[bold]{len(results)} crash(es) triaged.[/bold]")
    except Exception as exc:
        console.print(f"[red]Triage failed: {exc}[/red]")
