"""Coverage handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_coverage(session: InteractiveSession, console: Console) -> None:
    """View coverage stats."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    cov_dir = questionary.path(
        "Coverage data directory:",
        default=str(session.output_dir / "coverage"),
        only_directories=True,
    ).ask()

    if not cov_dir:
        return

    console.print(f"[dim]Loading coverage from {cov_dir}...[/dim]")
    try:
        from rtosploit.coverage.bitmap_reader import read_bitmap
        from rtosploit.coverage.mapper import CoverageMapper

        bitmap = read_bitmap(cov_dir)
        mapper = CoverageMapper(fw.image)
        stats = mapper.map_coverage(bitmap)

        table = Table(title="Coverage Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        total = getattr(stats, "total_blocks", 0)
        covered = getattr(stats, "covered_blocks", 0)
        pct = (covered / total * 100) if total > 0 else 0

        table.add_row("Total Blocks", f"{total:,}")
        table.add_row("Covered Blocks", f"{covered:,}")
        table.add_row("Coverage", f"{pct:.1f}%")

        console.print(table)
    except Exception as exc:
        console.print(f"[red]Coverage loading failed: {exc}[/red]")
