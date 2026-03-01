"""Reusable fuzzer dashboard for Rich Live display."""

from __future__ import annotations

import os
import time

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table


def build_dashboard_table(
    elapsed: float,
    executions: int,
    crashes: int,
    coverage: float,
    corpus_size: int,
    unique_crashes: int = 0,
    last_crash: str = "",
) -> Panel:
    """Build a Rich Table wrapped in a Panel for the fuzzer dashboard."""
    exec_per_sec = executions / elapsed if elapsed > 0 else 0.0

    table = Table(show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Metric", style="bold")
    table.add_column("Value", justify="right")

    mins, secs = divmod(int(elapsed), 60)
    hrs, mins = divmod(mins, 60)
    table.add_row("Elapsed Time", f"{hrs:02d}:{mins:02d}:{secs:02d}")
    table.add_row("Executions", f"{executions:,}")
    table.add_row("Exec/sec", f"{exec_per_sec:,.1f}")
    table.add_row("Crashes Found", f"[bold red]{crashes}[/bold red]" if crashes else "0")
    if unique_crashes:
        table.add_row("Unique Crashes", f"[red]{unique_crashes}[/red]")
    table.add_row("Coverage %", f"{coverage:.1f}%")
    table.add_row("Corpus Size", f"{corpus_size:,}")
    if last_crash:
        table.add_row("Last Crash", f"[dim]{last_crash}[/dim]")

    return Panel(table, title="[bold green]RTOSploit Fuzzer Dashboard[/bold green]", border_style="green")


def count_files(directory: str) -> int:
    """Count files in a directory (non-recursive)."""
    try:
        return len([f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])
    except FileNotFoundError:
        return 0


def run_dashboard(
    output: str,
    timeout: int,
    console: Console | None = None,
    on_complete: callable | None = None,
    stats_provider: callable | None = None,
) -> dict:
    """Run the live-updating fuzzer dashboard.

    Args:
        output: Output directory path.
        timeout: Timeout in seconds (0 = unlimited).
        console: Rich Console instance.
        on_complete: Callback invoked with final stats dict.
        stats_provider: Callable returning a dict with live stats from the
            fuzz engine (keys: executions, crashes, coverage, corpus_size).

    Returns a dict with final stats: executions, crashes, coverage, corpus_size.
    """
    if console is None:
        console = Console()

    start = time.monotonic()

    final_stats = {
        "executions": 0,
        "crashes": 0,
        "coverage": 0.0,
        "corpus_size": 0,
        "elapsed": 0.0,
    }

    try:
        with Live(
            build_dashboard_table(0, 0, 0, 0.0, 0),
            console=console,
            refresh_per_second=2,
        ) as live:
            while True:
                elapsed = time.monotonic() - start

                if timeout and elapsed >= timeout:
                    break

                if stats_provider is not None:
                    provider_stats = stats_provider()
                    if provider_stats:
                        executions = provider_stats.get("executions", 0)
                        crashes = provider_stats.get("crashes", 0)
                        coverage = provider_stats.get("coverage", 0.0)
                        corpus_size = provider_stats.get("corpus_size", 0)
                    else:
                        crashes = count_files(f"{output}/crashes")
                        corpus_size = count_files(f"{output}/corpus")
                        executions = 0
                        coverage = 0.0
                else:
                    crashes = count_files(f"{output}/crashes")
                    corpus_size = count_files(f"{output}/corpus")
                    executions = 0
                    coverage = 0.0

                live.update(
                    build_dashboard_table(elapsed, executions, crashes, coverage, corpus_size)
                )

                final_stats = {
                    "executions": executions,
                    "crashes": crashes,
                    "coverage": coverage,
                    "corpus_size": corpus_size,
                    "elapsed": elapsed,
                }

                time.sleep(0.5)
    except KeyboardInterrupt:
        console.print("\n[yellow]Fuzzer interrupted by user.[/yellow]")

    if on_complete:
        on_complete(final_stats)

    return final_stats
