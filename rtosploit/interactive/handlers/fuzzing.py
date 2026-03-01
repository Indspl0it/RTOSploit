"""Fuzzing handler for interactive mode."""

from __future__ import annotations

import logging
import os
import threading

import questionary
from rich.console import Console

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_fuzz(session: InteractiveSession, console: Console) -> None:
    """Configure and run fuzzer with live dashboard."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    # Prompt for fuzz parameters
    timeout = questionary.text("Fuzz timeout (seconds, 0=unlimited):", default="60").ask()
    try:
        timeout_int = int(timeout)
    except (ValueError, TypeError):
        timeout_int = 60

    corpus_dir = questionary.path(
        "Seed corpus directory (optional, leave empty to skip):",
        only_directories=True,
    ).ask()

    output_dir = questionary.path(
        "Output directory:",
        default=str(session.output_dir / "fuzz-output"),
    ).ask()

    if not output_dir:
        output_dir = str(session.output_dir / "fuzz-output")

    # Create output directories
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(f"{output_dir}/crashes", exist_ok=True)
    os.makedirs(f"{output_dir}/corpus", exist_ok=True)

    console.print(f"\n[dim]Fuzzing {fw.path.name} (timeout: {timeout_int}s)...[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    from rtosploit.fuzzing import FuzzEngine
    from rtosploit.interactive.dashboard import run_dashboard

    engine = FuzzEngine(
        firmware_path=str(fw.path),
        machine_name=fw.machine or "mps2-an385",
        inject_addr=0x20010000,
        inject_size=256,
        exec_timeout=0.05,
        jobs=1,
    )

    engine_stats = {}

    def stats_provider():
        return engine_stats

    def on_engine_stats(stats_dict):
        engine_stats.update(stats_dict)

    engine_thread = threading.Thread(
        target=engine.run,
        kwargs={
            "timeout": timeout_int,
            "corpus_dir": f"{output_dir}/corpus",
            "crash_dir": f"{output_dir}/crashes",
            "on_stats": on_engine_stats,
        },
        daemon=True,
    )
    engine_thread.start()

    stats = run_dashboard(
        output=output_dir,
        timeout=timeout_int,
        console=console,
        stats_provider=stats_provider,
    )

    engine_thread.join(timeout=5)

    console.print(f"\n[green]Fuzzer stopped.[/green] Output: [cyan]{output_dir}[/cyan]")

    # Post-fuzz actions
    if stats.get("crashes", 0) > 0:
        action = questionary.select(
            "Crashes found! What next?",
            choices=[
                questionary.Choice("Triage crashes", value="triage"),
                questionary.Choice("Generate report", value="report"),
                questionary.Choice("Return to menu", value="back"),
            ],
        ).ask()

        if action == "triage":
            from rtosploit.interactive.handlers.triage import handle_triage
            handle_triage(session, console)
        elif action == "report":
            from rtosploit.interactive.handlers.reporting import handle_reports
            handle_reports(session, console)
