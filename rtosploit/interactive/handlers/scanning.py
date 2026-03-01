"""Scanning handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console

from rtosploit.interactive.session import InteractiveSession, normalize_path

logger = logging.getLogger(__name__)


def handle_quick_scan(session: InteractiveSession, console: Console) -> None:
    """Run quick CI pipeline scan (no firmware pre-loaded required)."""
    fw_path = None
    if session.firmware:
        use_loaded = questionary.confirm(
            f"Use loaded firmware ({session.firmware.path.name})?",
            default=True,
        ).ask()
        if use_loaded:
            fw_path = str(session.firmware.path)

    if not fw_path:
        fw_path = questionary.path("Firmware file path:").ask()
        if not fw_path:
            return

    machine = questionary.text(
        "Machine name:",
        default=session.firmware.machine if session.firmware and session.firmware.machine else "mps2-an385",
    ).ask()

    timeout = questionary.text("Fuzz timeout (seconds):", default="60").ask()
    try:
        timeout_int = int(timeout)
    except (ValueError, TypeError):
        timeout_int = 60

    output_dir = questionary.path(
        "Output directory:",
        default=str(session.output_dir),
    ).ask()

    # Normalize paths (handles Windows paths under WSL)
    fw_path = str(normalize_path(fw_path))

    console.print("[dim]Starting CI pipeline scan...[/dim]")
    try:
        from rtosploit.ci.pipeline import CIPipeline, CIConfig
        config = CIConfig(
            firmware_path=fw_path,
            machine=machine or "mps2-an385",
            fuzz_timeout=timeout_int,
            output_dir=output_dir or str(session.output_dir),
        )
        pipeline = CIPipeline(config)
        exit_code = pipeline.run()

        if exit_code == 0:
            console.print("[bold green]Scan complete — no critical findings.[/bold green]")
        elif exit_code == 1:
            console.print("[bold red]Scan complete — findings exceed threshold.[/bold red]")
        else:
            console.print(f"[bold yellow]Scan finished with exit code {exit_code}.[/bold yellow]")
    except Exception as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")


def handle_full_scan(session: InteractiveSession, console: Console) -> None:
    """Run full security scan on loaded firmware."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    timeout = questionary.text("Fuzz timeout (seconds):", default="120").ask()
    try:
        timeout_int = int(timeout)
    except (ValueError, TypeError):
        timeout_int = 120

    console.print("[dim]Running full security scan...[/dim]")
    try:
        from rtosploit.ci.pipeline import CIPipeline, CIConfig
        config = CIConfig(
            firmware_path=str(fw.path),
            machine=fw.machine or "mps2-an385",
            fuzz_timeout=timeout_int,
            output_dir=str(session.output_dir),
            formats=["sarif", "html"],
        )
        pipeline = CIPipeline(config)
        exit_code = pipeline.run()

        if exit_code == 0:
            console.print("[bold green]Full scan complete — no critical findings.[/bold green]")
        elif exit_code == 1:
            console.print("[bold red]Full scan complete — findings exceed threshold.[/bold red]")
        else:
            console.print(f"[bold yellow]Scan finished with exit code {exit_code}.[/bold yellow]")
    except Exception as exc:
        console.print(f"[red]Full scan failed: {exc}[/red]")
