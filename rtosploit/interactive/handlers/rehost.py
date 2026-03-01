"""Rehosting handler for interactive mode."""

from __future__ import annotations

import logging
from pathlib import Path

import questionary
from rich.console import Console

from rtosploit.interactive.session import InteractiveSession, normalize_path

logger = logging.getLogger(__name__)


def handle_rehost(session: InteractiveSession, console: Console) -> None:
    """Run firmware with HAL peripheral intercepts."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    if not fw.machine:
        console.print("[red]No machine configured. Reload firmware with a machine target.[/red]")
        return

    # Peripheral config (optional)
    use_config = questionary.confirm(
        "Use a peripheral configuration YAML?",
        default=False,
    ).ask()

    periph_config = None
    if use_config:
        config_path = questionary.path("Peripheral config YAML:").ask()
        if config_path:
            p = normalize_path(config_path)
            if not p.exists():
                console.print(f"[red]File not found: {p}[/red]")
                return
            periph_config = str(p)

    timeout_str = questionary.text(
        "Timeout (seconds, 0 for unlimited):",
        default="0",
    ).ask()
    try:
        timeout = int(timeout_str) if timeout_str else 0
    except ValueError:
        timeout = 0

    console.print("[dim]Starting rehosted firmware...[/dim]")
    try:
        from rtosploit.peripherals.rehost import RehostingEngine

        engine = RehostingEngine(
            firmware_path=str(fw.path),
            machine_name=fw.machine,
            peripheral_config=periph_config,
            config=fw.machine_config,
        )

        # Use existing QEMU instance if available, otherwise create one
        if fw.qemu:
            qemu = fw.qemu
        else:
            from rtosploit.emulation.qemu import QEMUInstance
            qemu = QEMUInstance(
                firmware_path=str(fw.path),
                machine=fw.machine,
                config=fw.machine_config,
            )
            qemu.start()
            fw.qemu = qemu

        console.print("[dim]Setting up peripheral intercepts...[/dim]")
        engine.run_interactive(qemu, timeout=timeout)
        console.print("[green]Rehosting session ended.[/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Rehosting interrupted.[/yellow]")
    except Exception as exc:
        console.print(f"[red]Rehosting failed: {exc}[/red]")
