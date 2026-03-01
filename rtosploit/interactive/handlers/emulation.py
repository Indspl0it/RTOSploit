"""Emulation handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_boot_qemu(session: InteractiveSession, console: Console) -> None:
    """Boot firmware in QEMU."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    if fw.qemu is not None:
        action = questionary.select(
            "QEMU is already running.",
            choices=[
                questionary.Choice("Restart QEMU", value="restart"),
                questionary.Choice("Keep running", value="keep"),
            ],
        ).ask()
        if action == "keep":
            return
        try:
            fw.qemu.stop()
        except Exception:
            pass
        fw.qemu = None

    machine = fw.machine or "mps2-an385"
    paused = questionary.confirm("Start paused (for GDB attach)?", default=False).ask()

    console.print(f"[dim]Booting {fw.path.name} on {machine}...[/dim]")
    try:
        from rtosploit.config import RTOSploitConfig
        from rtosploit.emulation.qemu import QEMUInstance

        config = RTOSploitConfig()
        qemu = QEMUInstance(config)
        qemu.start(
            firmware_path=str(fw.path),
            machine_name=machine,
            gdb=False,
            paused=paused,
        )
        fw.qemu = qemu
        console.print(f"[green]QEMU started successfully.[/green]")
        if paused:
            console.print("[dim]Attach GDB to continue execution.[/dim]")
    except Exception as exc:
        console.print(f"[red]Failed to start QEMU: {exc}[/red]")


def handle_attach_gdb(session: InteractiveSession, console: Console) -> None:
    """Attach GDB debugger to running QEMU."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    if fw.qemu is None:
        start = questionary.confirm(
            "QEMU is not running. Start it first?",
            default=True,
        ).ask()
        if start:
            handle_boot_qemu(session, console)
        if fw.qemu is None:
            return

    port = questionary.text("GDB port:", default="1234").ask()
    try:
        port_int = int(port)
    except (ValueError, TypeError):
        port_int = 1234

    console.print(f"[dim]Attaching GDB on port {port_int}...[/dim]")
    try:
        from rtosploit.emulation.gdb import GDBClient
        gdb = GDBClient()
        gdb.connect(host="localhost", port=port_int)
        console.print(f"[green]GDB connected on port {port_int}.[/green]")
        console.print(f"[dim]Use 'target remote localhost:{port_int}' from your GDB client.[/dim]")
    except Exception as exc:
        console.print(f"[red]GDB attach failed: {exc}[/red]")
        console.print(f"[dim]Try connecting manually: target remote localhost:{port_int}[/dim]")
