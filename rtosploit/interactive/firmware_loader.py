"""Firmware loading with interactive prompts."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .session import FirmwareContext, InteractiveSession, normalize_path

logger = logging.getLogger(__name__)


def _auto_detect_machine(architecture: str, rtos_type: str | None = None) -> str | None:
    """Pick a default QEMU machine based on architecture and RTOS."""
    _SPECIFIC = {
        ("xtensa", "esp-idf"): "esp32",
    }
    _DEFAULTS = {
        "armv7m": "mps2-an385",
        "armv8m": "mps2-an505",
        "arm":    "mps2-an385",
        "riscv32": "sifive_e",
        "xtensa": "esp32",
    }
    return _SPECIFIC.get((architecture, rtos_type)) or _DEFAULTS.get(architecture)


def _display_firmware_info(
    ctx: FirmwareContext,
    console: Console,
) -> None:
    """Show a Rich panel with firmware details."""
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")

    table.add_row("Firmware", f"{ctx.path.name} ({ctx.size_kb:.0f} KB)")
    table.add_row("RTOS", f"{ctx.rtos_name} {ctx.rtos_version}".strip())
    table.add_row("Arch", ctx.arch_name)
    if ctx.machine:
        table.add_row("Machine", f"{ctx.machine} (auto)")

    if ctx.fingerprint and ctx.fingerprint.confidence:
        pct = ctx.fingerprint.confidence * 100
        table.add_row("Confidence", f"{pct:.0f}%")

    console.print(Panel(table, border_style="cyan", expand=False))


def load_firmware_interactive(session: InteractiveSession, console: Console) -> None:
    """Prompt for firmware path, load, fingerprint, and display info."""
    # 1. Prompt for firmware path
    fw_path = questionary.path(
        "Firmware file path:",
    ).ask()

    if fw_path is None:
        return  # Ctrl+C

    path = normalize_path(fw_path)
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        return
    if not path.is_file():
        console.print(f"[red]Not a file: {path}[/red]")
        return

    # 2. Load firmware
    console.print(f"[dim]Loading {path.name}...[/dim]")
    try:
        from rtosploit.utils.binary import load_firmware
        image = load_firmware(str(path))
    except Exception as exc:
        console.print(f"[red]Failed to load firmware: {exc}[/red]")
        return

    # 3. Fingerprint
    fingerprint = None
    try:
        from rtosploit.analysis.fingerprint import fingerprint_firmware
        fingerprint = fingerprint_firmware(image)
        if fingerprint.rtos_type == "unknown":
            console.print("[yellow]Could not identify RTOS.[/yellow]")
    except Exception as exc:
        console.print(f"[yellow]Fingerprint failed: {exc}[/yellow]")

    # 3b. Refine architecture from RTOS if still unknown
    rtos_type = None
    if fingerprint and fingerprint.rtos_type != "unknown":
        rtos_type = fingerprint.rtos_type
        if image.architecture == "unknown":
            _RTOS_ARCH_HINTS = {
                "esp-idf": "xtensa",
            }
            hinted = _RTOS_ARCH_HINTS.get(rtos_type)
            if hinted:
                image.architecture = hinted

    # 4. Auto-detect machine
    arch = image.architecture
    machine = _auto_detect_machine(arch, rtos_type)

    # 5. Build context
    ctx = FirmwareContext(
        path=path,
        image=image,
        fingerprint=fingerprint,
        machine=machine,
    )

    # 6. Display info
    _display_firmware_info(ctx, console)

    # 7. Override machine?
    if machine:
        override = questionary.confirm(
            "Override machine config?",
            default=False,
        ).ask()

        if override:
            try:
                from rtosploit.emulation.machines import list_machines
                machines = list_machines()
                if machines:
                    choices = [f"{name} ({cpu}, {arch})" for name, cpu, arch in machines]
                    selected = questionary.select(
                        "Select machine:",
                        choices=choices,
                    ).ask()
                    if selected:
                        # Extract machine name from "name (cpu, arch)"
                        machine = selected.split(" (")[0]
                        ctx.machine = machine
                else:
                    manual = questionary.text("Machine name:").ask()
                    if manual:
                        ctx.machine = manual.strip()
            except Exception as exc:
                console.print(f"[yellow]Could not list machines: {exc}[/yellow]")
                manual = questionary.text("Machine name:").ask()
                if manual:
                    ctx.machine = manual.strip()
    else:
        # No auto-detect — must pick manually
        manual = questionary.text(
            "Machine name (e.g. mps2-an385):",
        ).ask()
        if manual:
            ctx.machine = manual.strip()

    # 8. Load machine config
    if ctx.machine:
        try:
            from rtosploit.emulation.machines import load_machine
            ctx.machine_config = load_machine(ctx.machine)
        except Exception as exc:
            console.print(f"[yellow]Could not load machine config: {exc}[/yellow]")

    # 9. Store in session
    session.firmware = ctx
    console.print("[green]Firmware loaded successfully.[/green]")
