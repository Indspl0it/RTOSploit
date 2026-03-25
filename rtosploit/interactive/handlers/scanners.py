"""Vulnerability scanners handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def _get_matching_scanners(rtos_type: str | None) -> list[tuple[str, object]]:
    """Get scanner modules, optionally filtered by RTOS type."""
    try:
        from rtosploit.scanners.registry import ScannerRegistry
        registry = ScannerRegistry()
        registry.discover()

        matches = []
        for path, cls in sorted(registry._modules.items()):
            inst = cls()
            module_rtos = getattr(inst, "rtos", getattr(inst, "target_rtos", ""))
            if rtos_type and rtos_type != "unknown":
                if module_rtos.lower() == rtos_type.lower() or module_rtos == "*":
                    matches.append((path, inst))
            else:
                matches.append((path, inst))
        return matches
    except Exception:
        return []


def handle_scanners(session: InteractiveSession, console: Console) -> None:
    """List and run vulnerability scanner modules."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    rtos_type = fw.fingerprint.rtos_type if fw.fingerprint else None
    matches = _get_matching_scanners(rtos_type)

    if not matches:
        console.print("[yellow]No matching scanner modules found.[/yellow]")
        return

    # Display matching scanners
    table = Table(title="Available Vulnerability Scanners", show_header=True, header_style="bold cyan")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Module", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("Category", style="yellow")
    table.add_column("Reliability", style="magenta")

    for i, (path, inst) in enumerate(matches, 1):
        name = getattr(inst, "name", path)
        category = getattr(inst, "category", "")
        reliability = getattr(inst, "reliability", "")
        table.add_row(str(i), path, name, category, reliability)

    console.print(table)

    # Select action
    choices = [questionary.Choice(f"{path} — {getattr(inst, 'name', '')}", value=path) for path, inst in matches]
    selected = questionary.select(
        "Select scanner module:",
        choices=choices + [questionary.Choice("Back to menu", value=None)],
    ).ask()

    if not selected:
        return

    action = questionary.select(
        f"Action for {selected}:",
        choices=[
            questionary.Choice("Check vulnerability (non-destructive)", value="check"),
            questionary.Choice("Run scan", value="run"),
            questionary.Choice("Launch interactive console with module", value="console"),
            questionary.Choice("Back", value="back"),
        ],
    ).ask()

    if action == "console":
        _launch_console_with_module(session, console, selected)
    elif action in ("check", "run"):
        console.print(f"[dim]Use the interactive console for {action}.[/dim]")
        _launch_console_with_module(session, console, selected)


def _launch_console_with_module(
    session: InteractiveSession,
    console: Console,
    module_path: str,
) -> None:
    """Launch console REPL with a module pre-loaded."""
    try:
        from rtosploit.console.repl import RTOSploitConsole
        repl = RTOSploitConsole()

        # Pre-load module
        repl.cmd_use(module_path)

        # Pre-set firmware if available
        fw = session.firmware
        if fw:
            repl.cmd_set(f"firmware {fw.path}")
            if fw.machine:
                repl.cmd_set(f"machine {fw.machine}")

        repl.run()
    except Exception as exc:
        console.print(f"[red]Console error: {exc}[/red]")


def handle_console(session: InteractiveSession, console: Console) -> None:
    """Launch Metasploit-style console REPL."""
    try:
        from rtosploit.console.repl import RTOSploitConsole
        repl = RTOSploitConsole()

        # Pre-set firmware if available
        if session.firmware:
            fw = session.firmware
            if hasattr(repl.state, "option_values"):
                repl.state.option_values["firmware"] = str(fw.path)
                if fw.machine:
                    repl.state.option_values["machine"] = fw.machine

        repl.run()
    except Exception as exc:
        console.print(f"[red]Console error: {exc}[/red]")
