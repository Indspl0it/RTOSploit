"""VulnRange labs handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_vulnrange(session: InteractiveSession, console: Console) -> None:
    """Browse and interact with VulnRange practice labs."""
    try:
        from rtosploit.vulnrange.manager import VulnRangeManager
    except ImportError:
        console.print("[red]VulnRange module not available.[/red]")
        return

    mgr = VulnRangeManager("vulnrange")
    ranges = mgr.list()

    if not ranges:
        console.print("[yellow]No VulnRange labs found.[/yellow]")
        return

    # Display table of available labs
    table = Table(title="VulnRange Labs", border_style="cyan")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("CVE")
    table.add_column("Difficulty")
    table.add_column("RTOS")
    console.print()

    for r in ranges:
        table.add_row(
            r.get("id", "?"),
            r.get("name", "?"),
            r.get("cve", "N/A"),
            r.get("difficulty", "?"),
            r.get("rtos", "?"),
        )
    console.print(table)
    console.print()

    # Select a range
    choices = [r.get("id", "?") for r in ranges] + ["Back"]
    selected = questionary.select("Select a lab:", choices=choices).ask()
    if not selected or selected == "Back":
        return

    range_id = selected
    _vulnrange_submenu(mgr, range_id, session, console)


def _vulnrange_submenu(
    mgr: object,
    range_id: str,
    session: InteractiveSession,
    console: Console,
) -> None:
    """Sub-menu for a specific VulnRange lab."""
    while True:
        action = questionary.select(
            f"VulnRange [{range_id}]:",
            choices=[
                questionary.Choice("Start Lab", value="start"),
                questionary.Choice("Hint (Level 1)", value="hint1"),
                questionary.Choice("Hint (Level 2)", value="hint2"),
                questionary.Choice("Hint (Level 3)", value="hint3"),
                questionary.Choice("Solve", value="solve"),
                questionary.Choice("Writeup", value="writeup"),
                questionary.Choice("Back", value="back"),
            ],
        ).ask()

        if not action or action == "back":
            return

        try:
            if action == "start":
                info = mgr.get_range_info(range_id)
                if info:
                    console.print(f"\n[bold]{info.get('name', range_id)}[/bold]")
                    if info.get("description"):
                        console.print(f"[dim]{info['description']}[/dim]")
                    console.print(f"Target: {info.get('target', 'N/A')}")
                    console.print(f"CVE: {info.get('cve', 'N/A')}\n")
                else:
                    console.print(f"[yellow]No info for {range_id}.[/yellow]")

            elif action.startswith("hint"):
                level = int(action[-1])
                hint = mgr.hint(range_id, level)
                if hint:
                    console.print(f"\n[bold yellow]Hint {level}:[/bold yellow] {hint}\n")
                else:
                    console.print(f"[yellow]No hint at level {level}.[/yellow]")

            elif action == "solve":
                exploit_path = mgr.get_exploit_path(range_id)
                if exploit_path:
                    console.print(f"\n[green]Exploit script:[/green] {exploit_path}\n")
                else:
                    console.print("[yellow]No exploit script available.[/yellow]")

            elif action == "writeup":
                writeup_path = mgr.get_writeup_path(range_id)
                if writeup_path:
                    console.print(f"\n[green]Writeup:[/green] {writeup_path}\n")
                else:
                    console.print("[yellow]No writeup available.[/yellow]")

        except Exception as exc:
            console.print(f"[red]Error: {exc}[/red]")
