"""CVE handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_cve_search(session: InteractiveSession, console: Console) -> None:
    """Search CVE database."""
    term = questionary.text("Search term (CVE ID, keyword, or RTOS name):").ask()
    if not term:
        return

    console.print(f"[dim]Searching for '{term}'...[/dim]")
    try:
        from rtosploit.cve.database import CVEDatabase
        db = CVEDatabase()
        results = db.search(term)

        if not results:
            console.print("[yellow]No CVEs found.[/yellow]")
            return

        table = Table(title=f"CVE Results for '{term}'", show_header=True, header_style="bold cyan")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Description")

        for cve in results[:20]:
            cve_id = getattr(cve, "cve_id", str(cve))
            severity = getattr(cve, "severity", "unknown")
            desc = getattr(cve, "description", "")[:80]
            table.add_row(cve_id, severity, desc)

        console.print(table)
        if len(results) > 20:
            console.print(f"[dim]Showing 20 of {len(results)} results.[/dim]")
    except Exception as exc:
        console.print(f"[red]CVE search failed: {exc}[/red]")


def handle_cve_correlate(session: InteractiveSession, console: Console) -> None:
    """Correlate CVEs with loaded firmware."""
    fw = session.firmware
    if not fw or not fw.fingerprint:
        console.print("[red]Load and fingerprint firmware first.[/red]")
        return

    console.print(f"[dim]Correlating CVEs for {fw.rtos_name} {fw.rtos_version}...[/dim]")
    try:
        from rtosploit.cve.correlator import CVECorrelator
        correlator = CVECorrelator()
        results = correlator.correlate(fw.fingerprint)

        if not results:
            console.print("[green]No known CVEs found for this firmware.[/green]")
            return

        table = Table(title="CVE Correlation Results", show_header=True, header_style="bold cyan")
        table.add_column("CVE ID", style="cyan")
        table.add_column("Severity", style="red")
        table.add_column("Affected", style="yellow")
        table.add_column("Description")

        for cve in results:
            cve_id = getattr(cve, "cve_id", str(cve))
            severity = getattr(cve, "severity", "unknown")
            affected = getattr(cve, "affected_versions", "")
            desc = getattr(cve, "description", "")[:60]
            table.add_row(cve_id, severity, str(affected), desc)

        console.print(table)
        console.print(f"[bold red]{len(results)} CVE(s) potentially applicable.[/bold red]")
    except Exception as exc:
        console.print(f"[red]CVE correlation failed: {exc}[/red]")
