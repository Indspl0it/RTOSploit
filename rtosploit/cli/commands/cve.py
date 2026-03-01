"""CLI commands for CVE correlation and lookup."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.group()
def cve():
    """Firmware CVE correlation and lookup."""
    pass


@cve.command()
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Path to firmware binary.")
@click.option("--rtos", type=str, default=None, help="Override RTOS detection (freertos/threadx/zephyr).")
@click.option("--version", type=str, default=None, help="Override version detection.")
@click.pass_context
def scan(ctx, firmware: str, rtos: str | None, version: str | None):
    """Scan firmware for known CVEs.

    Fingerprints the firmware to detect the RTOS and version, then
    correlates against the bundled CVE database.
    """
    from rtosploit.cve import CVEDatabase, CVECorrelator
    from rtosploit.utils.binary import load_firmware
    from rtosploit.analysis.fingerprint import fingerprint_firmware

    output_json = ctx.obj.get("output_json", False)

    fw = load_firmware(firmware)

    if rtos is None or version is None:
        fp = fingerprint_firmware(fw)
        if rtos is None:
            rtos = fp.rtos_type
        if version is None:
            version = fp.version

    if rtos == "unknown":
        if output_json:
            click.echo(json.dumps({"error": "Could not detect RTOS. Use --rtos to specify."}))
        else:
            console.print("[yellow]Could not detect RTOS from firmware. Use --rtos to specify.[/yellow]")
        sys.exit(1)

    db = CVEDatabase()
    db.load()
    correlator = CVECorrelator(db)
    result = correlator.correlate(rtos, version)

    if output_json:
        click.echo(json.dumps({
            "rtos": result.rtos,
            "version": result.version,
            "total_cves": result.total_cves,
            "highest_severity": result.highest_severity,
            "matching_cves": [c.to_dict() for c in result.matching_cves],
            "exploitable_cves": [c.to_dict() for c in result.exploitable_cves],
        }, indent=2))
        return

    console.print(f"\n[bold]CVE Scan Results[/bold] for [cyan]{rtos}[/cyan]", end="")
    if version:
        console.print(f" v[cyan]{version}[/cyan]")
    else:
        console.print(" (all versions)")

    console.print(f"Total CVEs found: [bold]{result.total_cves}[/bold]")
    console.print(f"Exploitable (RTOSploit modules): [bold red]{len(result.exploitable_cves)}[/bold red]")
    console.print(f"Highest severity: [bold]{result.highest_severity}[/bold]\n")

    if result.matching_cves:
        table = Table(title="Matching CVEs")
        table.add_column("CVE ID", style="cyan")
        table.add_column("CVSS", justify="right")
        table.add_column("Severity")
        table.add_column("Exploit?", justify="center")
        table.add_column("Description", max_width=60)

        for cve_entry in sorted(result.matching_cves, key=lambda c: c.cvss_score or 0, reverse=True):
            sev_style = {
                "critical": "bold red",
                "high": "red",
                "medium": "yellow",
                "low": "green",
            }.get(cve_entry.severity, "white")

            table.add_row(
                cve_entry.cve_id,
                f"{cve_entry.cvss_score:.1f}" if cve_entry.cvss_score else "N/A",
                f"[{sev_style}]{cve_entry.severity}[/{sev_style}]",
                "[bold red]YES[/bold red]" if cve_entry.has_exploit else "no",
                cve_entry.description[:60],
            )

        console.print(table)


@cve.command()
@click.argument("term")
@click.pass_context
def search(ctx, term: str):
    """Search CVE database by term (CVE ID, keyword, product name)."""
    from rtosploit.cve import CVEDatabase

    output_json = ctx.obj.get("output_json", False)

    db = CVEDatabase()
    db.load()
    results = db.search(term)

    if output_json:
        click.echo(json.dumps([c.to_dict() for c in results], indent=2))
        return

    if not results:
        console.print(f"[yellow]No CVEs found matching '{term}'[/yellow]")
        return

    table = Table(title=f"CVE search: '{term}'")
    table.add_column("CVE ID", style="cyan")
    table.add_column("Product")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Description", max_width=60)

    for entry in results:
        table.add_row(
            entry.cve_id,
            entry.affected_product,
            f"{entry.cvss_score:.1f}" if entry.cvss_score else "N/A",
            entry.severity,
            entry.description[:60],
        )

    console.print(table)
    console.print(f"\n[dim]{len(results)} result(s)[/dim]")


@cve.command()
@click.option("--api-key", type=str, default=None, envvar="NVD_API_KEY", help="NVD API key for higher rate limits.")
@click.option("--product", type=str, default=None, help="Product to fetch (freertos/threadx/zephyr).")
@click.pass_context
def update(ctx, api_key: str | None, product: str | None):
    """Update CVE database from NVD API.

    Fetches the latest CVE data from the NIST NVD and merges new
    entries into the local database.
    """
    from rtosploit.cve import CVEDatabase, NVDClient

    output_json = ctx.obj.get("output_json", False)

    products = [product] if product else ["freertos", "threadx", "zephyr"]
    client = NVDClient(api_key=api_key)
    db = CVEDatabase()
    db.load()

    total_new = 0
    for prod in products:
        if not output_json:
            console.print(f"[dim]Fetching CVEs for {prod}...[/dim]")
        try:
            entries = client.search_cves(prod, product=prod)
            before = len(db.entries)
            db.update_from_nvd(entries)
            after = len(db.entries)
            new_count = after - before
            total_new += new_count
            if not output_json:
                console.print(f"  {prod}: fetched {len(entries)}, {new_count} new")
        except Exception as e:
            if not output_json:
                console.print(f"  [red]Error fetching {prod}: {e}[/red]")

    db.save()

    if output_json:
        click.echo(json.dumps({"new_entries": total_new, "total": len(db.entries)}))
    else:
        console.print(f"\n[green]Database updated: {total_new} new entries, {len(db.entries)} total[/green]")
