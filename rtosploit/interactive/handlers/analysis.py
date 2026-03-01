"""Analysis handler for interactive mode."""

from __future__ import annotations

import logging

import questionary
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession

logger = logging.getLogger(__name__)


def handle_analysis(session: InteractiveSession, console: Console) -> None:
    """Run static analysis on loaded firmware."""
    fw = session.firmware
    if not fw:
        console.print("[red]No firmware loaded.[/red]")
        return

    choices = questionary.checkbox(
        "Select analyses to run:",
        choices=[
            questionary.Choice("RTOS Fingerprint", value="fingerprint", checked=True),
            questionary.Choice("Heap Allocator Detection", value="heap", checked=True),
            questionary.Choice("MPU Configuration Check", value="mpu", checked=True),
            questionary.Choice("String Extraction", value="strings"),
        ],
    ).ask()

    if not choices:
        return

    if "fingerprint" in choices:
        console.print("\n[bold cyan]RTOS Fingerprint[/bold cyan]")
        try:
            from rtosploit.analysis.fingerprint import fingerprint_firmware
            fp = fingerprint_firmware(fw.image)
            fw.fingerprint = fp
            table = Table(show_header=False, box=None)
            table.add_column("Key", style="bold")
            table.add_column("Value")
            table.add_row("RTOS", fp.rtos_type)
            table.add_row("Version", fp.version or "Unknown")
            table.add_row("Confidence", f"{fp.confidence * 100:.0f}%")
            for ev in fp.evidence[:5]:
                table.add_row("Evidence", f"[dim]{ev}[/dim]")
            console.print(Panel(table, border_style="cyan", expand=False))
        except Exception as exc:
            console.print(f"[red]Fingerprint failed: {exc}[/red]")

    if "heap" in choices:
        console.print("\n[bold cyan]Heap Detection[/bold cyan]")
        try:
            from rtosploit.analysis.heap_detect import detect_heap
            heap = detect_heap(fw.image)
            table = Table(show_header=False, box=None)
            table.add_column("Key", style="bold")
            table.add_column("Value")
            table.add_row("Allocator", heap.allocator_type)
            if heap.heap_base is not None:
                table.add_row("Base", f"0x{heap.heap_base:08x}")
            if heap.heap_size is not None:
                table.add_row("Size", f"{heap.heap_size:,} bytes")
            for ev in heap.evidence[:5]:
                table.add_row("Evidence", f"[dim]{ev}[/dim]")
            console.print(Panel(table, border_style="cyan", expand=False))
        except Exception as exc:
            console.print(f"[red]Heap detection failed: {exc}[/red]")

    if "mpu" in choices:
        console.print("\n[bold cyan]MPU Configuration[/bold cyan]")
        try:
            from rtosploit.analysis.mpu_check import check_mpu
            mpu = check_mpu(fw.image)
            table = Table(show_header=False, box=None)
            table.add_column("Key", style="bold")
            table.add_column("Value")
            table.add_row("MPU Present", str(mpu.mpu_present))
            table.add_row("Regions", str(mpu.regions_configured))
            for vuln in mpu.vulnerabilities:
                table.add_row("Vulnerability", f"[red]{vuln}[/red]")
            console.print(Panel(table, border_style="cyan", expand=False))
        except Exception as exc:
            console.print(f"[red]MPU check failed: {exc}[/red]")

    if "strings" in choices:
        console.print("\n[bold cyan]String Extraction[/bold cyan]")
        try:
            from rtosploit.analysis.strings import extract_strings
            strings = extract_strings(fw.image)
            console.print(f"  Found [cyan]{len(strings)}[/cyan] strings")
            table = Table(show_header=True, header_style="bold")
            table.add_column("Address", style="cyan")
            table.add_column("String")
            for addr, s in strings[:25]:
                table.add_row(f"0x{addr:08x}", s[:80])
            if len(strings) > 25:
                table.add_row("...", f"({len(strings) - 25} more)")
            console.print(table)
        except Exception as exc:
            console.print(f"[red]String extraction failed: {exc}[/red]")
