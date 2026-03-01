"""SVD operations handler for interactive mode."""

from __future__ import annotations

import logging
from pathlib import Path

import questionary
from rich.console import Console
from rich.table import Table

from rtosploit.interactive.session import InteractiveSession, normalize_path

logger = logging.getLogger(__name__)


def handle_svd(session: InteractiveSession, console: Console) -> None:
    """SVD file operations sub-menu."""
    while True:
        action = questionary.select(
            "SVD Operations:",
            choices=[
                questionary.Choice("Parse SVD File", value="parse"),
                questionary.Choice("Generate Peripheral Stubs", value="generate"),
                questionary.Choice("Download SVD", value="download"),
                questionary.Choice("Back", value="back"),
            ],
        ).ask()

        if not action or action == "back":
            return

        if action == "parse":
            _handle_parse(console)
        elif action == "generate":
            _handle_generate(console)
        elif action == "download":
            _handle_download(console)


def _handle_parse(console: Console) -> None:
    """Parse an SVD file and display peripherals."""
    svd_path = questionary.path("SVD file path:").ask()
    if not svd_path:
        return

    path = normalize_path(svd_path)
    if not path.exists():
        console.print(f"[red]File not found: {path}[/red]")
        return

    console.print(f"[dim]Parsing {path.name}...[/dim]")
    try:
        import xml.etree.ElementTree as ET

        tree = ET.parse(str(path))
        root = tree.getroot()

        table = Table(title=f"Peripherals — {path.name}", border_style="cyan")
        table.add_column("Name", style="bold")
        table.add_column("Base Address")
        table.add_column("Description")
        table.add_column("Registers", justify="right")

        for periph in root.findall(".//peripheral"):
            name = periph.findtext("name", "?")
            base = periph.findtext("baseAddress", "?")
            desc = periph.findtext("description", "")
            if desc and len(desc) > 50:
                desc = desc[:47] + "..."
            regs = len(periph.findall(".//register"))
            table.add_row(name, base, desc, str(regs))

        console.print()
        console.print(table)
        console.print()
    except Exception as exc:
        console.print(f"[red]Parse failed: {exc}[/red]")


def _handle_generate(console: Console) -> None:
    """Generate peripheral stubs from SVD."""
    svd_path = questionary.path("SVD file path:").ask()
    if not svd_path:
        return

    stub_type = questionary.select(
        "Stub type:",
        choices=[
            questionary.Choice("Reset Value Stubs", value="reset"),
            questionary.Choice("Read/Write Handler Stubs", value="readwrite"),
            questionary.Choice("Fuzzer Stubs", value="fuzzer"),
        ],
    ).ask()
    if not stub_type:
        return

    output_dir = questionary.path(
        "Output directory:",
        default="./generated_stubs",
    ).ask()
    if not output_dir:
        return

    console.print(f"[dim]Generating {stub_type} stubs...[/dim]")
    try:
        from rtosploit.cli.commands.svd import (
            _parse_svd_peripherals,
            _generate_reset_value_stub,
            _generate_read_write_stub,
            _generate_fuzzer_stub,
            _generate_peripheral_map_header,
        )

        peripherals = _parse_svd_peripherals(str(normalize_path(svd_path)))
        out = normalize_path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        generators = {
            "reset": _generate_reset_value_stub,
            "readwrite": _generate_read_write_stub,
            "fuzzer": _generate_fuzzer_stub,
        }
        gen = generators[stub_type]

        for periph in peripherals:
            code = gen(periph)
            name = periph["name"].lower()
            (out / f"{name}_stub.c").write_text(code)

        header = _generate_peripheral_map_header()
        (out / "peripheral_map.h").write_text(header)

        console.print(f"[green]Generated {len(peripherals)} stubs in {out}[/green]")
    except Exception as exc:
        console.print(f"[red]Generation failed: {exc}[/red]")


def _handle_download(console: Console) -> None:
    """Download an SVD file for a device."""
    device = questionary.text("Device name (e.g. STM32F103):").ask()
    if not device:
        return

    output_dir = questionary.path(
        "Save to directory:",
        default=".",
    ).ask()
    if not output_dir:
        return

    console.print(f"[dim]Searching for SVD file for {device}...[/dim]")
    try:
        from rtosploit.cli.commands.svd import _guess_vendor
        import urllib.request

        vendor = _guess_vendor(device)
        if not vendor:
            console.print(f"[yellow]Could not determine vendor for {device}.[/yellow]")
            return

        base_url = "https://raw.githubusercontent.com/cmsis-svd/cmsis-svd-data/main"
        candidates = [
            f"{device}.svd",
            f"{device.upper()}.SVD",
            f"{device}.xml",
            f"{device.upper()}.xml",
        ]

        out = normalize_path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        for candidate in candidates:
            url = f"{base_url}/{vendor}/{candidate}"
            dest = out / candidate
            try:
                urllib.request.urlretrieve(url, str(dest))
                console.print(f"[green]Downloaded: {dest}[/green]")
                return
            except Exception:
                continue

        console.print(f"[yellow]No SVD file found for {device} (vendor: {vendor}).[/yellow]")
    except Exception as exc:
        console.print(f"[red]Download failed: {exc}[/red]")
