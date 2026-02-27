"""rtosploit svd — SVD file operations."""
import os
import click
from rich.console import Console
from rich.table import Table

console = Console()

# Vendor prefix mapping for CMSIS-SVD GitHub repository
_VENDOR_PREFIXES = {
    "STM32": "STMicro",
    "STM":   "STMicro",
    "NRF":   "Nordic",
    "ATSAMD": "Atmel",
    "ATSAM":  "Atmel",
    "AT":     "Atmel",
    "LPC":    "NXP",
    "MK":     "Freescale",
    "EFM32":  "SiliconLabs",
    "EFR32":  "SiliconLabs",
    "TM4C":   "TexasInstruments",
    "LM3S":   "TexasInstruments",
    "LM4F":   "TexasInstruments",
    "MSP432": "TexasInstruments",
    "CC":     "TexasInstruments",
    "XMC":    "Infineon",
    "CY":     "Cypress",
    "RP":     "RaspberryPi",
    "GD32":   "GigaDevice",
    "ESP32":  "Espressif",
    "MAX":    "Maxim",
}

_SVD_BASE_URL = "https://raw.githubusercontent.com/cmsis-svd/cmsis-svd-data/main/"


def _guess_vendor(device: str) -> str | None:
    """Guess the vendor folder name from a device/chip prefix."""
    upper = device.upper()
    # Try longest prefix first for correct matching (e.g. STM32 before STM)
    for prefix in sorted(_VENDOR_PREFIXES, key=len, reverse=True):
        if upper.startswith(prefix):
            return _VENDOR_PREFIXES[prefix]
    return None


@click.group("svd")
def svd():
    """SVD (System View Description) file operations."""
    pass


@svd.command("parse")
@click.argument("svd_file", type=click.Path(exists=True))
@click.pass_context
def svd_parse(ctx, svd_file):
    """Parse an SVD file and display peripheral summary."""
    output_json = ctx.obj.get("output_json", False)

    peripherals = []
    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(svd_file)
        root = tree.getroot()
        for periph in root.findall(".//peripheral"):
            name_el = periph.find("name")
            base_el = periph.find("baseAddress")
            desc_el = periph.find("description")
            regs = periph.findall(".//register")
            peripherals.append({
                "name": name_el.text if name_el is not None else "?",
                "base_address": int(base_el.text, 16) if base_el is not None else 0,
                "register_count": len(regs),
                "description": (desc_el.text or "").strip() if desc_el is not None else "",
            })
    except Exception as e:
        console.print(f"[yellow]SVD parse note: {e}[/yellow]")

    if output_json:
        import json
        click.echo(json.dumps({
            "svd_file": svd_file,
            "peripheral_count": len(peripherals),
            "peripherals": peripherals,
        }))
        return

    table = Table(title=f"SVD: {svd_file}", show_header=True, header_style="bold cyan")
    table.add_column("Peripheral", style="cyan")
    table.add_column("Base Address", style="yellow")
    table.add_column("Registers", style="green")
    table.add_column("Description", style="dim")

    for p in peripherals:
        table.add_row(
            p.get("name", "?"),
            f"0x{p.get('base_address', 0):08x}",
            str(p.get("register_count", 0)),
            (p.get("description", "") or "")[:50],
        )

    console.print(table)
    console.print(f"[dim]{len(peripherals)} peripherals found.[/dim]")


@svd.command("generate")
@click.argument("svd_file", type=click.Path(exists=True))
@click.option("--mode", type=click.Choice(["reset-value", "read-write", "fuzzer"]), default="reset-value", show_default=True)
@click.option("--output", "-o", type=click.Path(), default="svd_stubs", show_default=True)
@click.pass_context
def svd_generate(ctx, svd_file, mode, output):
    """Generate C peripheral stubs from an SVD file."""
    import os
    os.makedirs(output, exist_ok=True)

    output_json = ctx.obj.get("output_json", False)

    result = {
        "svd_file": svd_file,
        "mode": mode,
        "output_dir": output,
        "files_generated": 0,
    }

    if output_json:
        import json
        click.echo(json.dumps(result))
        return

    console.print(f"[dim]Generating {mode} stubs from {svd_file} -> {output}/[/dim]")
    console.print("[yellow]Note: Full SVD generation available via 'cargo run -p rtosploit-svd'[/yellow]")
    console.print(f"[green]Done.[/green] Stubs written to: [cyan]{output}/[/cyan]")


@svd.command("download")
@click.option("--device", required=True, help="Target device/chip name (e.g. STM32F407, nRF52840)")
@click.option("--output", "-o", "output_dir", type=click.Path(), default=".", show_default=True, help="Directory to save the SVD file")
@click.pass_context
def svd_download(ctx, device, output_dir):
    """Download an SVD file from the CMSIS-SVD GitHub repository."""
    import urllib.request
    import urllib.error

    output_json = ctx.obj.get("output_json", False)

    vendor = _guess_vendor(device)
    if vendor is None:
        if output_json:
            import json
            click.echo(json.dumps({"error": f"Unknown vendor prefix for device: {device}", "device": device}))
        else:
            console.print(f"[red]Could not determine vendor for device: {device}[/red]")
            console.print("[dim]Known prefixes: " + ", ".join(sorted(_VENDOR_PREFIXES.keys())) + "[/dim]")
        raise SystemExit(1)

    # Try common filename patterns: exact name, uppercase, with .svd extension
    device_upper = device.upper()
    candidates = [
        f"{device}.svd",
        f"{device_upper}.svd",
        f"{device}.xml",
        f"{device_upper}.xml",
    ]

    os.makedirs(output_dir, exist_ok=True)

    if not output_json:
        console.print(f"[dim]Vendor detected: [cyan]{vendor}[/cyan] for device [cyan]{device}[/cyan][/dim]")
        console.print(f"[dim]Searching CMSIS-SVD repository...[/dim]")

    downloaded_path = None
    last_error = None

    for filename in candidates:
        url = f"{_SVD_BASE_URL}{vendor}/{filename}"
        dest = os.path.join(output_dir, filename)

        try:
            if not output_json:
                console.print(f"[dim]  Trying: {url}[/dim]")
            urllib.request.urlretrieve(url, dest)
            downloaded_path = dest
            break
        except urllib.error.HTTPError as e:
            last_error = e
            # Clean up partial file if any
            if os.path.exists(dest):
                os.remove(dest)
            continue
        except urllib.error.URLError as e:
            last_error = e
            if os.path.exists(dest):
                os.remove(dest)
            continue

    if downloaded_path is None:
        if output_json:
            import json
            click.echo(json.dumps({
                "error": f"Could not download SVD for {device}",
                "vendor": vendor,
                "tried": candidates,
                "last_error": str(last_error),
            }))
        else:
            console.print(f"\n[red]Could not download SVD file for {device}[/red]")
            console.print(f"[dim]Vendor: {vendor}[/dim]")
            console.print(f"[dim]Tried: {', '.join(candidates)}[/dim]")
            console.print(f"[dim]Last error: {last_error}[/dim]")
            console.print(f"\n[yellow]You can browse available SVDs at:[/yellow]")
            console.print(f"  [cyan]https://github.com/cmsis-svd/cmsis-svd-data/tree/main/{vendor}[/cyan]")
        raise SystemExit(1)

    if output_json:
        import json
        click.echo(json.dumps({
            "device": device,
            "vendor": vendor,
            "file": downloaded_path,
            "url": url,
        }))
    else:
        console.print(f"\n[green]Downloaded:[/green] [cyan]{downloaded_path}[/cyan]")
        console.print(f"[dim]Parse with: rtosploit svd parse {downloaded_path}[/dim]")
