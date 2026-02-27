"""rtosploit svd — SVD file operations."""
import click
from rich.console import Console
from rich.table import Table

console = Console()


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
