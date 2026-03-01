"""rtosploit coverage — coverage visualization and analysis."""

from __future__ import annotations

import click
from rich.console import Console

console = Console()


@click.group("coverage")
def coverage():
    """Coverage visualization and analysis."""
    pass


@coverage.command()
@click.option("--bitmap", "-b", type=click.Path(exists=True), default=None, help="AFL-style bitmap file")
@click.option("--trace", "-t", type=click.Path(exists=True), default=None, help="Trace log file")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary")
@click.option("--base-address", type=str, default="0x08000000", help="Firmware base address (hex)")
@click.option("--format", "fmt", type=click.Choice(["terminal", "html"]), default="terminal", help="Output format")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output file (for HTML)")
@click.option("--max-lines", type=int, default=50, help="Max lines for terminal output")
@click.pass_context
def view(ctx, bitmap, trace, firmware, base_address, fmt, output, max_lines):
    """View coverage visualization.

    \b
    Requires at least one of --bitmap or --trace.

    \b
    Examples:
      rtosploit coverage view -f fw.bin -t trace.log
      rtosploit coverage view -f fw.bin -b bitmap.bin --format html -o report.html
    """
    if bitmap is None and trace is None:
        raise click.UsageError("At least one of --bitmap or --trace is required.")

    from rtosploit.coverage.bitmap_reader import BitmapReader
    from rtosploit.coverage.mapper import CoverageMapper
    from rtosploit.coverage.visualizer import CoverageVisualizer

    base = int(base_address, 16)
    mapper = CoverageMapper(firmware, base_address=base)
    reader = BitmapReader()

    bitmap_data = None
    if bitmap:
        bitmap_data = reader.read_file(bitmap)

    if trace:
        cov_map = mapper.map_from_trace(trace, bitmap_data=bitmap_data)
    else:
        cov_map = mapper.map_from_bitmap(bitmap_data)

    disasm = mapper.disassemble_firmware()
    # Update total instructions from disassembly
    cov_map.total_instructions = len(disasm)
    all_addrs = {addr for addr, _, _ in disasm}
    cov_map.covered_instructions = len(cov_map.covered_addresses & all_addrs)

    viz = CoverageVisualizer(cov_map, disasm)

    if fmt == "html":
        if output is None:
            output = "coverage_report.html"
        viz.write_html(output)
        console.print(f"[green]HTML report written to:[/green] [cyan]{output}[/cyan]")
    else:
        rendered = viz.render_terminal(max_lines=max_lines)
        console.print(rendered)


@coverage.command()
@click.option("--bitmap", "-b", type=click.Path(exists=True), default=None, help="AFL-style bitmap file")
@click.option("--trace", "-t", type=click.Path(exists=True), default=None, help="Trace log file")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary")
@click.option("--base-address", type=str, default="0x08000000", help="Firmware base address (hex)")
@click.pass_context
def stats(ctx, bitmap, trace, firmware, base_address):
    """Show coverage statistics.

    \b
    Examples:
      rtosploit coverage stats -f fw.bin -t trace.log
      rtosploit coverage stats -f fw.bin -b bitmap.bin
    """
    if bitmap is None and trace is None:
        raise click.UsageError("At least one of --bitmap or --trace is required.")

    import json as json_mod

    from rtosploit.coverage.bitmap_reader import BitmapReader
    from rtosploit.coverage.mapper import CoverageMapper
    from rtosploit.coverage.visualizer import CoverageVisualizer

    output_json = ctx.obj.get("output_json", False) if ctx.obj else False

    base = int(base_address, 16)
    mapper = CoverageMapper(firmware, base_address=base)
    reader = BitmapReader()

    bitmap_data = None
    if bitmap:
        bitmap_data = reader.read_file(bitmap)

    if trace:
        cov_map = mapper.map_from_trace(trace, bitmap_data=bitmap_data)
    else:
        cov_map = mapper.map_from_bitmap(bitmap_data)

    disasm = mapper.disassemble_firmware()
    cov_map.total_instructions = len(disasm)
    all_addrs = {addr for addr, _, _ in disasm}
    cov_map.covered_instructions = len(cov_map.covered_addresses & all_addrs)

    viz = CoverageVisualizer(cov_map, disasm)
    stat = viz.get_stats()

    if output_json:
        # Serialize hot_spots as list of dicts
        stat["hot_spots"] = [
            {"address": f"0x{addr:08x}", "hits": count}
            for addr, count in stat["hot_spots"]
        ]
        click.echo(json_mod.dumps(stat, indent=2))
    else:
        console.print("[bold cyan]Coverage Statistics[/bold cyan]")
        console.print(f"  Total instructions:   {stat['total_instructions']}")
        console.print(f"  Covered instructions: {stat['covered_instructions']}")
        console.print(f"  Coverage:             {stat['coverage_percent']:.1f}%")
        console.print(f"  Total edges:          {stat['total_edges']}")
        if stat["hot_spots"]:
            console.print("\n[bold cyan]Top Hot Spots[/bold cyan]")
            for addr, count in stat["hot_spots"]:
                console.print(f"  [green]0x{addr:08x}[/green]: {count} hits")
