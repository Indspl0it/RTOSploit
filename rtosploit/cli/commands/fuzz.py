"""rtosploit fuzz — start QEMU-based firmware fuzzer."""
import click
from rich.console import Console
from rich.table import Table

console = Console()


@click.command("fuzz")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Firmware binary")
@click.option("--machine", "-m", required=True, type=str, help="QEMU machine name")
@click.option("--rtos", type=click.Choice(["freertos", "threadx", "zephyr", "auto"]), default="auto", show_default=True, help="Target RTOS")
@click.option("--output", "-o", type=click.Path(), default="fuzz-output", show_default=True, help="Output directory for crashes and corpus")
@click.option("--seeds", "-s", type=click.Path(exists=True), default=None, help="Seed corpus directory")
@click.option("--timeout", "-t", type=int, default=0, help="Fuzzing timeout in seconds (0=unlimited)")
@click.option("--jobs", "-j", type=int, default=1, show_default=True, help="Parallel fuzzer instances")
@click.pass_context
def fuzz(ctx, firmware, machine, rtos, output, seeds, timeout, jobs):
    """Start fuzzing a firmware image with QEMU-based grey-box fuzzing.

    \b
    Example:
      rtosploit fuzz --firmware fw.bin --machine mps2-an385 --output ./output
      rtosploit fuzz --firmware fw.bin --machine mps2-an385 --timeout 3600
    """
    output_json = ctx.obj.get("output_json", False)

    result = {
        "firmware": firmware,
        "machine": machine,
        "rtos": rtos,
        "output": output,
        "status": "started",
        "crashes": 0,
        "executions": 0,
    }

    if output_json:
        import json
        click.echo(json.dumps(result, indent=2))
        return

    console.print("[bold green]RTOSploit Fuzzer[/bold green]")
    console.print(f"  Firmware:  [cyan]{firmware}[/cyan]")
    console.print(f"  Machine:   [cyan]{machine}[/cyan]")
    console.print(f"  RTOS:      [cyan]{rtos}[/cyan]")
    console.print(f"  Output:    [cyan]{output}[/cyan]")
    console.print(f"  Jobs:      [cyan]{jobs}[/cyan]")
    if timeout:
        console.print(f"  Timeout:   [cyan]{timeout}s[/cyan]")

    console.print("\n[dim]Starting fuzzer... (Ctrl+C to stop)[/dim]")
    console.print("[yellow]Note: Full fuzzer requires Rust engine (cargo build -p rtosploit-fuzzer)[/yellow]")

    # Create output directory
    import os
    os.makedirs(output, exist_ok=True)
    os.makedirs(f"{output}/crashes", exist_ok=True)
    os.makedirs(f"{output}/corpus", exist_ok=True)

    console.print(f"\n[green]Fuzzer ready.[/green] Output directory: [cyan]{output}[/cyan]")
    console.print(
        f"[dim]Run 'cargo run -p rtosploit-fuzzer -- --firmware {firmware} "
        f"--machine {machine} --output {output}' for full fuzzing.[/dim]"
    )
