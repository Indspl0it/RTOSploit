"""rtosploit emulate — launch QEMU firmware emulation."""
import click
from rich.console import Console

console = Console()


@click.command("emulate")
@click.option("--firmware", "-f", required=True, type=click.Path(exists=True), help="Path to firmware binary (.bin/.elf/.hex)")
@click.option("--machine", "-m", required=True, type=str, help="QEMU machine name (e.g. mps2-an385)")
@click.option("--gdb", is_flag=True, default=False, help="Enable GDB server (port 1234)")
@click.option("--gdb-port", type=int, default=1234, show_default=True, help="GDB server port")
@click.option("--serial-port", type=int, default=None, help="Forward UART to TCP port")
@click.option("--svd", type=click.Path(exists=True), default=None, help="SVD file for peripheral definitions")
@click.pass_context
def emulate(ctx, firmware, machine, gdb, gdb_port, serial_port, svd):
    """Launch QEMU emulation of a firmware image.

    \b
    Example:
      rtosploit emulate --firmware fw.bin --machine mps2-an385
      rtosploit emulate --firmware fw.bin --machine mps2-an385 --gdb
    """
    output_json = ctx.obj.get("output_json", False)

    result = {
        "firmware": firmware,
        "machine": machine,
        "gdb": gdb,
        "gdb_port": gdb_port if gdb else None,
        "status": "ready",
    }

    if output_json:
        import json
        click.echo(json.dumps(result, indent=2))
        return

    console.print("[bold green]RTOSploit Emulator[/bold green]")
    console.print(f"  Firmware: [cyan]{firmware}[/cyan]")
    console.print(f"  Machine:  [cyan]{machine}[/cyan]")
    if gdb:
        console.print(f"  GDB:      [cyan]localhost:{gdb_port}[/cyan]")
        console.print(f"  Connect:  [dim]gdb-multiarch -ex 'target remote localhost:{gdb_port}'[/dim]")
    if serial_port:
        console.print(f"  Serial:   [cyan]TCP localhost:{serial_port}[/cyan]")

    console.print("\n[dim]Starting QEMU... (Ctrl+C to stop)[/dim]")

    try:
        from rtosploit.config import load_config
        from rtosploit.emulation.qemu import QEMUInstance

        # Load config and apply CLI overrides
        config = load_config()
        if gdb_port != 1234:
            config.gdb.port = gdb_port

        instance = QEMUInstance(config)
        instance.start(
            firmware_path=firmware,
            machine_name=machine,
            gdb=gdb,
            paused=False,
        )
        pid = instance._process.pid if instance._process else "?"
        console.print(f"[green]QEMU running[/green] (PID: {pid})")

        try:
            # Wait for QEMU process to exit
            if instance._process:
                instance._process.wait()
        except KeyboardInterrupt:
            console.print("\n[yellow]Stopping QEMU...[/yellow]")
            instance.stop()
    except Exception as e:
        console.print(f"[red]QEMU error: {e}[/red]")
        if ctx.obj.get("verbose"):
            import traceback
            traceback.print_exc()
        raise SystemExit(1)
